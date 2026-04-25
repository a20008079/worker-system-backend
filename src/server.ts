// src/server.ts — 校車定位管理系統後端
import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app  = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || 'school-bus-secret-2026';

app.use(cors());
app.use(express.json());

// ── DB Pool ────────────────────────────────────────────
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               Number(process.env.DB_PORT || 3306),
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',
  database:           process.env.DB_NAME     || 'zeabur',
  waitForConnections: true,
  connectionLimit:    10,
  timezone:           '+08:00',
});

// ── JWT Middleware ─────────────────────────────────────
interface AuthRequest extends Request {
  user?: { id: number; role: 'admin' | 'driver' | 'parent' };
}

function auth(roles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登入' });
    try {
      const payload = jwt.verify(token, JWT_SECRET) as any;
      if (!roles.includes(payload.role)) return res.status(403).json({ error: '權限不足' });
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'Token 無效' });
    }
  };
}

// ══════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { account, password, role } = req.body;
  if (!account || !password || !role) return res.status(400).json({ error: '缺少欄位' });

  const tableMap: Record<string, string> = {
    admin: 'admins', driver: 'drivers', parent: 'parents',
  };
  const table = tableMap[role];
  if (!table) return res.status(400).json({ error: '角色錯誤' });

  try {
    const [rows]: any = await pool.query(
      `SELECT * FROM \`${table}\` WHERE account = ? LIMIT 1`, [account]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });

    // 開發階段：若密碼是 placeholder 直接比對明文
    let ok = false;
    if (user.password.startsWith('$2b$')) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = password === user.password;
    }
    if (!ok) return res.status(401).json({ error: '帳號或密碼錯誤' });

    const token = jwt.sign({ id: user.id, role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, id: user.id, name: user.name, role });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 司機端
// ══════════════════════════════════════════════════════

// GET /api/driver/me — 司機資訊 + 今日班次 + 負責校車
app.get('/api/driver/me', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [drivers]: any = await pool.query(
      `SELECT d.id, d.name, d.phone, b.id as bus_id, b.bus_name, b.route_name
       FROM drivers d LEFT JOIN buses b ON b.driver_id = d.id
       WHERE d.id = ? LIMIT 1`, [driverId]
    );
    const driver = drivers[0];
    if (!driver) return res.status(404).json({ error: '找不到司機' });

    // 今日 session
    const [sessions]: any = await pool.query(
      `SELECT * FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() ORDER BY id DESC LIMIT 1`,
      [driverId]
    );
    const session = sessions[0] || null;

    res.json({ driver, session });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// POST /api/driver/online — 上線
app.post('/api/driver/online', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [buses]: any = await pool.query(
      `SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]
    );
    const bus = buses[0];
    if (!bus) return res.status(400).json({ error: '尚未分配校車' });

    // 檢查今日是否已有 session
    const [existing]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`,
      [driverId]
    );
    if (existing[0]) return res.status(400).json({ error: '已經上線' });

    const [result]: any = await pool.query(
      `INSERT INTO driver_sessions (driver_id, bus_id, session_date) VALUES (?, ?, CURDATE())`,
      [driverId, bus.id]
    );
    res.json({ session_id: result.insertId, bus_id: bus.id });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// POST /api/driver/offline — 下線
app.post('/api/driver/offline', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    await pool.query(
      `UPDATE driver_sessions SET end_time = NOW() WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL`,
      [driverId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// POST /api/location/update — GPS 回傳（司機）
app.post('/api/location/update', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { latitude, longitude, accuracy } = req.body;
  try {
    // 找今日 session
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds
       WHERE ds.driver_id = ? AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '尚未上線' });

    await pool.query(
      `INSERT INTO bus_locations (bus_id, session_id, latitude, longitude, accuracy) VALUES (?, ?, ?, ?, ?)`,
      [session.bus_id, session.id, latitude, longitude, accuracy || null]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 家長端
// ══════════════════════════════════════════════════════

// GET /api/parent/me — 家長資訊 + 學生 + 校車最新位置
app.get('/api/parent/me', auth(['parent']), async (req: AuthRequest, res) => {
  const parentId = req.user!.id;
  try {
    // 取得學生與對應校車
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, b.id as bus_id, b.bus_name, b.route_name
       FROM students s JOIN buses b ON s.bus_id = b.id
       WHERE s.parent_id = ? AND s.is_active = 1`,
      [parentId]
    );

    // 每台校車的最新位置
    const result = await Promise.all(students.map(async (student: any) => {
      const [locs]: any = await pool.query(
        `SELECT latitude, longitude, created_at FROM bus_locations
         WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`,
        [student.bus_id]
      );
      // 校車是否在線
      const [sessions]: any = await pool.query(
        `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`,
        [student.bus_id]
      );
      const sessionId = sessions[0]?.id || null;

      // 學生今日是否已上車
      let boarded_at = null;
      if (sessionId) {
        const [boarding]: any = await pool.query(
          `SELECT boarded_at FROM boarding_records WHERE student_id = ? AND session_id = ? LIMIT 1`,
          [student.id, sessionId]
        );
        boarded_at = boarding[0]?.boarded_at || null;
      }

      return {
        student: { id: student.id, name: student.name, school_class: student.school_class },
        bus: { id: student.bus_id, bus_name: student.bus_name, route_name: student.route_name },
        location: locs[0] || null,
        is_online: sessions.length > 0,
        boarded_at,
      };
    }));

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/bus/:busId/location — 校車最新位置（家長權限：只能看自己小孩的校車）
app.get('/api/bus/:busId/location', auth(['parent', 'admin']), async (req: AuthRequest, res) => {
  const busId = Number(req.params.busId);
  const role  = req.user!.role;

  try {
    // 家長需驗證是否有權限看這台車
    if (role === 'parent') {
      const [check]: any = await pool.query(
        `SELECT s.id FROM students s WHERE s.parent_id = ? AND s.bus_id = ? AND s.is_active = 1 LIMIT 1`,
        [req.user!.id, busId]
      );
      if (!check[0]) return res.status(403).json({ error: '無權限查看此校車' });
    }

    const [locs]: any = await pool.query(
      `SELECT latitude, longitude, created_at FROM bus_locations
       WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`,
      [busId]
    );
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`,
      [busId]
    );

    res.json({
      location: locs[0] || null,
      is_online: sessions.length > 0,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 管理員端
// ══════════════════════════════════════════════════════

// GET /api/admin/buses — 所有校車 + 狀態
app.get('/api/admin/buses', auth(['admin']), async (_req, res) => {
  try {
    const [buses]: any = await pool.query(
      `SELECT b.id, b.bus_name, b.route_name, b.is_active,
              d.id as driver_id, d.name as driver_name,
              bl.latitude, bl.longitude, bl.created_at as last_seen,
              (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1) as student_count,
              (SELECT id FROM driver_sessions ds WHERE ds.bus_id = b.id AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1) as session_id
       FROM buses b
       LEFT JOIN drivers d ON b.driver_id = d.id
       LEFT JOIN bus_locations bl ON bl.id = (
         SELECT id FROM bus_locations WHERE bus_id = b.id ORDER BY created_at DESC LIMIT 1
       )
       ORDER BY b.route_name, b.bus_name`
    );
    res.json(buses);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/admin/students — 所有學生
app.get('/api/admin/students', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.is_active,
              p.name as parent_name, p.account as parent_account,
              b.bus_name, b.route_name
       FROM students s
       JOIN parents p ON s.parent_id = p.id
       JOIN buses b ON s.bus_id = b.id
       ORDER BY b.route_name, s.name`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// POST /api/admin/students — 新增學生
app.post('/api/admin/students', auth(['admin']), async (req, res) => {
  const { name, school_class, parent_id, bus_id } = req.body;
  try {
    const [r]: any = await pool.query(
      `INSERT INTO students (name, school_class, parent_id, bus_id) VALUES (?, ?, ?, ?)`,
      [name, school_class, parent_id, bus_id]
    );
    res.json({ id: r.insertId });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/admin/drivers — 所有司機
app.get('/api/admin/drivers', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT d.id, d.name, d.phone, d.account, d.is_active,
              b.bus_name, b.route_name
       FROM drivers d LEFT JOIN buses b ON b.driver_id = d.id
       ORDER BY d.name`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// Health Check
// ══════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({ ok: true }));

// 新增以下 API 到 server.ts
// 放在 "管理員端" 區塊之後，app.listen 之前
// =====================================================

// ══════════════════════════════════════════════════════
// 掃描建檔 API
// ══════════════════════════════════════════════════════

// GET /api/admin/scan/:code — 查詢 student_code
app.get('/api/admin/scan/:code', auth(['admin', 'driver']), async (req: AuthRequest, res) => {
  const code = req.params.code;
  try {
    const [rows]: any = await pool.query(
      `SELECT s.*, p.name as parent_name, p.phone as parent_phone,
              b.bus_name, b.route_name
       FROM students s
       LEFT JOIN parents p ON s.parent_id = p.id
       LEFT JOIN buses b ON s.bus_id = b.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`,
      [code, code]
    );
    if (rows[0]) {
      res.json({ found: true, student: rows[0] });
    } else {
      res.json({ found: false, scanned_code: code });
    }
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// POST /api/admin/scan/save — 掃描後快速建檔
app.post('/api/admin/scan/save', auth(['admin']), async (req: AuthRequest, res) => {
  const {
    student_code, student_name, school_class,
    parent_name, parent_phone,
    bus_id, student_id,
  } = req.body;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. 找或建立家長
    let parentId: number;
    const [existingParents]: any = await conn.query(
      `SELECT id FROM parents WHERE phone = ? LIMIT 1`, [parent_phone]
    );
    if (existingParents[0]) {
      parentId = existingParents[0].id;
      await conn.query(
        `UPDATE parents SET name = ? WHERE id = ?`, [parent_name, parentId]
      );
    } else {
      // 新家長帳號 = 手機號碼，密碼 = 手機後4碼
      const account  = parent_phone;
      const password = parent_phone.slice(-4);
      const [r]: any = await conn.query(
        `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE name=VALUES(name), phone=VALUES(phone)`,
        [parent_name, account, password, parent_phone]
      );
      parentId = r.insertId || existingParents[0]?.id;
      // 再查一次確保拿到 id
      if (!parentId) {
        const [p]: any = await conn.query(
          `SELECT id FROM parents WHERE account = ? LIMIT 1`, [account]
        );
        parentId = p[0].id;
      }
    }

    // 2. 建立或更新學生
    if (student_id) {
      // 更新
      await conn.query(
        `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?,
         student_code=?, parent_phone=? WHERE id=?`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone, student_id]
      );
    } else {
      // 新增
      await conn.query(
        `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone]
      );
    }

    await conn.commit();
    res.json({ ok: true, parent_account: parent_phone, parent_password: parent_phone.slice(-4) });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// Excel / CSV 批次匯入 API
// ══════════════════════════════════════════════════════

// POST /api/admin/import — 批次匯入學生
// Body: { rows: [ { student_name, class_name, parent_name, parent_phone, route_name, bus_name, student_code } ] }
app.post('/api/admin/import', auth(['admin']), async (req: AuthRequest, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: '沒有資料' });
  }

  let added = 0, updated = 0, failed = 0;
  const errors: string[] = [];

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    for (const row of rows) {
      try {
        const { student_name, class_name, parent_name, parent_phone, route_name, bus_name, student_code } = row;

        // 驗證必要欄位
        if (!student_name || !parent_phone || !bus_name) {
          failed++;
          errors.push(`${student_name || '?'}: 缺少必要欄位`);
          continue;
        }

        // 1. 找校車
        const [buses]: any = await conn.query(
          `SELECT id FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]
        );
        if (!buses[0]) {
          failed++;
          errors.push(`${student_name}: 找不到校車「${bus_name}」`);
          continue;
        }
        const busId = buses[0].id;

        // 2. 找或建立家長
        let parentId: number;
        const [existingP]: any = await conn.query(
          `SELECT id FROM parents WHERE phone = ? LIMIT 1`, [parent_phone]
        );
        if (existingP[0]) {
          parentId = existingP[0].id;
        } else {
          const password = parent_phone.slice(-4);
          const [r]: any = await conn.query(
            `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
            [parent_name, parent_phone, password, parent_phone]
          );
          parentId = r.insertId;
        }

        // 3. 找或建立學生
        if (student_code) {
          const [existingS]: any = await conn.query(
            `SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]
          );
          if (existingS[0]) {
            await conn.query(
              `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`,
              [student_name, class_name, parentId, busId, parent_phone, existingS[0].id]
            );
            updated++;
          } else {
            await conn.query(
              `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone)
               VALUES (?, ?, ?, ?, ?, ?)`,
              [student_name, class_name, parentId, busId, student_code, parent_phone]
            );
            added++;
          }
        } else {
          await conn.query(
            `INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone)
             VALUES (?, ?, ?, ?, ?)`,
            [student_name, class_name, parentId, busId, parent_phone]
          );
          added++;
        }
      } catch (e: any) {
        failed++;
        errors.push(`${row.student_name || '?'}: ${e.message}`);
      }
    }

    await conn.commit();
    res.json({ ok: true, added, updated, failed, errors });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// 司機掃描上車 API
// ══════════════════════════════════════════════════════

// POST /api/driver/scan — 司機掃描學生證上車
app.post('/api/driver/scan', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { code } = req.body;

  try {
    // 找司機的今日 session
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds
       WHERE ds.driver_id = ? AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '請先上線' });

    // 查學生
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.bus_id,
              p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`,
      [code, code]
    );
    const student = students[0];

    if (!student) {
      return res.json({ status: 'not_found', message: '查無學生，請聯絡管理員' });
    }

    if (student.bus_id !== session.bus_id) {
      return res.json({
        status: 'wrong_bus',
        message: `${student.name} 不是本車學生`,
        student,
      });
    }

    // 記錄上車
    await pool.query(
      `INSERT INTO boarding_records (student_id, session_id) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE boarded_at = NOW()`,
      [student.id, session.id]
    );

    res.json({ status: 'ok', message: `${student.name} 上車成功`, student });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/admin/buses-simple — 給表單用的簡易校車列表
app.get('/api/admin/buses-simple', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT id, bus_name, route_name FROM buses WHERE is_active = 1 ORDER BY route_name, bus_name`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
// =====================================================
// 帳號管理 API
// 加到 server.ts 的 app.listen 之前
// =====================================================

// ══════════════════════════════════════════════════════
// GET /api/admin/accounts — 取得所有帳號
// ══════════════════════════════════════════════════════
app.get('/api/admin/accounts', auth(['admin']), async (_req, res) => {
  try {
    const [drivers]: any = await pool.query(
      `SELECT id, name, account, phone, is_active, 'driver' as role FROM drivers ORDER BY name`
    );
    const [parents]: any = await pool.query(
      `SELECT id, name, account, phone, 1 as is_active, 'parent' as role FROM parents ORDER BY name`
    );
    const [admins]: any = await pool.query(
      `SELECT id, name, account, '' as phone, 1 as is_active, 'admin' as role FROM admins ORDER BY name`
    );
    res.json({ drivers, parents, admins });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// POST /api/admin/accounts — 新增帳號
// ══════════════════════════════════════════════════════
app.post('/api/admin/accounts', auth(['admin']), async (req, res) => {
  const { role, name, account, password, phone } = req.body;
  if (!role || !name || !account || !password) {
    return res.status(400).json({ error: '缺少必要欄位' });
  }
  try {
    if (role === 'driver') {
      await pool.query(
        `INSERT INTO drivers (name, account, password, phone) VALUES (?, ?, ?, ?)`,
        [name, account, password, phone || '']
      );
    } else if (role === 'parent') {
      await pool.query(
        `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
        [name, account, password, phone || '']
      );
    } else if (role === 'admin') {
      await pool.query(
        `INSERT INTO admins (name, account, password) VALUES (?, ?, ?)`,
        [name, account, password]
      );
    } else {
      return res.status(400).json({ error: '角色錯誤' });
    }
    res.json({ ok: true });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: '帳號已存在' });
    }
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// PUT /api/admin/accounts/:role/:id — 修改帳號
// ══════════════════════════════════════════════════════
app.put('/api/admin/accounts/:role/:id', auth(['admin']), async (req, res) => {
  const { role, id } = req.params;
  const { name, account, password, phone } = req.body;
  try {
    if (role === 'driver') {
      if (password) {
        await pool.query(
          `UPDATE drivers SET name=?, account=?, password=?, phone=? WHERE id=?`,
          [name, account, password, phone || '', id]
        );
      } else {
        await pool.query(
          `UPDATE drivers SET name=?, account=?, phone=? WHERE id=?`,
          [name, account, phone || '', id]
        );
      }
    } else if (role === 'parent') {
      if (password) {
        await pool.query(
          `UPDATE parents SET name=?, account=?, password=?, phone=? WHERE id=?`,
          [name, account, password, phone || '', id]
        );
      } else {
        await pool.query(
          `UPDATE parents SET name=?, account=?, phone=? WHERE id=?`,
          [name, account, phone || '', id]
        );
      }
    } else if (role === 'admin') {
      if (password) {
        await pool.query(
          `UPDATE admins SET name=?, account=?, password=? WHERE id=?`,
          [name, account, password, id]
        );
      } else {
        await pool.query(
          `UPDATE admins SET name=?, account=? WHERE id=?`,
          [name, account, id]
        );
      }
    }
    res.json({ ok: true });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: '帳號已存在' });
    }
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// DELETE /api/admin/accounts/:role/:id — 刪除帳號
// ══════════════════════════════════════════════════════
app.delete('/api/admin/accounts/:role/:id', auth(['admin']), async (req, res) => {
  const { role, id } = req.params;
  try {
    if (role === 'driver') {
      await pool.query(`DELETE FROM drivers WHERE id=?`, [id]);
    } else if (role === 'parent') {
      await pool.query(`DELETE FROM parents WHERE id=?`, [id]);
    } else if (role === 'admin') {
      await pool.query(`DELETE FROM admins WHERE id=?`, [id]);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
// 新增以下 API 到 server.ts 的 app.listen 之前
// =====================================================

// ══════════════════════════════════════════════════════
// GET /api/driver/students — 司機今日應載學生 + 上車狀態
// ══════════════════════════════════════════════════════
app.get('/api/driver/students', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    // 找司機負責的校車
    const [buses]: any = await pool.query(
      `SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]
    );
    const bus = buses[0];
    if (!bus) return res.json({ students: [], session: null });

    // 今日 session
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0] || null;

    // 取得所有應載學生
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.student_code,
              p.name as parent_name, p.phone as parent_phone
       FROM students s
       LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.bus_id = ? AND s.is_active = 1
       ORDER BY s.school_class, s.name`,
      [bus.id]
    );

    // 如果有今日 session，查上車紀錄
    let boardedIds: number[] = [];
    let boardingTimes: Record<number, string> = {};
    if (session) {
      const [boarding]: any = await pool.query(
        `SELECT student_id, boarded_at FROM boarding_records WHERE session_id = ?`,
        [session.id]
      );
      boardedIds = boarding.map((b: any) => b.student_id);
      boarding.forEach((b: any) => { boardingTimes[b.student_id] = b.boarded_at; });
    }

    const result = students.map((s: any) => ({
      ...s,
      is_boarded: boardedIds.includes(s.id),
      boarded_at: boardingTimes[s.id] || null,
    }));

    res.json({
      students: result,
      session,
      total: result.length,
      boarded: boardedIds.length,
      missing: result.length - boardedIds.length,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// POST /api/admin/import-full — 完整匯入（司機+校車+學生+家長）
// ══════════════════════════════════════════════════════
app.post('/api/admin/import-full', auth(['admin']), async (req: AuthRequest, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: '沒有資料' });
  }

  let added = 0, updated = 0, failed = 0;
  const errors: string[] = [];
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    for (const row of rows) {
      try {
        const {
          route_name, bus_name, driver_name, driver_phone,
          student_name, student_code, class_name,
          parent_name, parent_phone,
        } = row;

        if (!bus_name || !student_name || !parent_phone) {
          failed++;
          errors.push(`${student_name || '?'}: 缺少必要欄位（bus_name / student_name / parent_phone）`);
          continue;
        }

        // 1. 找或建立校車
        let busId: number;
        const [existingBus]: any = await conn.query(
          `SELECT id FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]
        );
        if (existingBus[0]) {
          busId = existingBus[0].id;
        } else {
          // 找或建立司機
          let driverId: number | null = null;
          if (driver_phone) {
            const [existingDriver]: any = await conn.query(
              `SELECT id FROM drivers WHERE account = ? LIMIT 1`, [driver_phone]
            );
            if (existingDriver[0]) {
              driverId = existingDriver[0].id;
            } else if (driver_name) {
              const password = driver_phone.slice(-4);
              const [dr]: any = await conn.query(
                `INSERT INTO drivers (name, phone, account, password) VALUES (?, ?, ?, ?)`,
                [driver_name, driver_phone, driver_phone, password]
              );
              driverId = dr.insertId;
            }
          }
          const [br]: any = await conn.query(
            `INSERT INTO buses (bus_name, route_name, driver_id) VALUES (?, ?, ?)`,
            [bus_name, route_name || bus_name, driverId]
          );
          busId = br.insertId;
        }

        // 2. 找或建立家長
        let parentId: number;
        const [existingParent]: any = await conn.query(
          `SELECT id FROM parents WHERE phone = ? OR account = ? LIMIT 1`,
          [parent_phone, parent_phone]
        );
        if (existingParent[0]) {
          parentId = existingParent[0].id;
          await conn.query(
            `UPDATE parents SET name = ? WHERE id = ?`, [parent_name, parentId]
          );
        } else {
          const password = parent_phone.slice(-4);
          const [pr]: any = await conn.query(
            `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
            [parent_name, parent_phone, password, parent_phone]
          );
          parentId = pr.insertId;
        }

        // 3. 找或建立學生
        if (student_code) {
          const [existingStudent]: any = await conn.query(
            `SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]
          );
          if (existingStudent[0]) {
            await conn.query(
              `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`,
              [student_name, class_name, parentId, busId, parent_phone, existingStudent[0].id]
            );
            updated++;
          } else {
            await conn.query(
              `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone)
               VALUES (?, ?, ?, ?, ?, ?)`,
              [student_name, class_name, parentId, busId, student_code, parent_phone]
            );
            added++;
          }
        } else {
          await conn.query(
            `INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone)
             VALUES (?, ?, ?, ?, ?)`,
            [student_name, class_name, parentId, busId, parent_phone]
          );
          added++;
        }
      } catch (e: any) {
        failed++;
        errors.push(`${row.student_name || '?'}: ${e.message}`);
      }
    }

    await conn.commit();
    res.json({ ok: true, added, updated, failed, errors });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});
// GET /api/admin/export — 匯出現有學生資料為漂亮的 xlsx
app.get('/api/admin/export', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT
        b.route_name, b.bus_name,
        d.name as driver_name, d.phone as driver_phone,
        s.name as student_name, s.student_code, s.school_class as class_name,
        p.name as parent_name, p.phone as parent_phone
       FROM students s
       LEFT JOIN buses b ON s.bus_id = b.id
       LEFT JOIN drivers d ON b.driver_id = d.id
       LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.is_active = 1
       ORDER BY b.route_name, b.bus_name, s.name`
    );

    const XLSX = require('xlsx');

    const wb = XLSX.utils.book_new();

    // ── 學生名單 Sheet ──
    const headers = ['route_name','bus_name','driver_name','driver_phone','student_name','student_code','class_name','parent_name','parent_phone'];
    const headerLabels = ['路線名稱','車次名稱','司機姓名','司機手機','學生姓名','學生證號','班級','家長姓名','家長手機'];
    const notes = ['選填','必填','選填','選填（司機帳號）','必填','選填（掃描用）','選填','必填','必填（家長帳號）'];

    const wsData: any[][] = [
      // 第一列：欄位英文名
      headers,
      // 第二列：欄位中文說明
      headerLabels,
      // 第三列：備註
      notes,
      // 空白分隔
    ];

    // 加入資料
    if (rows.length > 0) {
      rows.forEach((r: any) => {
        wsData.push(headers.map(h => r[h] || ''));
      });
    } else {
      // 沒有資料時放範例
      wsData.push(['觀音線','觀音線01','陳大明','0912345678','王小明','S001','三年二班','王爸爸','0911111111']);
      wsData.push(['觀音線','觀音線01','陳大明','0912345678','李小美','S002','四年一班','李媽媽','0922222222']);
    }

    const ws = XLSX.utils.aoa_to_sheet(wsData);

    // 欄寬設定
    ws['!cols'] = [
      { wch: 12 }, { wch: 14 }, { wch: 12 }, { wch: 18 },
      { wch: 12 }, { wch: 14 }, { wch: 12 }, { wch: 12 }, { wch: 18 }
    ];

    // 凍結前三列（欄位說明）
    ws['!freeze'] = { xSplit: 0, ySplit: 3 };

    XLSX.utils.book_append_sheet(wb, ws, '學生名單');

    // ── 填寫說明 Sheet ──
    const ws2Data = [
      ['填寫說明', ''],
      ['', ''],
      ['【必填欄位】', ''],
      ['bus_name', '車次名稱，例如：觀音線01、大園線01'],
      ['student_name', '學生姓名'],
      ['parent_name', '家長姓名'],
      ['parent_phone', '家長手機號碼（作為家長登入帳號，密碼預設為手機後4碼）'],
      ['', ''],
      ['【選填欄位】', ''],
      ['route_name', '路線名稱，例如：觀音線、大園線'],
      ['driver_name', '司機姓名'],
      ['driver_phone', '司機手機號碼（作為司機登入帳號，密碼預設為手機後4碼）'],
      ['student_code', '學生證號（用於司機掃描學生上車，建議填寫）'],
      ['class_name', '學生班級，例如：三年二班'],
      ['', ''],
      ['【匯入邏輯】', ''],
      ['校車', 'bus_name 不存在 → 自動建立校車'],
      ['司機', 'driver_phone 不存在 → 自動建立司機帳號'],
      ['家長', 'parent_phone 不存在 → 自動建立家長帳號'],
      ['學生', 'student_code 不存在 → 建立新學生'],
      ['更新', 'student_code 已存在 → 更新學生資料'],
      ['', ''],
      ['【注意事項】', ''],
      ['1.', '同一台校車的學生，bus_name 要完全一致'],
      ['2.', '家長手機號碼作為帳號，不可重複'],
      ['3.', '第4行起填寫實際資料，可刪除範例資料'],
      ['4.', `匯出時間：${new Date().toLocaleString('zh-TW')}`],
      ['5.', `共 ${rows.length} 筆學生資料`],
    ];

    const ws2 = XLSX.utils.aoa_to_sheet(ws2Data);
    ws2['!cols'] = [{ wch: 18 }, { wch: 55 }];
    XLSX.utils.book_append_sheet(wb, ws2, '填寫說明');

    // 輸出 buffer
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    const today = new Date().toLocaleDateString('zh-TW').replace(/\//g, '');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''%E6%A0%A1%E8%BB%8A%E5%AD%B8%E7%94%9F%E8%B3%87%E6%96%99%E5%BA%AB_${today}.xlsx`);
    res.send(buf);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});


app.listen(PORT, () => {
  console.log(`✅ 校車系統 API running on port ${PORT}`);
  console.log(`   TZ=${process.env.TZ || '(未設定)'}`);
});
// =====================================================
