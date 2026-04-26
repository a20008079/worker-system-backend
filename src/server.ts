// src/server.ts — 校車定位管理系統後端（含自動下線）
import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || 'school-bus-secret-2026';

app.use(cors());
app.use(express.json());

// ── DB Pool ────────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'zeabur',
  waitForConnections: true,
  connectionLimit: 10,
  timezone: '+08:00',
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
// 自動下線機制
// 規則：司機上線後，若超過 N 分鐘沒有回傳 GPS 定位，
//        系統自動幫他下線（避免家長一直看到「行駛中」）
// ══════════════════════════════════════════════════════
const AUTO_OFFLINE_MINUTES = 30; // 超過 30 分鐘無 GPS 更新 → 自動下線

async function autoOfflineCheck() {
  try {
    // 找出：今天仍在線（end_time IS NULL）但超過 N 分鐘沒有 GPS 更新的 session
    const [sessions]: any = await pool.query(`
      SELECT ds.id, ds.driver_id, ds.bus_id, d.name as driver_name, b.bus_name
      FROM driver_sessions ds
      JOIN drivers d ON ds.driver_id = d.id
      JOIN buses b ON ds.bus_id = b.id
      WHERE ds.session_date = CURDATE()
        AND ds.end_time IS NULL
        AND COALESCE(
          (SELECT MAX(bl.created_at) FROM bus_locations bl WHERE bl.session_id = ds.id),
          ds.start_time
        ) < DATE_SUB(NOW(), INTERVAL ${AUTO_OFFLINE_MINUTES} MINUTE)
    `);

    if (sessions.length > 0) {
      const ids = sessions.map((s: any) => s.id);
      const ph = ids.map(() => '?').join(',');
      await pool.query(
        `UPDATE driver_sessions SET end_time = NOW() WHERE id IN (${ph})`,
        ids
      );
      sessions.forEach((s: any) => {
        console.log(`[自動下線] ${s.driver_name} / ${s.bus_name} (session_id: ${s.id}) — 超過 ${AUTO_OFFLINE_MINUTES} 分鐘無 GPS`);
      });
    }
  } catch (e) {
    console.error('[自動下線] 檢查失敗:', e);
  }
}

// 每 5 分鐘檢查一次
setInterval(autoOfflineCheck, 5 * 60 * 1000);
// 啟動時也立即執行一次
autoOfflineCheck();

// ══════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { account, password, role } = req.body;
  if (!account || !password || !role) return res.status(400).json({ error: '缺少欄位' });
  const tableMap: Record<string, string> = { admin: 'admins', driver: 'drivers', parent: 'parents' };
  const table = tableMap[role];
  if (!table) return res.status(400).json({ error: '角色錯誤' });
  try {
    const [rows]: any = await pool.query(`SELECT * FROM \`${table}\` WHERE account = ? LIMIT 1`, [account]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });
    let ok = false;
    if (user.password.startsWith('$2b$')) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = password === user.password;
    }
    if (!ok) return res.status(401).json({ error: '帳號或密碼錯誤' });
    const token = jwt.sign({ id: user.id, role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, id: user.id, name: user.name, role });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// 司機端
// ══════════════════════════════════════════════════════
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
    const [sessions]: any = await pool.query(
      `SELECT * FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() ORDER BY id DESC LIMIT 1`,
      [driverId]
    );
    res.json({ driver, session: sessions[0] || null });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/driver/online', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [buses]: any = await pool.query(`SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]);
    const bus = buses[0];
    if (!bus) return res.status(400).json({ error: '尚未分配校車' });
    const [existing]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`, [driverId]
    );
    if (existing[0]) return res.status(400).json({ error: '已經上線' });
    const [result]: any = await pool.query(
      `INSERT INTO driver_sessions (driver_id, bus_id, session_date) VALUES (?, ?, CURDATE())`, [driverId, bus.id]
    );
    res.json({ session_id: result.insertId, bus_id: bus.id });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/driver/offline', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    await pool.query(
      `UPDATE driver_sessions SET end_time = NOW() WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL`, [driverId]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/location/update', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { latitude, longitude, accuracy } = req.body;
  try {
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds WHERE ds.driver_id = ? AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '尚未上線' });
    await pool.query(
      `INSERT INTO bus_locations (bus_id, session_id, latitude, longitude, accuracy) VALUES (?, ?, ?, ?, ?)`,
      [session.bus_id, session.id, latitude, longitude, accuracy || null]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/driver/students', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [buses]: any = await pool.query(`SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]);
    const bus = buses[0];
    if (!bus) return res.json({ students: [], session: null });
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`, [driverId]
    );
    const session = sessions[0] || null;
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.student_code, p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.bus_id = ? AND s.is_active = 1 ORDER BY s.school_class, s.name`, [bus.id]
    );
    let boardedIds: number[] = [];
    let boardingTimes: Record<number, string> = {};
    if (session) {
      const [boarding]: any = await pool.query(`SELECT student_id, boarded_at FROM boarding_records WHERE session_id = ?`, [session.id]);
      boardedIds = boarding.map((b: any) => b.student_id);
      boarding.forEach((b: any) => { boardingTimes[b.student_id] = b.boarded_at; });
    }
    const result = students.map((s: any) => ({ ...s, is_boarded: boardedIds.includes(s.id), boarded_at: boardingTimes[s.id] || null }));
    res.json({ students: result, session, total: result.length, boarded: boardedIds.length, missing: result.length - boardedIds.length });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/driver/scan', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { code } = req.body;
  try {
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds WHERE ds.driver_id = ? AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1`, [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '請先上線' });
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.bus_id, p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`, [code, code]
    );
    const student = students[0];
    if (!student) return res.json({ status: 'not_found', message: '查無學生，請聯絡管理員' });
    if (student.bus_id !== session.bus_id) return res.json({ status: 'wrong_bus', message: `${student.name} 不是本車學生`, student });
    await pool.query(
      `INSERT INTO boarding_records (student_id, session_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE boarded_at = NOW()`,
      [student.id, session.id]
    );
    res.json({ status: 'ok', message: `${student.name} 上車成功`, student });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// 家長端
// ══════════════════════════════════════════════════════
app.get('/api/parent/me', auth(['parent']), async (req: AuthRequest, res) => {
  const parentId = req.user!.id;
  try {
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, b.id as bus_id, b.bus_name, b.route_name
       FROM students s JOIN buses b ON s.bus_id = b.id
       WHERE s.parent_id = ? AND s.is_active = 1`, [parentId]
    );
    const result = await Promise.all(students.map(async (student: any) => {
      const [locs]: any = await pool.query(
        `SELECT latitude, longitude, created_at FROM bus_locations WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`, [student.bus_id]
      );
      const [sessions]: any = await pool.query(
        `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`, [student.bus_id]
      );
      const sessionId = sessions[0]?.id || null;
      let boarded_at = null;
      if (sessionId) {
        const [boarding]: any = await pool.query(
          `SELECT boarded_at FROM boarding_records WHERE student_id = ? AND session_id = ? LIMIT 1`, [student.id, sessionId]
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
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/bus/:busId/location', auth(['parent', 'admin']), async (req: AuthRequest, res) => {
  const busId = Number(req.params.busId);
  const role = req.user!.role;
  try {
    if (role === 'parent') {
      const [check]: any = await pool.query(
        `SELECT s.id FROM students s WHERE s.parent_id = ? AND s.bus_id = ? AND s.is_active = 1 LIMIT 1`, [req.user!.id, busId]
      );
      if (!check[0]) return res.status(403).json({ error: '無權限查看此校車' });
    }
    const [locs]: any = await pool.query(
      `SELECT latitude, longitude, created_at FROM bus_locations WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`, [busId]
    );
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = CURDATE() AND end_time IS NULL LIMIT 1`, [busId]
    );
    res.json({ location: locs[0] || null, is_online: sessions.length > 0 });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// Health Check
// ══════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({ ok: true, autoOfflineMinutes: AUTO_OFFLINE_MINUTES }));

// ══════════════════════════════════════════════════════
// 管理員端 - 校車管理
// ══════════════════════════════════════════════════════
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
       LEFT JOIN bus_locations bl ON bl.id = (SELECT id FROM bus_locations WHERE bus_id = b.id ORDER BY created_at DESC LIMIT 1)
       ORDER BY b.route_name, b.bus_name`
    );
    res.json(buses);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.put('/api/admin/buses/:busId/driver', auth(['admin']), async (req, res) => {
  const busId = Number(req.params.busId);
  const { driver_id } = req.body;
  try {
    await pool.query(`UPDATE buses SET driver_id = ? WHERE id = ?`, [driver_id ?? null, busId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/admin/buses/locations', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT b.id, b.bus_name, b.route_name,
             d.name AS driver_name, d.account AS driver_account,
             bl.latitude, bl.longitude, bl.created_at AS last_seen,
             (SELECT id FROM driver_sessions ds WHERE ds.bus_id = b.id AND ds.session_date = CURDATE() AND ds.end_time IS NULL LIMIT 1) AS session_id,
             (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1) AS student_count,
             (SELECT COUNT(*) FROM boarding_records br JOIN driver_sessions ds ON br.session_id = ds.id
              WHERE ds.bus_id = b.id AND ds.session_date = CURDATE() AND ds.end_time IS NULL) AS boarded_count
      FROM buses b
      LEFT JOIN drivers d ON b.driver_id = d.id
      LEFT JOIN bus_locations bl ON bl.id = (SELECT id FROM bus_locations WHERE bus_id = b.id ORDER BY created_at DESC LIMIT 1)
      WHERE b.is_active = 1
      ORDER BY b.route_name, b.bus_name
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/admin/buses/:busId/history', auth(['admin', 'parent']), async (req, res) => {
  const busId = Number(req.params.busId);
  try {
    const [rows]: any = await pool.query(
      `SELECT latitude, longitude, created_at FROM bus_locations
       WHERE bus_id = ? AND DATE(created_at) = CURDATE() ORDER BY created_at ASC`, [busId]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/admin/buses-simple', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`SELECT id, bus_name, route_name FROM buses WHERE is_active = 1 ORDER BY route_name, bus_name`);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// 管理員端 - 學生管理
// ══════════════════════════════════════════════════════
app.get('/api/admin/students', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.is_active,
              p.name as parent_name, p.account as parent_account,
              b.bus_name, b.route_name
       FROM students s JOIN parents p ON s.parent_id = p.id JOIN buses b ON s.bus_id = b.id
       ORDER BY b.route_name, s.name`
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/admin/students', auth(['admin']), async (req, res) => {
  const { name, school_class, parent_id, bus_id } = req.body;
  try {
    const [r]: any = await pool.query(`INSERT INTO students (name, school_class, parent_id, bus_id) VALUES (?, ?, ?, ?)`, [name, school_class, parent_id, bus_id]);
    res.json({ id: r.insertId });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.delete('/api/admin/students/:id', auth(['admin']), async (req, res) => {
  const id = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(`DELETE FROM boarding_records WHERE student_id = ?`, [id]);
    await conn.query(`DELETE FROM students WHERE id = ?`, [id]);
    await conn.commit();
    res.json({ ok: true });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// 管理員端 - 司機管理
// ══════════════════════════════════════════════════════
app.get('/api/admin/drivers', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT d.id, d.name, d.phone, d.account, d.is_active, b.bus_name, b.route_name
       FROM drivers d LEFT JOIN buses b ON b.driver_id = d.id ORDER BY d.account`
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// 掃描建檔 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/scan/:code', auth(['admin', 'driver']), async (req: AuthRequest, res) => {
  const code = req.params.code;
  try {
    const [rows]: any = await pool.query(
      `SELECT s.*, p.name as parent_name, p.phone as parent_phone, b.bus_name, b.route_name
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id LEFT JOIN buses b ON s.bus_id = b.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`, [code, code]
    );
    if (rows[0]) res.json({ found: true, student: rows[0] });
    else res.json({ found: false, scanned_code: code });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/admin/scan/save', auth(['admin']), async (req: AuthRequest, res) => {
  const { student_code, student_name, school_class, parent_name, parent_phone, bus_id, student_id } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let parentId: number;
    const [existingParents]: any = await conn.query(`SELECT id FROM parents WHERE phone = ? LIMIT 1`, [parent_phone]);
    if (existingParents[0]) {
      parentId = existingParents[0].id;
      await conn.query(`UPDATE parents SET name = ? WHERE id = ?`, [parent_name, parentId]);
    } else {
      const account = parent_phone;
      const password = parent_phone.slice(-4);
      const [r]: any = await conn.query(
        `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name), phone=VALUES(phone)`,
        [parent_name, account, password, parent_phone]
      );
      parentId = r.insertId || existingParents[0]?.id;
      if (!parentId) {
        const [p]: any = await conn.query(`SELECT id FROM parents WHERE account = ? LIMIT 1`, [account]);
        parentId = p[0].id;
      }
    }
    if (student_id) {
      await conn.query(
        `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, student_code=?, parent_phone=? WHERE id=?`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone, student_id]
      );
    } else {
      await conn.query(
        `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone) VALUES (?, ?, ?, ?, ?, ?)`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone]
      );
    }
    await conn.commit();
    res.json({ ok: true, parent_account: parent_phone, parent_password: parent_phone.slice(-4) });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// 批次匯入 API
// ══════════════════════════════════════════════════════
app.post('/api/admin/import', auth(['admin']), async (req: AuthRequest, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: '沒有資料' });
  let added = 0, updated = 0, failed = 0;
  const errors: string[] = [];
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const row of rows) {
      try {
        const { student_name, class_name, parent_name, parent_phone, bus_name, student_code } = row;
        if (!student_name || !parent_phone || !bus_name) { failed++; errors.push(`${student_name || '?'}: 缺少必要欄位`); continue; }
        const [buses]: any = await conn.query(`SELECT id FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]);
        if (!buses[0]) { failed++; errors.push(`${student_name}: 找不到校車「${bus_name}」`); continue; }
        const busId = buses[0].id;
        let parentId: number;
        const [existingP]: any = await conn.query(`SELECT id FROM parents WHERE phone = ? LIMIT 1`, [parent_phone]);
        if (existingP[0]) { parentId = existingP[0].id; }
        else {
          const [r]: any = await conn.query(`INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`, [parent_name, parent_phone, parent_phone.slice(-4), parent_phone]);
          parentId = r.insertId;
        }
        if (student_code) {
          const [existingS]: any = await conn.query(`SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]);
          if (existingS[0]) { await conn.query(`UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`, [student_name, class_name, parentId, busId, parent_phone, existingS[0].id]); updated++; }
          else { await conn.query(`INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone) VALUES (?, ?, ?, ?, ?, ?)`, [student_name, class_name, parentId, busId, student_code, parent_phone]); added++; }
        } else { await conn.query(`INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone) VALUES (?, ?, ?, ?, ?)`, [student_name, class_name, parentId, busId, parent_phone]); added++; }
      } catch (e: any) { failed++; errors.push(`${row.student_name || '?'}: ${e.message}`); }
    }
    await conn.commit();
    res.json({ ok: true, added, updated, failed, errors });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

app.post('/api/admin/import-full', auth(['admin']), async (req: AuthRequest, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: '沒有資料' });
  let added = 0, updated = 0, failed = 0;
  const errors: string[] = [];
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const row of rows) {
      try {
        const { route_name, bus_name, driver_name, driver_phone, student_name, student_code, class_name, parent_name, parent_phone } = row;
        if (!bus_name || !student_name || !parent_phone) { failed++; errors.push(`${student_name || '?'}: 缺少必要欄位`); continue; }
        let busId: number;
        const [existingBus]: any = await conn.query(`SELECT id FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]);
        if (existingBus[0]) { busId = existingBus[0].id; }
        else {
          let driverId: number | null = null;
          if (driver_phone) {
            const [existingDriver]: any = await conn.query(`SELECT id FROM drivers WHERE account = ? LIMIT 1`, [driver_phone]);
            if (existingDriver[0]) { driverId = existingDriver[0].id; }
            else if (driver_name) {
              const [dr]: any = await conn.query(`INSERT INTO drivers (name, phone, account, password) VALUES (?, ?, ?, ?)`, [driver_name, driver_phone, driver_phone, driver_phone.slice(-4)]);
              driverId = dr.insertId;
            }
          }
          const [br]: any = await conn.query(`INSERT INTO buses (bus_name, route_name, driver_id) VALUES (?, ?, ?)`, [bus_name, route_name || bus_name, driverId]);
          busId = br.insertId;
        }
        let parentId: number;
        const [existingParent]: any = await conn.query(`SELECT id FROM parents WHERE phone = ? OR account = ? LIMIT 1`, [parent_phone, parent_phone]);
        if (existingParent[0]) { parentId = existingParent[0].id; await conn.query(`UPDATE parents SET name = ? WHERE id = ?`, [parent_name, parentId]); }
        else {
          const [pr]: any = await conn.query(`INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`, [parent_name, parent_phone, parent_phone.slice(-4), parent_phone]);
          parentId = pr.insertId;
        }
        if (student_code) {
          const [existingStudent]: any = await conn.query(`SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]);
          if (existingStudent[0]) { await conn.query(`UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`, [student_name, class_name, parentId, busId, parent_phone, existingStudent[0].id]); updated++; }
          else { await conn.query(`INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone) VALUES (?, ?, ?, ?, ?, ?)`, [student_name, class_name, parentId, busId, student_code, parent_phone]); added++; }
        } else { await conn.query(`INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone) VALUES (?, ?, ?, ?, ?)`, [student_name, class_name, parentId, busId, parent_phone]); added++; }
      } catch (e: any) { failed++; errors.push(`${row.student_name || '?'}: ${e.message}`); }
    }
    await conn.commit();
    res.json({ ok: true, added, updated, failed, errors });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// 帳號管理 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/accounts', auth(['admin']), async (_req, res) => {
  try {
    const [drivers]: any = await pool.query(`SELECT id, name, account, phone, is_active, 'driver' as role FROM drivers ORDER BY account`);
    const [parents]: any = await pool.query(`SELECT id, name, account, phone, 1 as is_active, 'parent' as role FROM parents ORDER BY name`);
    const [admins]: any = await pool.query(`SELECT id, name, account, '' as phone, 1 as is_active, 'admin' as role FROM admins ORDER BY name`);
    res.json({ drivers, parents, admins });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/admin/accounts', auth(['admin']), async (req, res) => {
  const { role, name, account, password, phone } = req.body;
  if (!role || !name || !account || !password) return res.status(400).json({ error: '缺少必要欄位' });
  try {
    if (role === 'driver') await pool.query(`INSERT INTO drivers (name, account, password, phone) VALUES (?, ?, ?, ?)`, [name, account, password, phone || '']);
    else if (role === 'parent') await pool.query(`INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`, [name, account, password, phone || '']);
    else if (role === 'admin') await pool.query(`INSERT INTO admins (name, account, password) VALUES (?, ?, ?)`, [name, account, password]);
    else return res.status(400).json({ error: '角色錯誤' });
    res.json({ ok: true });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '帳號已存在' });
    res.status(500).json({ error: String(e) });
  }
});

app.put('/api/admin/accounts/:role/:id', auth(['admin']), async (req, res) => {
  const { role, id } = req.params;
  const { name, account, password, phone, driver_id } = req.body;
  try {
    if (role === 'bus') {
      if (driver_id !== undefined) await pool.query(`UPDATE buses SET driver_id = ? WHERE id = ?`, [driver_id || null, id]);
      if (name) await pool.query(`UPDATE buses SET bus_name = ? WHERE id = ?`, [name, id]);
    } else if (role === 'driver') {
      if (password) await pool.query(`UPDATE drivers SET name=?, account=?, password=?, phone=? WHERE id=?`, [name, account, password, phone || '', id]);
      else await pool.query(`UPDATE drivers SET name=?, account=?, phone=? WHERE id=?`, [name, account, phone || '', id]);
    } else if (role === 'parent') {
      if (password) await pool.query(`UPDATE parents SET name=?, account=?, password=?, phone=? WHERE id=?`, [name, account, password, phone || '', id]);
      else await pool.query(`UPDATE parents SET name=?, account=?, phone=? WHERE id=?`, [name, account, phone || '', id]);
    } else if (role === 'admin') {
      if (password) await pool.query(`UPDATE admins SET name=?, account=?, password=? WHERE id=?`, [name, account, password, id]);
      else await pool.query(`UPDATE admins SET name=?, account=? WHERE id=?`, [name, account, id]);
    }
    res.json({ ok: true });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '帳號已存在' });
    res.status(500).json({ error: String(e) });
  }
});

app.delete('/api/admin/accounts/:role/:id', auth(['admin']), async (req, res) => {
  const { role, id } = req.params;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    if (role === 'driver') {
      await conn.query(`UPDATE buses SET driver_id = NULL WHERE driver_id = ?`, [id]);
      await conn.query(`DELETE FROM driver_sessions WHERE driver_id = ?`, [id]);
      await conn.query(`DELETE FROM drivers WHERE id = ?`, [id]);
    } else if (role === 'parent') {
      const [stuList]: any = await conn.query(`SELECT id FROM students WHERE parent_id = ?`, [id]);
      for (const s of stuList) {
        await conn.query(`DELETE FROM boarding_records WHERE student_id = ?`, [s.id]);
        await conn.query(`DELETE FROM students WHERE id = ?`, [s.id]);
      }
      await conn.query(`DELETE FROM parents WHERE id = ?`, [id]);
    } else if (role === 'admin') {
      await conn.query(`DELETE FROM admins WHERE id = ?`, [id]);
    } else if (role === 'student') {
      await conn.query(`DELETE FROM boarding_records WHERE student_id = ?`, [id]);
      await conn.query(`DELETE FROM students WHERE id = ?`, [id]);
    }
    await conn.commit();
    res.json({ ok: true });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// 清理 API
// ══════════════════════════════════════════════════════
app.post('/api/admin/cleanup', auth(['admin']), async (req, res) => {
  const { bus_names } = req.body;
  if (!Array.isArray(bus_names) || bus_names.length === 0) return res.status(400).json({ error: '請提供 bus_names' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const ph = bus_names.map(() => '?').join(',');
    const [busList]: any = await conn.query(`SELECT id FROM buses WHERE bus_name IN (${ph})`, bus_names);
    const busIds = busList.map((b: any) => b.id);
    let deletedStudents = 0, deletedBuses = 0;
    if (busIds.length > 0) {
      const bph = busIds.map(() => '?').join(',');
      const [stuList]: any = await conn.query(`SELECT id FROM students WHERE bus_id IN (${bph})`, busIds);
      const stuIds = stuList.map((s: any) => s.id);
      if (stuIds.length > 0) {
        const sph = stuIds.map(() => '?').join(',');
        await conn.query(`DELETE FROM boarding_records WHERE student_id IN (${sph})`, stuIds);
        await conn.query(`DELETE FROM students WHERE id IN (${sph})`, stuIds);
        deletedStudents = stuIds.length;
      }
      await conn.query(`DELETE FROM bus_locations WHERE bus_id IN (${bph})`, busIds);
      const [sessions]: any = await conn.query(`SELECT id FROM driver_sessions WHERE bus_id IN (${bph})`, busIds);
      if (sessions.length > 0) {
        const sessionIds = sessions.map((s: any) => s.id);
        await conn.query(`DELETE FROM boarding_records WHERE session_id IN (${sessionIds.map(() => '?').join(',')})`, sessionIds);
        await conn.query(`DELETE FROM driver_sessions WHERE bus_id IN (${bph})`, busIds);
      }
      await conn.query(`UPDATE buses SET driver_id = NULL WHERE id IN (${bph})`, busIds);
      await conn.query(`DELETE FROM buses WHERE id IN (${bph})`, busIds);
      deletedBuses = busIds.length;
    }
    await conn.query(`DELETE FROM parents WHERE account IN ('user','0933333333','0922222222','0987654321') AND NOT EXISTS (SELECT 1 FROM students s WHERE s.parent_id = parents.id)`);
    await conn.query(`DELETE FROM drivers WHERE account = 'bus' AND NOT EXISTS (SELECT 1 FROM buses b WHERE b.driver_id = drivers.id)`);
    await conn.commit();
    res.json({ ok: true, deletedBuses, deletedStudents });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// 匯出 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/export', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT b.route_name, b.bus_name, d.name as driver_name, d.phone as driver_phone,
              s.name as student_name, s.student_code, s.school_class as class_name,
              p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN buses b ON s.bus_id = b.id
       LEFT JOIN drivers d ON b.driver_id = d.id LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.is_active = 1 ORDER BY b.route_name, b.bus_name, s.name`
    );
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    wb.creator = '校車定位系統';
    wb.created = new Date();
    const ws = wb.addWorksheet('學生名單', { views: [{ state: 'frozen', ySplit: 3 }] });
    const headers = [
      { key: 'route_name', label: '路線名稱', note: '選填', width: 14 },
      { key: 'bus_name', label: '車次名稱', note: '必填', width: 16 },
      { key: 'driver_name', label: '司機姓名', note: '選填', width: 13 },
      { key: 'driver_phone', label: '司機手機', note: '選填', width: 18 },
      { key: 'student_name', label: '學生姓名', note: '必填', width: 13 },
      { key: 'student_code', label: '學生證號', note: '選填', width: 16 },
      { key: 'class_name', label: '班級', note: '選填', width: 13 },
      { key: 'parent_name', label: '家長姓名', note: '必填', width: 13 },
      { key: 'parent_phone', label: '家長手機', note: '必填', width: 18 },
    ];
    ws.columns = headers.map(h => ({ width: h.width }));
    ws.mergeCells('A1:I1');
    const titleCell = ws.getCell('A1');
    titleCell.value = `校車學生資料庫 ｜ 共 ${rows.length} 筆 ｜ 匯出時間：${new Date().toLocaleString('zh-TW')}`;
    titleCell.font = { name: 'Microsoft JhengHei', size: 12, bold: true, color: { argb: 'FFFFFFFF' } };
    titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0A1628' } };
    titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
    ws.getRow(1).height = 28;
    const row2 = ws.getRow(2);
    headers.forEach((h, i) => {
      const cell = row2.getCell(i + 1);
      cell.value = h.key;
      cell.font = { name: 'Microsoft JhengHei', size: 11, bold: true, color: { argb: 'FFFFFFFF' } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E3A6E' } };
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
    });
    row2.height = 22;
    const row3 = ws.getRow(3);
    headers.forEach((h, i) => {
      const cell = row3.getCell(i + 1);
      cell.value = `${h.label} (${h.note})`;
      cell.font = { name: 'Microsoft JhengHei', size: 10, color: { argb: 'FFFCD34D' } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1A1000' } };
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
    });
    row3.height = 28;
    rows.forEach((r: any, idx: number) => {
      const row = ws.addRow(headers.map(h => r[h.key] || ''));
      const isEven = idx % 2 === 0;
      row.eachCell((cell: any) => {
        cell.font = { name: 'Microsoft JhengHei', size: 11 };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: isEven ? 'FFFAFAFA' : 'FFFFFFFF' } };
        cell.alignment = { horizontal: 'center', vertical: 'middle' };
      });
      row.height = 20;
    });
    const today = new Date().toLocaleDateString('zh-TW').replace(/\//g, '');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''%E6%A0%A1%E8%BB%8A%E5%AD%B8%E7%94%9F%E8%B3%87%E6%96%99%E5%BA%AB_${today}.xlsx`);
    await wb.xlsx.write(res);
    res.end();
  } catch (e: any) { res.status(500).json({ error: String(e) }); }
});



// PUT /api/admin/students/:id — 修改學生資料（含校車）
app.put('/api/admin/students/:id', auth(['admin']), async (req: AuthRequest, res) => {
  const id = Number(req.params.id);
  const { name, school_class, bus_id, parent_id } = req.body;
  if (isNaN(id)) return res.status(400).json({ error: '無效的 ID' });
  if (!bus_id) return res.status(400).json({ error: '請選擇校車' });
  try {
    await pool.query(
      `UPDATE students SET name=?, school_class=?, bus_id=?, parent_id=? WHERE id=?`,
      [name, school_class, Number(bus_id), parent_id, id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// ══════════════════════════════════════════════════════
// 路線管理 API
// ══════════════════════════════════════════════════════

// POST /api/admin/buses — 新增校車
app.post('/api/admin/buses', auth(['admin']), async (req: AuthRequest, res) => {
  const { bus_name, route_name, driver_id } = req.body;
  if (!bus_name || !route_name) return res.status(400).json({ error: '請提供 bus_name 和 route_name' });
  try {
    const [r]: any = await pool.query(
      `INSERT INTO buses (bus_name, route_name, driver_id) VALUES (?, ?, ?)`,
      [bus_name, route_name, driver_id || null]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '車次名稱已存在' });
    res.status(500).json({ error: String(e) });
  }
});

// DELETE /api/admin/buses/:id — 刪除單台校車（含學生和出勤紀錄）
app.delete('/api/admin/buses/:id', auth(['admin']), async (req: AuthRequest, res) => {
  const busId = Number(req.params.id);
  if (isNaN(busId)) return res.status(400).json({ error: '無效的校車 ID' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // 找出此校車的學生
    const [stuList]: any = await conn.query(`SELECT id FROM students WHERE bus_id = ?`, [busId]);
    const stuIds = stuList.map((s: any) => s.id);
    if (stuIds.length > 0) {
      const sph = stuIds.map(() => '?').join(',');
      await conn.query(`DELETE FROM boarding_records WHERE student_id IN (${sph})`, stuIds);
      await conn.query(`DELETE FROM students WHERE id IN (${sph})`, stuIds);
    }
    // 找出 sessions
    const [sessions]: any = await conn.query(`SELECT id FROM driver_sessions WHERE bus_id = ?`, [busId]);
    if (sessions.length > 0) {
      const sessionIds = sessions.map((s: any) => s.id);
      await conn.query(`DELETE FROM boarding_records WHERE session_id IN (${sessionIds.map(() => '?').join(',')})`, sessionIds);
      await conn.query(`DELETE FROM driver_sessions WHERE bus_id = ?`, [busId]);
    }
    await conn.query(`DELETE FROM bus_locations WHERE bus_id = ?`, [busId]);
    await conn.query(`UPDATE buses SET driver_id = NULL WHERE id = ?`, [busId]);
    await conn.query(`DELETE FROM buses WHERE id = ?`, [busId]);
    await conn.commit();
    res.json({ ok: true, deletedStudents: stuIds.length });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: String(e) }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════
// Start Server
// ══════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`✅ 校車系統 API running on port ${PORT}`);
  console.log(`   TZ=${process.env.TZ || '(未設定)'}`);
  console.log(`   自動下線：超過 ${AUTO_OFFLINE_MINUTES} 分鐘無 GPS 更新自動下線`);
});

// ══════════════════════════════════════════════════════
// 歷史紀錄 API
// ══════════════════════════════════════════════════════

// GET /api/admin/history/sessions?date=2026-04-27&bus_id=4
// 查詢某日出勤紀錄
app.get('/api/admin/history/sessions', auth(['admin']), async (req, res) => {
  const { date, bus_id } = req.query;
  const targetDate = date || new Date().toISOString().slice(0,10);
  try {
    let sql = `
      SELECT
        ds.id, ds.session_date, ds.start_time, ds.end_time,
        d.name as driver_name, d.account as driver_account,
        b.bus_name, b.route_name,
        (SELECT COUNT(*) FROM boarding_records br WHERE br.session_id = ds.id) as boarded_count,
        (SELECT COUNT(*) FROM students s WHERE s.bus_id = ds.bus_id AND s.is_active = 1) as total_students
      FROM driver_sessions ds
      JOIN drivers d ON ds.driver_id = d.id
      JOIN buses b ON ds.bus_id = b.id
      WHERE DATE(ds.session_date) = ?
    `;
    const params: any[] = [targetDate];
    if (bus_id) { sql += ` AND ds.bus_id = ?`; params.push(bus_id); }
    sql += ` ORDER BY ds.start_time DESC`;
    const [rows]: any = await pool.query(sql, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// GET /api/admin/history/boarding?session_id=5
// 查詢某次出勤的學生上車明細
app.get('/api/admin/history/boarding', auth(['admin']), async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: '請提供 session_id' });
  try {
    const [rows]: any = await pool.query(`
      SELECT
        s.name as student_name, s.school_class,
        p.name as parent_name, p.phone as parent_phone,
        br.boarded_at
      FROM students s
      LEFT JOIN parents p ON s.parent_id = p.id
      LEFT JOIN boarding_records br ON br.student_id = s.id AND br.session_id = ?
      WHERE s.bus_id = (SELECT bus_id FROM driver_sessions WHERE id = ?)
        AND s.is_active = 1
      ORDER BY br.boarded_at ASC, s.school_class, s.name
    `, [session_id, session_id]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// GET /api/admin/history/student?student_name=張詠勝&days=7
// 查詢某學生近期上車紀錄
app.get('/api/admin/history/student', auth(['admin']), async (req, res) => {
  const { student_name, days = 7 } = req.query;
  if (!student_name) return res.status(400).json({ error: '請提供 student_name' });
  try {
    const [rows]: any = await pool.query(`
      SELECT
        s.name as student_name, s.school_class,
        b.bus_name, b.route_name,
        ds.session_date, ds.start_time,
        br.boarded_at,
        CASE WHEN br.boarded_at IS NOT NULL THEN '已上車' ELSE '未上車' END as status
      FROM students s
      JOIN buses b ON s.bus_id = b.id
      JOIN driver_sessions ds ON ds.bus_id = b.id
        AND ds.session_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
      LEFT JOIN boarding_records br ON br.student_id = s.id AND br.session_id = ds.id
      WHERE s.name LIKE ? AND s.is_active = 1
      ORDER BY ds.session_date DESC, ds.start_time DESC
    `, [Number(days), `%${student_name}%`]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// GET /api/admin/history/stats?days=30
// 統計報表：各校車出勤率
app.get('/api/admin/history/stats', auth(['admin']), async (req, res) => {
  const { days = 30 } = req.query;
  try {
    const [rows]: any = await pool.query(`
      SELECT
        b.id as bus_id, b.bus_name, b.route_name,
        COUNT(DISTINCT ds.id) as total_sessions,
        COUNT(DISTINCT DATE(ds.session_date)) as active_days,
        COALESCE(SUM(br_count.cnt), 0) as total_boardings,
        COALESCE(AVG(br_count.cnt), 0) as avg_boardings,
        (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1) as enrolled_students
      FROM buses b
      LEFT JOIN driver_sessions ds ON ds.bus_id = b.id
        AND ds.session_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        AND ds.end_time IS NOT NULL
      LEFT JOIN (
        SELECT session_id, COUNT(*) as cnt FROM boarding_records GROUP BY session_id
      ) br_count ON br_count.session_id = ds.id
      GROUP BY b.id, b.bus_name, b.route_name
      ORDER BY b.route_name, b.bus_name
    `, [Number(days)]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: String(e) }); }
});
