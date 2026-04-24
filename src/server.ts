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
      return {
        student: { id: student.id, name: student.name, school_class: student.school_class },
        bus: { id: student.bus_id, bus_name: student.bus_name, route_name: student.route_name },
        location: locs[0] || null,
        is_online: sessions.length > 0,
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

app.listen(PORT, () => {
  console.log(`✅ 校車系統 API running on port ${PORT}`);
  console.log(`   TZ=${process.env.TZ || '(未設定)'}`);
});
