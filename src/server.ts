// src/server.ts — 校車定位管理系統後端（含放學時段 + 座位管理）
import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || 'school-bus-secret-2026';

app.use(cors());
app.use(express.json({ limit: '10mb' })); // 3c-1: 批次匯入 479 筆 JSON 較大,預設 100KB 會 413

// ── DB Pool ────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     Number(process.env.DB_PORT || 3306),
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'zeabur',
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
// ══════════════════════════════════════════════════════
const AUTO_OFFLINE_MINUTES = 180; // 3小時無GPS才自動下線

async function autoOfflineCheck() {
  try {
    const [sessions]: any = await pool.query(`
      SELECT ds.id, ds.driver_id, ds.bus_id, d.name as driver_name, b.bus_name
      FROM driver_sessions ds
      JOIN drivers d ON ds.driver_id = d.id
      JOIN buses b ON ds.bus_id = b.id
      WHERE ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00'))
        AND ds.end_time IS NULL
        AND COALESCE(
          (SELECT MAX(bl.created_at) FROM bus_locations bl WHERE bl.session_id = ds.id),
          ds.start_time
        ) < DATE_SUB(NOW(), INTERVAL ${AUTO_OFFLINE_MINUTES} MINUTE)
    `);
    if (sessions.length > 0) {
      const ids = sessions.map((s: any) => s.id);
      const ph = ids.map(() => '?').join(',');
      await pool.query(`UPDATE driver_sessions SET end_time = NOW() WHERE id IN (${ph})`, ids);
      sessions.forEach((s: any) => {
        console.log(`[自動下線] ${s.driver_name} / ${s.bus_name} (session_id: ${s.id})`);
      });
    }
  } catch (e) {
    console.error('[自動下線] 檢查失敗:', e);
  }
}
setInterval(autoOfflineCheck, 5 * 60 * 1000);
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
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 司機端
// ══════════════════════════════════════════════════════
app.get('/api/driver/me', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [drivers]: any = await pool.query(
      `SELECT d.id, d.name, d.phone, b.id as bus_id, b.bus_name, b.route_name, b.bus_type, b.capacity
       FROM drivers d LEFT JOIN buses b ON b.driver_id = d.id
       WHERE d.id = ? LIMIT 1`,
      [driverId]
    );
    const driver = drivers[0];
    if (!driver) return res.status(404).json({ error: '找不到司機' });
    const [sessions]: any = await pool.query(
      `SELECT * FROM driver_sessions WHERE driver_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) ORDER BY id DESC LIMIT 1`,
      [driverId]
    );
    res.json({ driver, session: sessions[0] || null });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/driver/online', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [buses]: any = await pool.query(`SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]);
    const bus = buses[0];
    if (!bus) return res.status(400).json({ error: '尚未分配校車' });
    const [existing]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND end_time IS NULL LIMIT 1`,
      [driverId]
    );
    if (existing[0]) return res.status(400).json({ error: '已經上線' });
    const [result]: any = await pool.query(
      `INSERT INTO driver_sessions (driver_id, bus_id, session_date) VALUES (?, ?, DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')))`,
      [driverId, bus.id]
    );
    res.json({ session_id: result.insertId, bus_id: bus.id });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/driver/offline', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    await pool.query(
      `UPDATE driver_sessions SET end_time = NOW() WHERE driver_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND end_time IS NULL`,
      [driverId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/location/update', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { latitude, longitude, accuracy } = req.body;
  try {
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds
       WHERE ds.driver_id = ? AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL LIMIT 1`,
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

app.get('/api/driver/students', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  try {
    const [buses]: any = await pool.query(`SELECT id FROM buses WHERE driver_id = ? AND is_active = 1 LIMIT 1`, [driverId]);
    const bus = buses[0];
    if (!bus) return res.json({ students: [], session: null });
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE driver_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0] || null;

    // 取得今天星期幾（1=週一 ~ 5=週五，週六日回空）
    const dayOfWeek = new Date().getDay(); // 0=日,1=一...6=六
    const todayKey = dayOfWeek === 0 || dayOfWeek === 6 ? null : String(dayOfWeek);

    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.student_code,
              s.pickup_location, s.dropoff_1620, s.dropoff_1800,
              s.dismissal_session, s.active_days,
              p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.bus_id = ? AND s.is_active = 1
       ORDER BY s.school_class, s.name`,
      [bus.id]
    );

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

    const result = students
      .filter((s: any) => !todayKey || (s.active_days || '12345').includes(todayKey))
      .map((s: any) => ({
        ...s,
        is_boarded: boardedIds.includes(s.id),
        boarded_at: boardingTimes[s.id] || null
      }));

    res.json({
      students: result,
      session,
      total: result.length,
      boarded: boardedIds.length,
      missing: result.length - boardedIds.length
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/driver/scan', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { code } = req.body;
  try {
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds
       WHERE ds.driver_id = ? AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '請先上線' });
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.bus_id,
              s.pickup_location, s.dropoff_1620, s.dropoff_1800, s.dismissal_session,
              p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`,
      [code, code]
    );
    const student = students[0];
    if (!student) return res.json({ status: 'not_found', message: '查無學生，請聯絡管理員' });
    if (student.bus_id !== session.bus_id)
      return res.json({ status: 'wrong_bus', message: `${student.name} 不是本車學生`, student });
    await pool.query(
      `INSERT INTO boarding_records (student_id, session_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE boarded_at = NOW()`,
      [student.id, session.id]
    );
    res.json({ status: 'ok', message: `${student.name} 上車成功`, student });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 家長端
// ══════════════════════════════════════════════════════
app.get('/api/parent/me', auth(['parent']), async (req: AuthRequest, res) => {
  const parentId = req.user!.id;
  try {
    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class,
              s.pickup_location, s.dropoff_1620, s.dropoff_1800,
              s.dismissal_session, s.active_days,
              s.school_direction,
              s.dismissal_mon, s.dismissal_tue, s.dismissal_wed, s.dismissal_thu, s.dismissal_fri,
              b.id as bus_id, b.bus_name, b.route_name
       FROM students s JOIN buses b ON s.bus_id = b.id
       WHERE s.parent_id = ? AND s.is_active = 1`,
      [parentId]
    );
    const result = await Promise.all(students.map(async (student: any) => {
      const [locs]: any = await pool.query(
        `SELECT latitude, longitude, created_at FROM bus_locations WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`,
        [student.bus_id]
      );
      const [sessions]: any = await pool.query(
        `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND end_time IS NULL LIMIT 1`,
        [student.bus_id]
      );
      const sessionId = sessions[0]?.id || null;
      let boarded_at = null;
      let alighted_at = null;
      if (sessionId) {
        const [boarding]: any = await pool.query(
          `SELECT boarded_at FROM boarding_records WHERE student_id = ? AND session_id = ? LIMIT 1`,
          [student.id, sessionId]
        );
        boarded_at = boarding[0]?.boarded_at || null;

        const [alighting]: any = await pool.query(
          `SELECT alighted_at FROM alighting_records WHERE student_id = ? AND session_id = ? LIMIT 1`,
          [student.id, sessionId]
        );
        alighted_at = alighting[0]?.alighted_at || null;
      }
      return {
        student: {
          id: student.id, name: student.name, school_class: student.school_class,
          pickup_location: student.pickup_location,
          dropoff_1620: student.dropoff_1620, dropoff_1800: student.dropoff_1800,
          dismissal_session: student.dismissal_session, active_days: student.active_days,
          school_direction: student.school_direction,
          dismissal_mon: student.dismissal_mon, dismissal_tue: student.dismissal_tue,
          dismissal_wed: student.dismissal_wed, dismissal_thu: student.dismissal_thu,
          dismissal_fri: student.dismissal_fri
        },
        bus: { id: student.bus_id, bus_name: student.bus_name, route_name: student.route_name },
        location: locs[0] || null,
        is_online: sessions.length > 0,
        boarded_at,
        alighted_at,
      };
    }));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/bus/:busId/location', auth(['parent', 'admin']), async (req: AuthRequest, res) => {
  const busId = Number(req.params.busId);
  const role = req.user!.role;
  try {
    if (role === 'parent') {
      const [check]: any = await pool.query(
        `SELECT s.id FROM students s WHERE s.parent_id = ? AND s.bus_id = ? AND s.is_active = 1 LIMIT 1`,
        [req.user!.id, busId]
      );
      if (!check[0]) return res.status(403).json({ error: '無權限查看此校車' });
    }
    const [locs]: any = await pool.query(
      `SELECT latitude, longitude, created_at FROM bus_locations WHERE bus_id = ? ORDER BY created_at DESC LIMIT 1`,
      [busId]
    );
    const [sessions]: any = await pool.query(
      `SELECT id FROM driver_sessions WHERE bus_id = ? AND session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND end_time IS NULL LIMIT 1`,
      [busId]
    );
    res.json({ location: locs[0] || null, is_online: sessions.length > 0 });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
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
    const [buses]: any = await pool.query(`
      SELECT b.id, b.bus_name, b.route_name, b.is_active, b.bus_type, b.capacity,
             d.id as driver_id, d.name as driver_name,
             bl.latitude, bl.longitude, bl.created_at as last_seen,
             (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1 AND s.school_direction = 'morning') as student_count,
             (SELECT id FROM driver_sessions ds
              WHERE ds.bus_id = b.id AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL LIMIT 1) as session_id
      FROM buses b
      LEFT JOIN drivers d ON b.driver_id = d.id
      LEFT JOIN bus_locations bl ON bl.id = (
        SELECT id FROM bus_locations WHERE bus_id = b.id ORDER BY created_at DESC LIMIT 1
      )
      ORDER BY b.route_name, b.bus_name
    `);
    res.json(buses);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.put('/api/admin/buses/:busId', auth(['admin']), async (req, res) => {
  const busId = Number(req.params.busId);
  const { driver_id, bus_type, capacity } = req.body;
  try {
    const fields: string[] = [];
    const vals: any[] = [];
    if (driver_id !== undefined) { fields.push('driver_id = ?'); vals.push(driver_id ?? null); }
    if (bus_type !== undefined)  { fields.push('bus_type = ?');  vals.push(bus_type); }
    if (capacity !== undefined)  { fields.push('capacity = ?');  vals.push(Number(capacity)); }
    if (fields.length === 0) return res.status(400).json({ error: '沒有可更新的欄位' });
    vals.push(busId);
    await pool.query(`UPDATE buses SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// 保留舊路由相容性
app.put('/api/admin/buses/:busId/driver', auth(['admin']), async (req, res) => {
  const busId = Number(req.params.busId);
  const { driver_id } = req.body;
  try {
    await pool.query(`UPDATE buses SET driver_id = ? WHERE id = ?`, [driver_id ?? null, busId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/buses/locations', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT b.id, b.bus_name, b.route_name, b.bus_type, b.capacity,
             d.name AS driver_name, d.account AS driver_account,
             bl.latitude, bl.longitude, bl.created_at AS last_seen,
             (SELECT id FROM driver_sessions ds
              WHERE ds.bus_id = b.id AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL LIMIT 1) AS session_id,
             (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1 AND s.school_direction = 'morning') AS student_count,
             (SELECT COUNT(*) FROM boarding_records br
              JOIN driver_sessions ds ON br.session_id = ds.id
              WHERE ds.bus_id = b.id AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL) AS boarded_count
      FROM buses b
      LEFT JOIN drivers d ON b.driver_id = d.id
      LEFT JOIN bus_locations bl ON bl.id = (
        SELECT id FROM bus_locations WHERE bus_id = b.id ORDER BY created_at DESC LIMIT 1
      )
      WHERE b.is_active = 1
      ORDER BY b.route_name, b.bus_name
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/buses/:busId/history', auth(['admin', 'parent']), async (req, res) => {
  const busId = Number(req.params.busId);
  try {
    const [rows]: any = await pool.query(
      `SELECT latitude, longitude, created_at FROM bus_locations
       WHERE bus_id = ? AND DATE(created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) ORDER BY created_at ASC`,
      [busId]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/buses-simple', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT id, bus_name, route_name, bus_type, capacity,
              (SELECT COUNT(*) FROM students s WHERE s.bus_id = buses.id AND s.is_active = 1 AND s.school_direction = 'morning') as student_count
       FROM buses WHERE is_active = 1 ORDER BY route_name, bus_name`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 管理員端 - 學生管理
// ══════════════════════════════════════════════════════
app.get('/api/admin/students', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT s.id, s.name, s.school_class, s.is_active, s.parent_id, s.bus_id,
             s.address, s.pickup_location, s.dropoff_1620, s.dropoff_1800,
             s.dismissal_session, s.active_days,
             s.school_direction,
             s.dismissal_mon, s.dismissal_tue, s.dismissal_wed, s.dismissal_thu, s.dismissal_fri,
             p.name as parent_name, p.account as parent_account,
             b.bus_name, b.route_name, b.bus_type, b.capacity,
             (SELECT COUNT(*) FROM students ss WHERE ss.bus_id = s.bus_id AND ss.is_active = 1 AND ss.school_direction = 'morning') as bus_student_count
      FROM students s
      JOIN parents p ON s.parent_id = p.id
      JOIN buses b ON s.bus_id = b.id
      ORDER BY b.route_name, s.name
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/admin/students', auth(['admin']), async (req, res) => {
  const { name, school_class, parent_id, bus_id,
          address, pickup_location, dropoff_1620, dropoff_1800,
          dismissal_session, active_days,
          school_direction,
          dismissal_mon, dismissal_tue, dismissal_wed, dismissal_thu, dismissal_fri } = req.body;
  try {
    // 座位上限檢查
    const [cap]: any = await pool.query(
      `SELECT b.capacity,
              (SELECT COUNT(*) FROM students WHERE bus_id = ? AND is_active = 1) as current_count
       FROM buses b WHERE b.id = ?`,
      [bus_id, bus_id]
    );
    if (cap[0] && cap[0].current_count >= cap[0].capacity) {
      return res.status(400).json({ error: `此校車已達座位上限（${cap[0].capacity} 人）` });
    }
    const [r]: any = await pool.query(
      `INSERT INTO students
         (name, school_class, parent_id, bus_id, address, pickup_location,
          dropoff_1620, dropoff_1800, dismissal_session, active_days,
          school_direction, dismissal_mon, dismissal_tue, dismissal_wed, dismissal_thu, dismissal_fri)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, school_class, parent_id, bus_id,
       address || null, pickup_location || null,
       dropoff_1620 || null, dropoff_1800 || null,
       dismissal_session || null, active_days || '12345',
       school_direction || null,
       dismissal_mon || null, dismissal_tue || null, dismissal_wed || null,
       dismissal_thu || null, dismissal_fri || null]
    );
    res.json({ id: r.insertId });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.put('/api/admin/students/:id', auth(['admin']), async (req: AuthRequest, res) => {
  const id = Number(req.params.id);
  const { name, school_class, bus_id, parent_id,
          address, pickup_location, dropoff_1620, dropoff_1800,
          dismissal_session, active_days,
          school_direction,
          dismissal_mon, dismissal_tue, dismissal_wed, dismissal_thu, dismissal_fri } = req.body;
  if (isNaN(id))  return res.status(400).json({ error: '無效的 ID' });
  if (!bus_id)    return res.status(400).json({ error: '請選擇校車' });
  try {
    // 若換車，檢查新車座位上限（排除自己）
    const [current]: any = await pool.query(`SELECT bus_id FROM students WHERE id = ?`, [id]);
    if (current[0] && Number(current[0].bus_id) !== Number(bus_id)) {
      const [cap]: any = await pool.query(
        `SELECT b.capacity,
                (SELECT COUNT(*) FROM students WHERE bus_id = ? AND is_active = 1 AND id != ?) as current_count
         FROM buses b WHERE b.id = ?`,
        [bus_id, id, bus_id]
      );
      if (cap[0] && cap[0].current_count >= cap[0].capacity) {
        return res.status(400).json({ error: `目標校車已達座位上限（${cap[0].capacity} 人）` });
      }
    }
    await pool.query(
      `UPDATE students SET
         name=?, school_class=?, bus_id=?, parent_id=?,
         address=?, pickup_location=?, dropoff_1620=?, dropoff_1800=?,
         dismissal_session=?, active_days=?,
         school_direction=?,
         dismissal_mon=?, dismissal_tue=?, dismissal_wed=?, dismissal_thu=?, dismissal_fri=?
       WHERE id=?`,
      [name, school_class, Number(bus_id), parent_id,
       address || null, pickup_location || null,
       dropoff_1620 || null, dropoff_1800 || null,
       dismissal_session || null, active_days || '12345',
       school_direction || null,
       dismissal_mon || null, dismissal_tue || null, dismissal_wed || null,
       dismissal_thu || null, dismissal_fri || null, id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
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
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// 管理員端 - 司機管理
// ══════════════════════════════════════════════════════
app.get('/api/admin/drivers', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT d.id, d.name, d.phone, d.account, d.is_active, b.bus_name, b.route_name
      FROM drivers d LEFT JOIN buses b ON b.driver_id = d.id
      ORDER BY d.account
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 掃描建檔 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/scan/:code', auth(['admin', 'driver']), async (req: AuthRequest, res) => {
  const code = req.params.code;
  try {
    const [rows]: any = await pool.query(
      `SELECT s.*, p.name as parent_name, p.phone as parent_phone, b.bus_name, b.route_name
       FROM students s
       LEFT JOIN parents p ON s.parent_id = p.id
       LEFT JOIN buses b ON s.bus_id = b.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`,
      [code, code]
    );
    if (rows[0]) res.json({ found: true, student: rows[0] });
    else res.json({ found: false, scanned_code: code });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/admin/scan/save', auth(['admin']), async (req: AuthRequest, res) => {
  const { student_code, student_name, school_class, parent_name, parent_phone,
          bus_id, student_id, pickup_location, dropoff_1620, dropoff_1800,
          dismissal_session, active_days } = req.body;
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
        `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE name=VALUES(name), phone=VALUES(phone)`,
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
        `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, student_code=?, parent_phone=?,
         pickup_location=?, dropoff_1620=?, dropoff_1800=?, dismissal_session=?, active_days=?
         WHERE id=?`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone,
         pickup_location || null, dropoff_1620 || null, dropoff_1800 || null,
         dismissal_session || null, active_days || '12345', student_id]
      );
    } else {
      await conn.query(
        `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone,
          pickup_location, dropoff_1620, dropoff_1800, dismissal_session, active_days)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [student_name, school_class, parentId, bus_id, student_code, parent_phone,
         pickup_location || null, dropoff_1620 || null, dropoff_1800 || null,
         dismissal_session || null, active_days || '12345']
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
        if (!student_name || !parent_phone || !bus_name) {
          failed++; errors.push(`${student_name || '?'}: 缺少必要欄位`); continue;
        }
        const [buses]: any = await conn.query(`SELECT id, capacity FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]);
        if (!buses[0]) { failed++; errors.push(`${student_name}: 找不到校車「${bus_name}」`); continue; }
        const busId = buses[0].id;
        let parentId: number;
        const [existingP]: any = await conn.query(`SELECT id FROM parents WHERE phone = ? LIMIT 1`, [parent_phone]);
        if (existingP[0]) {
          parentId = existingP[0].id;
        } else {
          const [r]: any = await conn.query(
            `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
            [parent_name, parent_phone, parent_phone.slice(-4), parent_phone]
          );
          parentId = r.insertId;
        }
        if (student_code) {
          const [existingS]: any = await conn.query(`SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]);
          if (existingS[0]) {
            await conn.query(
              `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`,
              [student_name, class_name, parentId, busId, parent_phone, existingS[0].id]
            );
            updated++;
          } else {
            await conn.query(
              `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone) VALUES (?, ?, ?, ?, ?, ?)`,
              [student_name, class_name, parentId, busId, student_code, parent_phone]
            );
            added++;
          }
        } else {
          await conn.query(
            `INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone) VALUES (?, ?, ?, ?, ?)`,
            [student_name, class_name, parentId, busId, parent_phone]
          );
          added++;
        }
      } catch (e: any) {
        failed++; errors.push(`${row.student_name || '?'}: ${e.message}`);
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
        const { route_name, bus_name, driver_name, driver_phone,
                student_name, student_code, class_name, parent_name, parent_phone } = row;
        if (!bus_name || !student_name || !parent_phone) {
          failed++; errors.push(`${student_name || '?'}: 缺少必要欄位`); continue;
        }
        let busId: number;
        const [existingBus]: any = await conn.query(`SELECT id FROM buses WHERE bus_name = ? LIMIT 1`, [bus_name]);
        if (existingBus[0]) {
          busId = existingBus[0].id;
        } else {
          let driverId: number | null = null;
          if (driver_phone) {
            const [existingDriver]: any = await conn.query(`SELECT id FROM drivers WHERE account = ? LIMIT 1`, [driver_phone]);
            if (existingDriver[0]) {
              driverId = existingDriver[0].id;
            } else if (driver_name) {
              const [dr]: any = await conn.query(
                `INSERT INTO drivers (name, phone, account, password) VALUES (?, ?, ?, ?)`,
                [driver_name, driver_phone, driver_phone, driver_phone.slice(-4)]
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
        let parentId: number;
        const [existingParent]: any = await conn.query(
          `SELECT id FROM parents WHERE phone = ? OR account = ? LIMIT 1`,
          [parent_phone, parent_phone]
        );
        if (existingParent[0]) {
          parentId = existingParent[0].id;
          await conn.query(`UPDATE parents SET name = ? WHERE id = ?`, [parent_name, parentId]);
        } else {
          const [pr]: any = await conn.query(
            `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
            [parent_name, parent_phone, parent_phone.slice(-4), parent_phone]
          );
          parentId = pr.insertId;
        }
        if (student_code) {
          const [existingStudent]: any = await conn.query(`SELECT id FROM students WHERE student_code = ? LIMIT 1`, [student_code]);
          if (existingStudent[0]) {
            await conn.query(
              `UPDATE students SET name=?, school_class=?, parent_id=?, bus_id=?, parent_phone=? WHERE id=?`,
              [student_name, class_name, parentId, busId, parent_phone, existingStudent[0].id]
            );
            updated++;
          } else {
            await conn.query(
              `INSERT INTO students (name, school_class, parent_id, bus_id, student_code, parent_phone) VALUES (?, ?, ?, ?, ?, ?)`,
              [student_name, class_name, parentId, busId, student_code, parent_phone]
            );
            added++;
          }
        } else {
          await conn.query(
            `INSERT INTO students (name, school_class, parent_id, bus_id, parent_phone) VALUES (?, ?, ?, ?, ?)`,
            [student_name, class_name, parentId, busId, parent_phone]
          );
          added++;
        }
      } catch (e: any) {
        failed++; errors.push(`${row.student_name || '?'}: ${e.message}`);
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
// 帳號管理 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/accounts', auth(['admin']), async (_req, res) => {
  try {
    const [drivers]: any = await pool.query(`SELECT id, name, account, phone, is_active, 'driver' as role FROM drivers ORDER BY account`);
    const [parents]: any = await pool.query(`SELECT id, name, account, phone, 1 as is_active, 'parent' as role FROM parents ORDER BY name`);
    const [admins]: any  = await pool.query(`SELECT id, name, account, '' as phone, 1 as is_active, 'admin' as role FROM admins ORDER BY name`);
    res.json({ drivers, parents, admins });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/admin/accounts', auth(['admin']), async (req, res) => {
  const { role, name, account, password, phone } = req.body;
  if (!role || !name || !account || !password) return res.status(400).json({ error: '缺少必要欄位' });
  try {
    if (role === 'driver')      await pool.query(`INSERT INTO drivers (name, account, password, phone) VALUES (?, ?, ?, ?)`, [name, account, password, phone || '']);
    else if (role === 'parent') await pool.query(`INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`, [name, account, password, phone || '']);
    else if (role === 'admin')  await pool.query(`INSERT INTO admins (name, account, password) VALUES (?, ?, ?)`, [name, account, password]);
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
      else          await pool.query(`UPDATE drivers SET name=?, account=?, phone=? WHERE id=?`, [name, account, phone || '', id]);
    } else if (role === 'parent') {
      if (password) await pool.query(`UPDATE parents SET name=?, account=?, password=?, phone=? WHERE id=?`, [name, account, password, phone || '', id]);
      else          await pool.query(`UPDATE parents SET name=?, account=?, phone=? WHERE id=?`, [name, account, phone || '', id]);
    } else if (role === 'admin') {
      if (password) await pool.query(`UPDATE admins SET name=?, account=?, password=? WHERE id=?`, [name, account, password, id]);
      else          await pool.query(`UPDATE admins SET name=?, account=? WHERE id=?`, [name, account, id]);
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
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// 清理 API
// ══════════════════════════════════════════════════════
app.post('/api/admin/cleanup', auth(['admin']), async (req, res) => {
  const { bus_names } = req.body;
  if (!Array.isArray(bus_names) || bus_names.length === 0)
    return res.status(400).json({ error: '請提供 bus_names' });
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
    await conn.commit();
    res.json({ ok: true, deletedBuses, deletedStudents });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// 匯出 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/export', auth(['admin']), async (_req, res) => {
  try {
    const [rows]: any = await pool.query(`
      SELECT b.route_name, b.bus_name, b.bus_type, b.capacity,
             d.name as driver_name, d.phone as driver_phone,
             s.name as student_name, s.student_code, s.school_class as class_name,
             s.address, s.pickup_location, s.dropoff_1620, s.dropoff_1800,
             s.dismissal_session, s.active_days,
             s.school_direction,
             s.dismissal_mon, s.dismissal_tue, s.dismissal_wed, s.dismissal_thu, s.dismissal_fri,
             p.name as parent_name, p.phone as parent_phone
      FROM students s
      LEFT JOIN buses b ON s.bus_id = b.id
      LEFT JOIN drivers d ON b.driver_id = d.id
      LEFT JOIN parents p ON s.parent_id = p.id
      WHERE s.is_active = 1
      ORDER BY b.route_name, b.bus_name, s.name
    `);
    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    wb.creator = '校車定位系統';
    wb.created = new Date();
    const ws = wb.addWorksheet('學生名單', { views: [{ state: 'frozen', ySplit: 3 }] });
    const headers = [
      { key: 'route_name',        label: '路線名稱',       note: '選填', width: 14 },
      { key: 'bus_name',          label: '車次名稱',       note: '必填', width: 16 },
      { key: 'bus_type',          label: '車型',           note: '',     width: 10 },
      { key: 'capacity',          label: '座位上限',       note: '',     width: 10 },
      { key: 'driver_name',       label: '司機姓名',       note: '選填', width: 13 },
      { key: 'driver_phone',      label: '司機手機',       note: '選填', width: 18 },
      { key: 'student_name',      label: '學生姓名',       note: '必填', width: 13 },
      { key: 'student_code',      label: '學生證號',       note: '選填', width: 16 },
      { key: 'class_name',        label: '班級',           note: '選填', width: 13 },
      { key: 'address',           label: '地址',           note: '選填', width: 22 },
      { key: 'pickup_location',   label: '上學接送地點',   note: '選填', width: 18 },
      { key: 'dropoff_1620',      label: '16:20放學地點',  note: '選填', width: 18 },
      { key: 'dropoff_1800',      label: '18:00放學地點',  note: '選填', width: 18 },
      { key: 'dismissal_session', label: '放學時段',       note: '選填', width: 12 },
      { key: 'active_days',       label: '搭車星期',       note: '選填', width: 12 },
      { key: 'parent_name',       label: '家長姓名',       note: '必填', width: 13 },
      { key: 'parent_phone',      label: '家長手機',       note: '必填', width: 18 },
    ];
    ws.columns = headers.map(h => ({ width: h.width }));
    ws.mergeCells(`A1:Q1`);
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
      cell.value = h.note ? `${h.label} (${h.note})` : h.label;
      cell.font = { name: 'Microsoft JhengHei', size: 10, color: { argb: 'FFFCD34D' } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1A1000' } };
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
    });
    row3.height = 28;
    const busTypeLabel: Record<string, string> = { minibus: '中巴', van: '廂型車' };
    const sessionLabel: Record<string, string> = { '1620': '16:20', '1800': '18:00', both: '兩段' };
    rows.forEach((r: any, idx: number) => {
      const displayRow = {
        ...r,
        bus_type: busTypeLabel[r.bus_type] || r.bus_type,
        dismissal_session: sessionLabel[r.dismissal_session] || r.dismissal_session || '',
        active_days: (r.active_days || '').replace(/1/g,'一').replace(/2/g,'二').replace(/3/g,'三').replace(/4/g,'四').replace(/5/g,'五'),
      };
      const row = ws.addRow(headers.map(h => displayRow[h.key] || ''));
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
  } catch (e: any) {
    res.status(500).json({ error: String(e) });
  }
});

// ══════════════════════════════════════════════════════
// 路線管理 API
// ══════════════════════════════════════════════════════
app.post('/api/admin/buses', auth(['admin']), async (req: AuthRequest, res) => {
  const { bus_name, route_name, driver_id, bus_type, capacity } = req.body;
  if (!bus_name || !route_name) return res.status(400).json({ error: '請提供 bus_name 和 route_name' });
  const typeDefault = bus_type || 'minibus';
  const capDefault = capacity ? Number(capacity) : (typeDefault === 'van' ? 8 : 20);
  try {
    const [r]: any = await pool.query(
      `INSERT INTO buses (bus_name, route_name, driver_id, bus_type, capacity) VALUES (?, ?, ?, ?, ?)`,
      [bus_name, route_name, driver_id || null, typeDefault, capDefault]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (e: any) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '車次名稱已存在' });
    res.status(500).json({ error: String(e) });
  }
});

app.delete('/api/admin/buses/:id', auth(['admin']), async (req: AuthRequest, res) => {
  const busId = Number(req.params.id);
  if (isNaN(busId)) return res.status(400).json({ error: '無效的校車 ID' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [stuList]: any = await conn.query(`SELECT id FROM students WHERE bus_id = ?`, [busId]);
    const stuIds = stuList.map((s: any) => s.id);
    if (stuIds.length > 0) {
      const sph = stuIds.map(() => '?').join(',');
      await conn.query(`DELETE FROM boarding_records WHERE student_id IN (${sph})`, stuIds);
      await conn.query(`DELETE FROM students WHERE id IN (${sph})`, stuIds);
    }
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
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════
// 歷史紀錄 API
// ══════════════════════════════════════════════════════
app.get('/api/admin/history/sessions', auth(['admin']), async (req, res) => {
  const { date, bus_id } = req.query;
  const targetDate = date || new Date().toISOString().slice(0, 10);
  try {
    let sql = `
      SELECT ds.id, ds.session_date, ds.start_time, ds.end_time,
             d.name as driver_name, d.account as driver_account,
             b.bus_name, b.route_name,
             (SELECT COUNT(*) FROM boarding_records br WHERE br.session_id = ds.id) as boarded_count,
             (SELECT COUNT(*) FROM students s WHERE s.bus_id = ds.bus_id AND s.is_active = 1) as total_students
      FROM driver_sessions ds
      JOIN drivers d ON ds.driver_id = d.id
      JOIN buses b ON ds.bus_id = b.id
      WHERE DATE(ds.session_date) = ?`;
    const params: any[] = [targetDate];
    if (bus_id) { sql += ` AND ds.bus_id = ?`; params.push(bus_id); }
    sql += ` ORDER BY ds.start_time DESC`;
    const [rows]: any = await pool.query(sql, params);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/history/boarding', auth(['admin']), async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: '請提供 session_id' });
  try {
    const [rows]: any = await pool.query(`
      SELECT s.name as student_name, s.school_class, s.pickup_location,
             s.dropoff_1620, s.dropoff_1800, s.dismissal_session,
             p.name as parent_name, p.phone as parent_phone, br.boarded_at
      FROM students s
      LEFT JOIN parents p ON s.parent_id = p.id
      LEFT JOIN boarding_records br ON br.student_id = s.id AND br.session_id = ?
      WHERE s.bus_id = (SELECT bus_id FROM driver_sessions WHERE id = ?)
        AND s.is_active = 1
      ORDER BY br.boarded_at ASC, s.school_class, s.name
    `, [session_id, session_id]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/history/student', auth(['admin']), async (req, res) => {
  const { student_name, days = 7 } = req.query;
  if (!student_name) return res.status(400).json({ error: '請提供 student_name' });
  try {
    const [rows]: any = await pool.query(`
      SELECT s.name as student_name, s.school_class, b.bus_name, b.route_name,
             ds.session_date, ds.start_time, br.boarded_at,
             CASE WHEN br.boarded_at IS NOT NULL THEN '已上車' ELSE '未上車' END as status
      FROM students s
      JOIN buses b ON s.bus_id = b.id
      JOIN driver_sessions ds ON ds.bus_id = b.id
        AND ds.session_date >= DATE_SUB(DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')), INTERVAL ? DAY)
      LEFT JOIN boarding_records br ON br.student_id = s.id AND br.session_id = ds.id
      WHERE s.name LIKE ? AND s.is_active = 1
      ORDER BY ds.session_date DESC, ds.start_time DESC
    `, [Number(days), `%${student_name}%`]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/api/admin/history/stats', auth(['admin']), async (req, res) => {
  const { days = 30 } = req.query;
  try {
    const [rows]: any = await pool.query(`
      SELECT b.id as bus_id, b.bus_name, b.route_name, b.bus_type, b.capacity,
             COUNT(DISTINCT ds.id) as total_sessions,
             COUNT(DISTINCT DATE(ds.session_date)) as active_days,
             COALESCE(SUM(br_count.cnt), 0) as total_boardings,
             COALESCE(AVG(br_count.cnt), 0) as avg_boardings,
             (SELECT COUNT(*) FROM students s WHERE s.bus_id = b.id AND s.is_active = 1) as enrolled_students
      FROM buses b
      LEFT JOIN driver_sessions ds ON ds.bus_id = b.id
        AND ds.session_date >= DATE_SUB(DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')), INTERVAL ? DAY)
        AND ds.end_time IS NOT NULL
      LEFT JOIN (
        SELECT session_id, COUNT(*) as cnt FROM boarding_records GROUP BY session_id
      ) br_count ON br_count.session_id = ds.id
      GROUP BY b.id, b.bus_name, b.route_name, b.bus_type, b.capacity
      ORDER BY b.route_name, b.bus_name
    `, [Number(days)]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});


// ══════════════════════════════════════════════════════
// 下車掃描 API
// ══════════════════════════════════════════════════════
app.post('/api/driver/scan-alight', auth(['driver']), async (req: AuthRequest, res) => {
  const driverId = req.user!.id;
  const { code } = req.body;
  try {
    const [sessions]: any = await pool.query(
      `SELECT ds.id, ds.bus_id FROM driver_sessions ds
       WHERE ds.driver_id = ? AND ds.session_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+08:00')) AND ds.end_time IS NULL LIMIT 1`,
      [driverId]
    );
    const session = sessions[0];
    if (!session) return res.status(400).json({ error: '請先上線' });

    const [students]: any = await pool.query(
      `SELECT s.id, s.name, s.school_class, s.bus_id,
              s.pickup_location, s.dropoff_1620, s.dropoff_1800, s.dismissal_session,
              s.dismissal_mon, s.dismissal_tue, s.dismissal_wed, s.dismissal_thu, s.dismissal_fri,
              p.name as parent_name, p.phone as parent_phone
       FROM students s LEFT JOIN parents p ON s.parent_id = p.id
       WHERE s.student_code = ? OR s.card_code = ? LIMIT 1`,
      [code, code]
    );
    const student = students[0];
    if (!student) return res.json({ status: 'not_found', message: '查無學生，請聯絡管理員' });
    if (student.bus_id !== session.bus_id)
      return res.json({ status: 'wrong_bus', message: `${student.name} 不是本車學生`, student });

    // 確認有上車記錄
    const [boarding]: any = await pool.query(
      `SELECT id FROM boarding_records WHERE student_id = ? AND session_id = ? LIMIT 1`,
      [student.id, session.id]
    );
    if (!boarding[0])
      return res.json({ status: 'not_boarded', message: `${student.name} 尚未上車記錄`, student });

    // 記錄下車
    await pool.query(
      `INSERT INTO alighting_records (student_id, session_id) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE alighted_at = NOW()`,
      [student.id, session.id]
    );

    // 取得今天放學地點
    const dayOfWeek = new Date().getDay();
    const dayKeys: Record<number, string> = { 1: 'dismissal_mon', 2: 'dismissal_tue', 3: 'dismissal_wed', 4: 'dismissal_thu', 5: 'dismissal_fri' };
    const todaySession = dayKeys[dayOfWeek] ? student[dayKeys[dayOfWeek]] : null;
    const dropoffLocation = todaySession === '1620' ? student.dropoff_1620 : student.dropoff_1800;

    res.json({
      status: 'ok',
      message: `${student.name} 下車成功`,
      student,
      dropoff_location: dropoffLocation,
      today_session: todaySession,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// 取得下車記錄（給家長和管理員）
app.get('/api/driver/students', auth(['driver']), async (req: AuthRequest, res) => {
  // 此路由已在上方定義，這裡補充下車資訊版本
  res.status(404).json({ error: 'use /api/driver/students' });
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
// 新學期自動匯入 API
// POST /api/admin/import-semester
// 支援 Google 表單 Excel 格式直接匯入
// 自動：建帳號、填資料、依停車點分配校車
// ══════════════════════════════════════════════════════
app.post('/api/admin/import-semester', auth(['admin']), async (req: AuthRequest, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0)
    return res.status(400).json({ error: '沒有資料' });

  let added = 0, updated = 0, failed = 0, nobus = 0;
  const errors: string[] = [];
  const unmatched: any[] = [];

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 取得所有校車（含站牌對應）
    const [buses]: any = await conn.query(
      `SELECT id, bus_name, route_name, bus_type, capacity,
              (SELECT COUNT(*) FROM students WHERE bus_id=buses.id AND is_active=1 AND school_direction='morning') as student_count
       FROM buses WHERE is_active=1`
    );

    // 取得所有停車點對應（bus_stops 表，若存在）
    let stopMap: Record<string, number> = {};
    try {
      const [stops]: any = await conn.query(
        `SELECT stop_name, bus_id FROM bus_stops`
      );
      stops.forEach((s: any) => {
        stopMap[s.stop_name.trim()] = s.bus_id;
      });
    } catch {
      // bus_stops 表不存在，跳過（之後再加）
    }

    for (const row of rows) {
      try {
        const {
          class_name, seat_no, student_name,
          parent_name, parent_phone, address,
          direction, pickup_location, dropoff_location,
          dismissal_mon, dismissal_tue, dismissal_wed,
          dismissal_thu, dismissal_fri
        } = row;

        if (!student_name || !parent_phone) {
          failed++;
          errors.push(`${student_name || '?'}: 缺少姓名或電話`);
          continue;
        }

        // 清理時段
        const cleanSession = (v: string) => {
          if (!v || v === '不搭') return '不搭';
          if (String(v).includes('1620')) return '1620';
          if (String(v).includes('1800')) return '1800';
          return '不搭';
        };
        const mon = cleanSession(dismissal_mon);
        const tue = cleanSession(dismissal_tue);
        const wed = cleanSession(dismissal_wed);
        const thu = cleanSession(dismissal_thu);
        const fri = cleanSession(dismissal_fri);

        // 搭車方向
        const dir = String(direction || '').trim();
        let schoolDir = 'both';
        if (dir === '上學') schoolDir = 'morning';
        else if (dir === '放學') schoolDir = 'afternoon';
        else schoolDir = 'both';

        // 整體放學時段
        const sessions = [mon, tue, wed, thu, fri].filter(s => s !== '不搭');
        let dismissalSession: string | null = null;
        if (sessions.length > 0) {
          if (sessions.every(s => s === '1620')) dismissalSession = '1620';
          else if (sessions.every(s => s === '1800')) dismissalSession = '1800';
          else dismissalSession = 'both';
        }

        // 搭車星期（從時段判斷）
        const dayMap: Record<string, string> = { mon: '1', tue: '2', wed: '3', thu: '4', fri: '5' };
        const activeDays = Object.entries({ mon, tue, wed, thu, fri })
          .filter(([, v]) => v !== '不搭')
          .map(([k]) => dayMap[k])
          .join('');

        // 嘗試依停車點找校車
        let busId: number | null = null;
        const pickupClean = String(pickup_location || '').trim();
        const dropoffClean = String(dropoff_location || '').trim();

        if (stopMap[pickupClean]) busId = stopMap[pickupClean];
        else if (stopMap[dropoffClean]) busId = stopMap[dropoffClean];

        // 若找不到停車點對應，記錄起來讓管理員確認
        if (!busId) {
          nobus++;
          unmatched.push({
            student_name,
            pickup_location: pickupClean,
            dropoff_location: dropoffClean,
            parent_phone,
          });
          // 仍然建立學生資料，但 bus_id 設為 null（需要後續手動指派）
        }

        // 建立或更新家長
        let parentId: number;
        const [existingParent]: any = await conn.query(
          `SELECT id FROM parents WHERE phone=? OR account=? LIMIT 1`,
          [parent_phone, parent_phone]
        );
        if (existingParent[0]) {
          parentId = existingParent[0].id;
          if (parent_name) {
            await conn.query(`UPDATE parents SET name=? WHERE id=?`, [parent_name, parentId]);
          }
        } else {
          const [pr]: any = await conn.query(
            `INSERT INTO parents (name, account, password, phone) VALUES (?, ?, ?, ?)`,
            [parent_name || parent_phone, parent_phone, parent_phone.slice(-4), parent_phone]
          );
          parentId = pr.insertId;
        }

        // 座位檢查（若有分配到校車）
        if (busId) {
          const bus = buses.find((b: any) => b.id === busId);
          if (bus && bus.student_count >= bus.capacity) {
            errors.push(`${student_name}: ${bus.bus_name} 已滿（${bus.capacity}人），請手動調整`);
            busId = null;
            nobus++;
          }
        }

        // 建立或更新學生
        const [existingStudent]: any = await conn.query(
          `SELECT id FROM students WHERE name=? AND parent_id=? LIMIT 1`,
          [student_name, parentId]
        );

        if (existingStudent[0]) {
          await conn.query(
            `UPDATE students SET
               school_class=?, address=?, pickup_location=?,
               dropoff_1620=?, dropoff_1800=?,
               school_direction=?, dismissal_session=?, active_days=?,
               dismissal_mon=?, dismissal_tue=?, dismissal_wed=?,
               dismissal_thu=?, dismissal_fri=?,
               bus_id=COALESCE(?,bus_id)
             WHERE id=?`,
            [
              class_name, address, pickupClean,
              dropoffClean, dropoffClean,
              schoolDir, dismissalSession, activeDays || '12345',
              mon, tue, wed, thu, fri,
              busId, existingStudent[0].id
            ]
          );
          updated++;
        } else {
          await conn.query(
            `INSERT INTO students
               (name, school_class, parent_id, bus_id, address,
                pickup_location, dropoff_1620, dropoff_1800,
                school_direction, dismissal_session, active_days,
                dismissal_mon, dismissal_tue, dismissal_wed, dismissal_thu, dismissal_fri,
                parent_phone)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
              student_name, class_name, parentId, busId, address,
              pickupClean, dropoffClean, dropoffClean,
              schoolDir, dismissalSession, activeDays || '12345',
              mon, tue, wed, thu, fri,
              parent_phone
            ]
          );
          added++;
        }

        // 更新 bus 的 student_count 計數（in-memory）
        if (busId) {
          const bus = buses.find((b: any) => b.id === busId);
          if (bus) bus.student_count++;
        }

      } catch (e: any) {
        failed++;
        errors.push(`${row.student_name || '?'}: ${e.message}`);
      }
    }

    await conn.commit();
    res.json({
      ok: true,
      added, updated, failed, nobus,
      errors,
      unmatched, // 需要手動指派校車的學生
      summary: `新增 ${added} 人，更新 ${updated} 人，失敗 ${failed} 人，待分配校車 ${nobus} 人`
    });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// ============================================================
// v4 階段 1 — 校車系統後端 API (專屬版,對齊 a20008079 的 server.ts)
// ============================================================
// 使用方式:把這整段貼到 worker-system-backend/src/server.ts 的最尾巴
// (跟你現有的 /api/admin/import-semester / /api/admin/bus-stops 那些一樣
//  放在 app.listen 之後)
//
// 對齊的點:
//   - 用 JWT auth(['admin']) 而不是 session
//   - admin id 從 req.user!.id 取(AuthRequest 型別)
//   - admins 表的姓名欄位是 `name`(不是 username)
//   - 用 pool / pool.getConnection() (mysql2/promise)
//
// 重要約定(讀過再改 SQL!):
//   students 表的 dismissal_mon ~ dismissal_fri 是 enum('1620','1800','不搭')
//   v4 約定:
//     - NULL                = 該天不搭(顯示「不搭」)
//     - '1620' / '1800'     = 放學該天搭哪一班
//     - 上學 (morning) row  = 該天有搭時也存 '1620' 當「有搭」佔位值
//                            (上學表 SELECT 把它顯示成空字串,不顯示班次)
//   所以同一個學生通常會有兩個 students row,一筆 morning、一筆 afternoon,
//   兩筆的 dismissal_* 互相獨立。
//
// 加的 endpoint:
//   GET   /api/admin/bus/morning              取上學表 (預期 348 row)
//   GET   /api/admin/bus/afternoon            取放學表 (預期 705 row)
//   GET   /api/admin/bus/buses                取所有路線(編輯下拉用)
//   PUT   /api/admin/bus/student/:id          更新單一學生 + 寫 audit log
//   PUT   /api/admin/bus/bus/:id              更新路線屬性
//   GET   /api/admin/bus/audit                取修改紀錄
// ============================================================


// ============================================================
// 1. GET /api/admin/bus/morning
// ============================================================
app.get('/api/admin/bus/morning', auth(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ROW_NUMBER() OVER (PARTITION BY s.bus_id ORDER BY s.id) AS '序號',
        s.school_class                                          AS '年級',
        s.name                                                  AS '姓名',
        s.parent_phone                                          AS '電話',
        s.pickup_location                                       AS '接送位置',
        b.pickup_time                                           AS '上車時間',
        CASE WHEN s.dismissal_mon = '不搭' THEN '不搭' ELSE '' END AS '星期一',
        CASE WHEN s.dismissal_tue = '不搭' THEN '不搭' ELSE '' END AS '星期二',
        CASE WHEN s.dismissal_wed = '不搭' THEN '不搭' ELSE '' END AS '星期三',
        CASE WHEN s.dismissal_thu = '不搭' THEN '不搭' ELSE '' END AS '星期四',
        CASE WHEN s.dismissal_fri = '不搭' THEN '不搭' ELSE '' END AS '星期五',
        b.bus_name                                              AS '路線',
        b.company                                               AS '交通公司',
        b.driver_phone                                          AS '司機/電話',
        b.plate_number                                          AS '車號',
        b.account_id                                            AS '帳號',
        b.account_pass                                          AS '密碼',
        s.id                                                    AS '_student_id',
        s.bus_id                                                AS '_bus_id'
      FROM students s
      LEFT JOIN buses b ON s.bus_id = b.id
      WHERE s.school_direction = 'morning' AND s.is_active = 1
      ORDER BY s.bus_id, s.id
    `);
    res.json({ rows });
  } catch (err) {
    console.error('GET /api/admin/bus/morning error:', err);
    res.status(500).json({ error: String(err) });
  }
});


// ============================================================
// 2. GET /api/admin/bus/afternoon
// ============================================================
app.get('/api/admin/bus/afternoon', auth(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ROW_NUMBER() OVER (PARTITION BY s.bus_id ORDER BY s.id) AS '序號',
        s.school_class                                          AS '年級',
        s.name                                                  AS '姓名',
        s.parent_phone                                          AS '電話',
        s.pickup_location                                       AS '接送位置',
        s.dropoff_1620                                          AS '1620到站時間',
        s.dropoff_1800                                          AS '1800到站時間',
        CASE WHEN s.dismissal_mon IS NULL THEN '不搭' ELSE s.dismissal_mon END AS '星期一',
        CASE WHEN s.dismissal_tue IS NULL THEN '不搭' ELSE s.dismissal_tue END AS '星期二',
        CASE WHEN s.dismissal_wed IS NULL THEN '不搭' ELSE s.dismissal_wed END AS '星期三',
        CASE WHEN s.dismissal_thu IS NULL THEN '不搭' ELSE s.dismissal_thu END AS '星期四',
        CASE WHEN s.dismissal_fri IS NULL THEN '不搭' ELSE s.dismissal_fri END AS '星期五',
        b.bus_name                                              AS '路線',
        b.company                                               AS '交通公司',
        b.driver_phone                                          AS '司機/電話',
        b.plate_number                                          AS '車號',
        b.account_id                                            AS '帳號',
        b.account_pass                                          AS '密碼',
        s.id                                                    AS '_student_id',
        s.bus_id                                                AS '_bus_id'
      FROM students s
      LEFT JOIN buses b ON s.bus_id = b.id
      WHERE s.school_direction = 'afternoon' AND s.is_active = 1
      ORDER BY s.bus_id, s.id
    `);
    res.json({ rows });
  } catch (err) {
    console.error('GET /api/admin/bus/afternoon error:', err);
    res.status(500).json({ error: String(err) });
  }
});


// ============================================================
// 3. GET /api/admin/bus/buses — 給「改路線」下拉用
// ============================================================
app.get('/api/admin/bus/buses', auth(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, bus_name, pickup_time, company, driver_phone, plate_number,
             account_id, account_pass, skip_1620, van_only
      FROM buses
      WHERE is_active = 1
      ORDER BY bus_name
    `);
    res.json({ rows });
  } catch (err) {
    console.error('GET /api/admin/bus/buses error:', err);
    res.status(500).json({ error: String(err) });
  }
});


// ============================================================
// 4. PUT /api/admin/bus/student/:id — 更新單一學生 + 寫 audit log
// ============================================================
app.put('/api/admin/bus/student/:id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const studentId = parseInt(req.params.id, 10);
  if (isNaN(studentId)) {
    return res.status(400).json({ error: 'invalid student id' });
  }
  const adminId = req.user!.id;

  const payload = req.body || {};

  // 允許更新的欄位白名單(防前端塞奇怪欄位)
  const allowedFields = new Set([
    'parent_phone', 'pickup_location', 'bus_id',
    'dropoff_1620', 'dropoff_1800',
    'dismissal_mon', 'dismissal_tue', 'dismissal_wed',
    'dismissal_thu', 'dismissal_fri',
  ]);

  const setClauses: string[] = [];
  const setValues: any[] = [];
  for (const [k, v] of Object.entries(payload)) {
    if (!allowedFields.has(k)) continue;
    setClauses.push(`\`${k}\` = ?`);
    setValues.push(v);  // null 會正確寫進 DB 變 NULL
  }

  if (setClauses.length === 0) {
    return res.status(400).json({ error: 'nothing to update' });
  }

  // 開 transaction:同時 UPDATE 學生 + INSERT audit log
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    setValues.push(studentId);
    const sql = `UPDATE students SET ${setClauses.join(', ')} WHERE id = ?`;
    const [result]: any = await conn.query(sql, setValues);

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'student not found' });
    }

    await conn.query(
      'INSERT INTO bus_audit_logs (student_id, admin_id, action) VALUES (?, ?, ?)',
      [studentId, adminId, 'update']
    );

    await conn.commit();
    res.json({ ok: true, student_id: studentId });
  } catch (err) {
    await conn.rollback();
    console.error('PUT /api/admin/bus/student error:', err);
    res.status(500).json({ error: String(err) });
  } finally {
    conn.release();
  }
});


// ============================================================
// 5. PUT /api/admin/bus/bus/:id — 更新路線屬性
// ============================================================
app.put('/api/admin/bus/bus/:id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const busId = parseInt(req.params.id, 10);
  if (isNaN(busId)) return res.status(400).json({ error: 'invalid bus id' });

  const allowedFields = new Set([
    'pickup_time', 'company', 'driver_phone', 'plate_number',
    'account_id', 'account_pass',
    'skip_1620', 'van_only',
  ]);
  const setClauses: string[] = [];
  const setValues: any[] = [];
  for (const [k, v] of Object.entries(req.body || {})) {
    if (!allowedFields.has(k)) continue;
    setClauses.push(`\`${k}\` = ?`);
    setValues.push(v);
  }
  if (setClauses.length === 0) return res.status(400).json({ error: 'nothing to update' });

  setValues.push(busId);
  try {
    const [result]: any = await pool.query(
      `UPDATE buses SET ${setClauses.join(', ')} WHERE id = ?`,
      setValues
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'bus not found' });
    res.json({ ok: true, bus_id: busId });
  } catch (err) {
    console.error('PUT /api/admin/bus/bus error:', err);
    res.status(500).json({ error: String(err) });
  }
});


// ============================================================
// 6. GET /api/admin/bus/audit — 取修改紀錄(最近 N 筆)
// ============================================================
app.get('/api/admin/bus/audit', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string, 10) || 100, 500);
  try {
    const [rows] = await pool.query(`
      SELECT
        l.id, l.action, l.changed_at,
        l.student_id, s.name AS student_name, s.school_class,
        l.admin_id, a.name AS admin_name
      FROM bus_audit_logs l
      LEFT JOIN students s ON s.id = l.student_id
      LEFT JOIN admins   a ON a.id = l.admin_id
      ORDER BY l.changed_at DESC
      LIMIT ?
    `, [limit]);
    res.json({ rows });
  } catch (err) {
    console.error('GET /api/admin/bus/audit error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// END of v4 階段 1 patch
// ============================================================


// ============================================================
// 系統設定 (車隊參數) — 階段 3a
// ============================================================

const ALLOWED_CONFIG_KEYS = new Set([
  'FLEET_BIG_BUS',
  'FLEET_VAN',
  'BIG_BUS_CAP_MORNING',
  'BIG_BUS_CAP_AFTERNOON',
  'VAN_CAP',
  'BIG_BUS_THRESHOLD',
]);

// GET /api/admin/config — 取所有設定
app.get('/api/admin/config', auth(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const [rows] = await pool.query(`
      SELECT config_key, config_value, description, updated_at, updated_by
      FROM system_config
      ORDER BY config_key
    `);
    res.json({ configs: rows });
  } catch (err) {
    console.error('GET /api/admin/config error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// PUT /api/admin/config — 更新一筆或多筆設定
// body: { configs: [{ key, value }, ...] }
app.put('/api/admin/config', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { configs } = req.body || {};
  if (!Array.isArray(configs) || configs.length === 0) {
    return res.status(400).json({ error: 'configs must be a non-empty array' });
  }
  // 驗證所有 key 都在白名單,且 value 是非負整數
  for (const c of configs) {
    if (!ALLOWED_CONFIG_KEYS.has(c.key)) {
      return res.status(400).json({ error: `invalid config key: ${c.key}` });
    }
    const n = Number(c.value);
    if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
      return res.status(400).json({
        error: `invalid value for ${c.key}: must be a non-negative integer`,
      });
    }
  }

  const updatedBy = String(req.user?.id ?? 'admin');

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const c of configs) {
      await conn.query(
        `INSERT INTO system_config (config_key, config_value, updated_by)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           config_value = VALUES(config_value),
           updated_by = VALUES(updated_by)`,
        [c.key, String(c.value), updatedBy]
      );
    }
    await conn.commit();

    const [rows] = await conn.query(`
      SELECT config_key, config_value, description, updated_at, updated_by
      FROM system_config
      ORDER BY config_key
    `);
    res.json({ configs: rows, updated: configs.length });
  } catch (err) {
    await conn.rollback();
    console.error('PUT /api/admin/config error:', err);
    res.status(500).json({ error: String(err) });
  } finally {
    conn.release();
  }
});

// ============================================================
// 階段 3b Step 1 — 站牌管理 API (給地圖功能用)
// ============================================================
// 新 bus_stops 表 schema:
//   id, bus_id, stop_name, stop_order, latitude, longitude, address, pickup_time
// 跟舊版完全不同 (舊版只有 id/stop_name/bus_id),migration 009 已重建

interface BusStopRow {
  id: number;
  bus_id: number;
  stop_name: string;
  stop_order: number | null;
  latitude: number | null;
  longitude: number | null;
  address: string | null;
  pickup_time: string | null;
}

// 工具:從學生 pickup_location 抓某路線的獨特站牌 (給「一鍵匯入」用)
async function suggestStopsFromStudents(busId: number): Promise<string[]> {
  const [rows]: any = await pool.query(
    `SELECT DISTINCT TRIM(pickup_location) AS loc
     FROM students
     WHERE bus_id = ? AND is_active = 1 AND pickup_location IS NOT NULL AND pickup_location != ''
     ORDER BY loc`,
    [busId]
  );
  return rows.map((r: any) => r.loc).filter((s: string) => s && s.length > 0);
}

// ============================================================
// GET /api/admin/buses/:bus_id/stops — 列某路線的所有站牌
// ============================================================
app.get('/api/admin/buses/:bus_id/stops', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const busId = Number(req.params.bus_id);
  if (!Number.isInteger(busId) || busId <= 0) {
    return res.status(400).json({ error: 'invalid bus_id' });
  }
  try {
    const [rows]: any = await pool.query(
      `SELECT id, bus_id, stop_name, stop_order, latitude, longitude, address, pickup_time
       FROM bus_stops
       WHERE bus_id = ?
       ORDER BY stop_order IS NULL, stop_order, id`,
      [busId]
    );
    res.json({ stops: rows });
  } catch (err) {
    console.error('GET stops error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// POST /api/admin/buses/:bus_id/stops — 新增單一站牌
// body: { stop_name, latitude?, longitude?, address?, pickup_time?, stop_order? }
// ============================================================
app.post('/api/admin/buses/:bus_id/stops', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const busId = Number(req.params.bus_id);
  const { stop_name, latitude, longitude, address, pickup_time, stop_order } = req.body || {};
  if (!Number.isInteger(busId) || busId <= 0) {
    return res.status(400).json({ error: 'invalid bus_id' });
  }
  if (!stop_name || typeof stop_name !== 'string' || stop_name.trim() === '') {
    return res.status(400).json({ error: 'stop_name is required' });
  }
  try {
    // 取現有最大 stop_order + 1 當預設
    const [maxRows]: any = await pool.query(
      'SELECT COALESCE(MAX(stop_order), 0) AS max_order FROM bus_stops WHERE bus_id = ?',
      [busId]
    );
    const defaultOrder = (maxRows[0]?.max_order || 0) + 1;

    const [r]: any = await pool.query(
      `INSERT INTO bus_stops (bus_id, stop_name, stop_order, latitude, longitude, address, pickup_time)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        busId,
        stop_name.trim(),
        stop_order ?? defaultOrder,
        latitude ?? null,
        longitude ?? null,
        address ?? null,
        pickup_time ?? null,
      ]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (err) {
    console.error('POST stop error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// POST /api/admin/buses/:bus_id/stops/import-from-students
// 從該路線學生的 pickup_location 抓獨特站牌,批次加入 (座標留空)
// body: {} (不需要參數)
// ============================================================
app.post('/api/admin/buses/:bus_id/stops/import-from-students', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const busId = Number(req.params.bus_id);
  if (!Number.isInteger(busId) || busId <= 0) {
    return res.status(400).json({ error: 'invalid bus_id' });
  }
  try {
    const suggested = await suggestStopsFromStudents(busId);
    if (suggested.length === 0) {
      return res.json({ imported: 0, skipped: 0, message: '該路線沒有學生 pickup_location 資料' });
    }

    // 取目前已有的站牌名 (避免重複)
    const [existRows]: any = await pool.query(
      'SELECT stop_name FROM bus_stops WHERE bus_id = ?',
      [busId]
    );
    const existing = new Set(existRows.map((r: any) => r.stop_name.trim()));

    const toInsert = suggested.filter((s) => !existing.has(s));
    if (toInsert.length === 0) {
      return res.json({ imported: 0, skipped: suggested.length, message: '所有站牌都已存在' });
    }

    // 取目前最大 order
    const [maxRows]: any = await pool.query(
      'SELECT COALESCE(MAX(stop_order), 0) AS max_order FROM bus_stops WHERE bus_id = ?',
      [busId]
    );
    let order = (maxRows[0]?.max_order || 0) + 1;

    // 批次 insert
    for (const name of toInsert) {
      await pool.query(
        `INSERT INTO bus_stops (bus_id, stop_name, stop_order) VALUES (?, ?, ?)`,
        [busId, name, order]
      );
      order += 1;
    }

    res.json({
      imported: toInsert.length,
      skipped:  suggested.length - toInsert.length,
      message:  `從學生資料匯入 ${toInsert.length} 個站牌${suggested.length - toInsert.length > 0 ? ` (跳過 ${suggested.length - toInsert.length} 個已存在)` : ''}`,
    });
  } catch (err) {
    console.error('import-from-students error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// PUT /api/admin/stops/:id — 更新站牌
// body: 任意 subset of { stop_name, stop_order, latitude, longitude, address, pickup_time }
// ============================================================
app.put('/api/admin/stops/:id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const stopId = Number(req.params.id);
  if (!Number.isInteger(stopId) || stopId <= 0) {
    return res.status(400).json({ error: 'invalid stop id' });
  }
  const allowedFields = new Set([
    'stop_name', 'stop_order', 'latitude', 'longitude', 'address', 'pickup_time',
  ]);
  const updates: string[] = [];
  const values: any[] = [];
  for (const [k, v] of Object.entries(req.body || {})) {
    if (!allowedFields.has(k)) continue;
    updates.push(`${k} = ?`);
    values.push(v === '' ? null : v);
  }
  if (updates.length === 0) {
    return res.status(400).json({ error: 'no valid fields to update' });
  }
  values.push(stopId);
  try {
    const [r]: any = await pool.query(
      `UPDATE bus_stops SET ${updates.join(', ')} WHERE id = ?`,
      values
    );
    if (r.affectedRows === 0) {
      return res.status(404).json({ error: 'stop not found' });
    }
    const [rows]: any = await pool.query(
      'SELECT id, bus_id, stop_name, stop_order, latitude, longitude, address, pickup_time FROM bus_stops WHERE id = ?',
      [stopId]
    );
    res.json({ stop: rows[0] });
  } catch (err) {
    console.error('PUT stop error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// DELETE /api/admin/stops/:id — 刪站牌
// ============================================================
app.delete('/api/admin/stops/:id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const stopId = Number(req.params.id);
  if (!Number.isInteger(stopId) || stopId <= 0) {
    return res.status(400).json({ error: 'invalid stop id' });
  }
  try {
    const [r]: any = await pool.query('DELETE FROM bus_stops WHERE id = ?', [stopId]);
    if (r.affectedRows === 0) {
      return res.status(404).json({ error: 'stop not found' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE stop error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// PUT /api/admin/buses/:bus_id/stops/reorder — 批次重排順序
// body: { order: [id1, id2, id3, ...] }
// 把這些 id 依照陣列順序設成 stop_order = 1, 2, 3...
// ============================================================
app.put('/api/admin/buses/:bus_id/stops/reorder', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const busId = Number(req.params.bus_id);
  const { order } = req.body || {};
  if (!Number.isInteger(busId) || busId <= 0) {
    return res.status(400).json({ error: 'invalid bus_id' });
  }
  if (!Array.isArray(order) || order.length === 0) {
    return res.status(400).json({ error: 'order must be a non-empty array of stop ids' });
  }
  for (const id of order) {
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: `invalid stop id in order: ${id}` });
    }
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // 確認這些 id 都屬於這條 bus
    const placeholders = order.map(() => '?').join(',');
    const [rows]: any = await conn.query(
      `SELECT id FROM bus_stops WHERE id IN (${placeholders}) AND bus_id = ?`,
      [...order, busId]
    );
    if (rows.length !== order.length) {
      await conn.rollback();
      return res.status(400).json({ error: 'some stop ids do not belong to this bus' });
    }
    // 更新 order
    for (let i = 0; i < order.length; i++) {
      await conn.query('UPDATE bus_stops SET stop_order = ? WHERE id = ?', [i + 1, order[i]]);
    }
    await conn.commit();
    res.json({ ok: true, reordered: order.length });
  } catch (err) {
    await conn.rollback();
    console.error('reorder error:', err);
    res.status(500).json({ error: String(err) });
  } finally {
    conn.release();
  }
});


// ============================================================
// 階段 3b Step 2 — 家長端站牌 API
// ============================================================
// GET /api/parent/buses/:bus_id/stops
// 家長可以看自己孩子那條車的站牌(限 admin/parent 都可呼叫,parent 要驗證權限)

app.get('/api/parent/buses/:bus_id/stops', auth(['admin', 'parent']), async (req: AuthRequest, res: Response) => {
  const busId = Number(req.params.bus_id);
  if (!Number.isInteger(busId) || busId <= 0) {
    return res.status(400).json({ error: 'invalid bus_id' });
  }

  // 若是 parent,驗證該 bus 是該 parent 的孩子的車
  if (req.user?.role === 'parent') {
    try {
      const [check]: any = await pool.query(
        `SELECT s.id FROM students s WHERE s.parent_id = ? AND s.bus_id = ? AND s.is_active = 1 LIMIT 1`,
        [req.user.id, busId]
      );
      if (!check[0]) {
        return res.status(403).json({ error: '無權限查看此校車站牌' });
      }
    } catch (err) {
      console.error('parent stops auth check error:', err);
      return res.status(500).json({ error: String(err) });
    }
  }

  // 取站牌 (只回有座標的)
  try {
    const [rows]: any = await pool.query(
      `SELECT id, bus_id, stop_name, stop_order, latitude, longitude, address, pickup_time
       FROM bus_stops
       WHERE bus_id = ? AND latitude IS NOT NULL AND longitude IS NOT NULL
       ORDER BY stop_order IS NULL, stop_order, id`,
      [busId]
    );
    res.json({ stops: rows });
  } catch (err) {
    console.error('GET parent stops error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// ============================================================
// 階段 3c Step 3c-1 : Google 表單匯入 (staging)
// 加在檔案尾巴 (跟 v4 / 3a / 3b patch 一樣的位置)
// 解析在前端做 (SheetJS),這裡只收 JSON rows 寫進 staging
// ============================================================

// 產生 batch_id: 20260524_143022 (台北時間)
function makeBatchId(): string {
  const d = new Date(Date.now() + 8 * 3600 * 1000); // UTC -> +08:00
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}_` +
         `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

// 上傳: 前端解析好的 rows (479 筆) 寫進 staging 表
app.post('/api/admin/student-import/upload', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: '沒有資料' });
  }

  const batchId = makeBatchId();

  // ── 先掃一遍算 班+座 重複 (dup_seat 旗標需要全批比對) ──
  const seatCount: Record<string, number> = {};
  for (const r of rows) {
    const key = `${(r.class_name || '').trim()}#${(r.seat_no || '').trim()}`;
    if ((r.class_name || '').trim() && (r.seat_no || '').trim()) {
      seatCount[key] = (seatCount[key] || 0) + 1;
    }
  }

  // ── 逐筆算品質旗標 ──
  // 真實資料確認 (479 筆): 放學值只有 1800/1620/不搭;上學站常空白(只搭放學的人)
  // 「無」代表家長明確表示不搭該段,視同已填,不算 empty_stop
  function qualityFlags(r: any): string {
    const flags: string[] = [];
    const addr = (r.home_address || '').trim();
    if (addr.length > 0 && addr.length < 10) flags.push('short_addr');     // 地址過短 (14筆)
    if ((r.parent_phone || '').includes('/')) flags.push('phone_slash');    // 電話含 / (2筆)

    const isBlank = (v: any) => {
      const s = (v ?? '').toString().trim();
      return s === '';   // 注意:'無' 不算 blank
    };
    const period = r.ride_period || '';
    const needPickup = period.includes('上學');
    const needDropoff = period.includes('放學');
    if ((needPickup && isBlank(r.pickup_stop)) ||
        (needDropoff && isBlank(r.dropoff_stop))) {
      flags.push('empty_stop');                                            // 正確算出 2 筆
    }

    const key = `${(r.class_name || '').trim()}#${(r.seat_no || '').trim()}`;
    if (seatCount[key] > 1) flags.push('dup_seat');                         // 班+座重複 (13組)
    return flags.join(',');
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    let inserted = 0;
    const flagSummary: Record<string, number> = {
      short_addr: 0, phone_slash: 0, empty_stop: 0, dup_seat: 0,
    };

    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      const flags = qualityFlags(r);
      flags.split(',').filter(Boolean).forEach((f) => {
        if (flagSummary[f] !== undefined) flagSummary[f]++;
      });

      await conn.query(
        `INSERT INTO student_import_staging
          (batch_id, row_num, timestamp_raw, class_name, seat_no, student_name,
           parent_name, parent_phone, home_address, ride_period, pickup_stop,
           dropoff_stop, mon_time, tue_time, wed_time, thu_time, fri_time, note,
           quality_flags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          batchId,
          r.row_num || (i + 2),
          r.timestamp_raw || null,
          (r.class_name || '').trim() || null,
          (r.seat_no || '').toString().trim() || null,
          (r.student_name || '').trim() || null,
          (r.parent_name || '').trim() || null,
          (r.parent_phone || '').toString().trim() || null,
          (r.home_address || '').trim() || null,
          (r.ride_period || '').trim() || null,
          (r.pickup_stop || '').trim() || null,
          (r.dropoff_stop || '').trim() || null,
          (r.mon_time || '').toString().trim() || null,
          (r.tue_time || '').toString().trim() || null,
          (r.wed_time || '').toString().trim() || null,
          (r.thu_time || '').toString().trim() || null,
          (r.fri_time || '').toString().trim() || null,
          (r.note || '').trim() || null,
          flags || null,
        ]
      );
      inserted++;
    }

    await conn.commit();
    res.json({
      ok: true,
      batch_id: batchId,
      total: inserted,
      quality: flagSummary,
    });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: String(e) });
  } finally {
    conn.release();
  }
});

// 列出所有批次
app.get('/api/admin/student-import/batches', auth(['admin']), async (_req: AuthRequest, res: Response) => {
  try {
    const [rows]: any = await pool.query(
      `SELECT batch_id,
              COUNT(*) AS total,
              SUM(applied) AS applied_count,
              MIN(created_at) AS created_at
       FROM student_import_staging
       GROUP BY batch_id
       ORDER BY created_at DESC`
    );
    res.json({ batches: rows });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// 讀某批次明細 (預覽用)
app.get('/api/admin/student-import/:batch_id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { batch_id } = req.params;
  try {
    const [rows]: any = await pool.query(
      `SELECT id, row_num, timestamp_raw, class_name, seat_no, student_name,
              parent_name, parent_phone, home_address, ride_period, pickup_stop,
              dropoff_stop, mon_time, tue_time, wed_time, thu_time, fri_time, note,
              quality_flags, match_status, matched_student_id,
              geo_lat, geo_lng, recommended_bus_id, recommended_stop_id, applied
       FROM student_import_staging
       WHERE batch_id = ?
       ORDER BY row_num`,
      [batch_id]
    );

    const quality = { short_addr: 0, phone_slash: 0, empty_stop: 0, dup_seat: 0 };
    for (const r of rows) {
      (r.quality_flags || '').split(',').filter(Boolean).forEach((f: string) => {
        if ((quality as any)[f] !== undefined) (quality as any)[f]++;
      });
    }

    res.json({ batch_id, total: rows.length, quality, rows });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// 刪某批次 (上傳到一半失敗想重來時用;不是清空整張表)
app.delete('/api/admin/student-import/:batch_id', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { batch_id } = req.params;
  try {
    const [r]: any = await pool.query(
      `DELETE FROM student_import_staging WHERE batch_id = ?`,
      [batch_id]
    );
    res.json({ ok: true, deleted: r.affectedRows });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});


// ============================================================
// 階段 3c Step 3c-2 : Geocoding (Nominatim 批次查經緯度)
// ============================================================
// 設計:可中斷續傳。前端反覆呼叫 geocode-step,每次查一小批 (10筆)。
// 規範:Nominatim 限速 1 req/s,必須帶自訂 User-Agent。
//   - 每筆間隔 1.1 秒
//   - 只查 geo_lat IS NULL 的 (跳過已查的 -> 可續傳)
//   - 地址過短 (<10字) 直接標 failed,不浪費 API 額度
//   - 桃園地區:地址沒含「市/縣」時自動補「桃園市」提高命中率

const NOMINATIM_UA = 'worker-system-school-bus/1.0 (contact: admin@school-bus)';

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }

// 單筆地址查座標
// 嘗試多個地址變體 (從詳細到粗略),OSM 台灣資料巷弄級覆蓋差,逐級降級提升命中率
function buildAddressFallbacks(rawAddr: string): string[] {
  let a = (rawAddr || '').trim();
  if (!a) return [];
  // 桃園地區:沒含 市/縣 就補「桃園市」
  if (!/[市縣]/.test(a)) a = '桃園市' + a;

  const variants: string[] = [a];

  // 1. 拿掉樓層 (X樓 / X樓之X / X樓之一)
  let v1 = a.replace(/\d+樓(之[一二三四五六七八九十\d]+)?/g, '').trim();
  if (v1 !== a && v1) variants.push(v1);

  // 2. 拿掉門牌號碼 (XXX號)
  let v2 = v1.replace(/\d+號(之[一二三四五六七八九十\d]+)?/g, '').replace(/[、,]\s*$/, '').trim();
  if (v2 && !variants.includes(v2)) variants.push(v2);

  // 3. 拿掉巷弄 (X巷 / X弄)
  let v3 = v2.replace(/\d+巷/g, '').replace(/\d+弄/g, '').trim();
  if (v3 && !variants.includes(v3)) variants.push(v3);

  // 4. 拿掉里鄰 (X里 X鄰)
  let v4 = v3.replace(/[\u4e00-\u9fa5]+里/g, '').replace(/\d+鄰/g, '').trim();
  if (v4 && !variants.includes(v4)) variants.push(v4);

  // 5. 只留到「區/鄉/鎮」
  const m = a.match(/^(桃園市[\u4e00-\u9fa5]+[區鄉鎮市])/);
  if (m && !variants.includes(m[1])) variants.push(m[1]);

  return variants.filter(s => s.length >= 4); // 過短的不送
}

// ── 兜底座標策略 ──
// 學校:有得雙語中小學,桃園市中壢區內壢長春一路 288 號
// 規則:
//   1. 地址寫出區的 (八德/平鎮/大溪/桃園/蘆竹/龜山/大園) -> 用該區中心座標
//   2. 地址沒寫區、太短、亂寫 -> 用「學校位置」當預設
const SCHOOL_LAT = 24.9627;     // 有得雙語中小學
const SCHOOL_LNG = 121.2435;

// 桃園各區中心座標 (查不到具體位置時依寫出的區兜底)
const DISTRICT_CENTERS: Record<string, { lat: number; lng: number }> = {
  '中壢區': { lat: SCHOOL_LAT, lng: SCHOOL_LNG }, // 學校所在,直接用學校座標
  '桃園區': { lat: 24.9937, lng: 121.3010 },
  '八德區': { lat: 24.9290, lng: 121.2843 },
  '平鎮區': { lat: 24.9438, lng: 121.2156 },
  '大溪區': { lat: 24.8807, lng: 121.2870 },
  '蘆竹區': { lat: 25.0451, lng: 121.2870 },
  '龜山區': { lat: 25.0367, lng: 121.3460 },
  '大園區': { lat: 25.0668, lng: 121.1957 },
  '楊梅區': { lat: 24.9080, lng: 121.1455 },
  '龍潭區': { lat: 24.8636, lng: 121.2161 },
  '新屋區': { lat: 24.9706, lng: 121.1062 },
  '觀音區': { lat: 25.0335, lng: 121.0810 },
  '復興區': { lat: 24.8203, lng: 121.3530 },
};

// 從地址抓出區名,沒寫就回 null (代表用學校預設)
function detectDistrict(addr: string): string | null {
  const m = addr.match(/([\u4e00-\u9fa5]{2,3}區)/);
  if (m && DISTRICT_CENTERS[m[1]]) return m[1];
  return null;
}

// 根據地址決定兜底座標
function getFallback(rawAddr: string): { lat: number; lng: number; matched: string } {
  const district = detectDistrict(rawAddr || '');
  if (district) {
    const c = DISTRICT_CENTERS[district];
    return { lat: c.lat, lng: c.lng, matched: `${district} (區中心兜底)` };
  }
  return { lat: SCHOOL_LAT, lng: SCHOOL_LNG, matched: '學校位置 (預設兜底)' };
}

// 單筆地址查座標 (逐級降級重試)
// 注意:結束前永遠 sleep 1.1 秒,保證下一次呼叫 geocodeOne 與本次的最後一次 API 間隔 ≥1.1s
async function geocodeOne(rawAddr: string): Promise<{ lat: number; lng: number; matched: string } | null> {
  const variants = buildAddressFallbacks(rawAddr);
  if (variants.length === 0) {
    await sleep(1100);
    // 空地址也兜底 (用學校位置,因為連區都沒寫)
    return getFallback(rawAddr);
  }

  let result: { lat: number; lng: number; matched: string } | null = null;
  for (let i = 0; i < variants.length; i++) {
    const addr = variants[i];
    const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(addr)}&format=json&limit=1&countrycodes=tw`;
    try {
      const resp = await fetch(url, {
        headers: { 'User-Agent': NOMINATIM_UA, 'Accept-Language': 'zh-TW' },
      });
      if (!resp.ok) {
        console.log(`[geocode] HTTP ${resp.status} for: ${addr}`);
      } else {
        const data: any = await resp.json();
        if (Array.isArray(data) && data.length > 0 && data[0].lat && data[0].lon) {
          if (i > 0) console.log(`[geocode] fallback hit (level ${i}): "${rawAddr}" -> "${addr}"`);
          result = { lat: Number(data[0].lat), lng: Number(data[0].lon), matched: addr };
          break;
        }
      }
    } catch (e: any) {
      console.log(`[geocode] error for "${addr}":`, e?.message || String(e));
    }
    // 每次 API 呼叫之後都 sleep,保證 1 req/s
    await sleep(1100);
  }

  if (!result) {
    // 全部 fallback 都失敗 -> 依「地址寫的區」兜底,沒寫區才用學校位置
    result = getFallback(rawAddr);
    console.log(`[geocode] using ${result.matched} for: ${rawAddr}`);
  }
  return result;
}

// POST /api/admin/student-import/:batch_id/geocode-step
// 每次查一小批 (預設 10),回傳進度。前端反覆呼叫直到 remaining=0
app.post('/api/admin/student-import/:batch_id/geocode-step', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { batch_id } = req.params;
  const stepSize = Math.min(Number(req.body?.step_size) || 10, 20);

  try {
    // 先把地址過短的直接給學校座標兜底 (沒地址無法判斷區,統一指向學校)
    await pool.query(
      `UPDATE student_import_staging
       SET geo_lat = ?, geo_lng = ?
       WHERE batch_id = ? AND geo_lat IS NULL AND match_status != 'failed'
         AND (home_address IS NULL OR CHAR_LENGTH(TRIM(home_address)) < 10)`,
      [SCHOOL_LAT, SCHOOL_LNG, batch_id]
    );

    // 取這批還沒查座標、地址夠長的 (一次 stepSize 筆)
    const [rows]: any = await pool.query(
      `SELECT id, home_address FROM student_import_staging
       WHERE batch_id = ? AND geo_lat IS NULL AND match_status != 'failed'
         AND home_address IS NOT NULL AND CHAR_LENGTH(TRIM(home_address)) >= 10
       ORDER BY id
       LIMIT ?`,
      [batch_id, stepSize]
    );

    let ok = 0, fail = 0;
    for (const r of rows) {
      const result = await geocodeOne(r.home_address);
      if (result) {
        await pool.query(
          `UPDATE student_import_staging SET geo_lat = ?, geo_lng = ? WHERE id = ?`,
          [result.lat, result.lng, r.id]
        );
        ok++;
      } else {
        await pool.query(
          `UPDATE student_import_staging SET match_status = 'failed' WHERE id = ?`,
          [r.id]
        );
        fail++;
      }
      // 不需要外層 sleep,geocodeOne 內部已保證下一次 API 呼叫間隔 ≥1.1 秒
    }

    // 回傳整體進度
    const [stat]: any = await pool.query(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN geo_lat IS NOT NULL THEN 1 ELSE 0 END) AS geocoded,
         SUM(CASE WHEN match_status = 'failed' THEN 1 ELSE 0 END) AS failed,
         SUM(CASE WHEN geo_lat IS NULL AND match_status != 'failed' THEN 1 ELSE 0 END) AS remaining
       FROM student_import_staging WHERE batch_id = ?`,
      [batch_id]
    );
    const s = stat[0] || {};
    res.json({
      ok: true,
      step_ok: ok,
      step_fail: fail,
      total: Number(s.total) || 0,
      geocoded: Number(s.geocoded) || 0,
      failed: Number(s.failed) || 0,
      remaining: Number(s.remaining) || 0,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// GET /api/admin/student-import/:batch_id/geocode-status
// 查目前進度 (進頁時先呼叫,顯示是否已查過)
app.get('/api/admin/student-import/:batch_id/geocode-status', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { batch_id } = req.params;
  try {
    const [stat]: any = await pool.query(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN geo_lat IS NOT NULL THEN 1 ELSE 0 END) AS geocoded,
         SUM(CASE WHEN match_status = 'failed' THEN 1 ELSE 0 END) AS failed,
         SUM(CASE WHEN geo_lat IS NULL AND match_status != 'failed' THEN 1 ELSE 0 END) AS remaining
       FROM student_import_staging WHERE batch_id = ?`,
      [batch_id]
    );
    const s = stat[0] || {};
    res.json({
      total: Number(s.total) || 0,
      geocoded: Number(s.geocoded) || 0,
      failed: Number(s.failed) || 0,
      remaining: Number(s.remaining) || 0,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// 3c-2 debug: 重置這批次的 geocoding 狀態,讓全部重查 (除了真的地址過短的)
app.post('/api/admin/student-import/:batch_id/geocode-reset', auth(['admin']), async (req: AuthRequest, res: Response) => {
  const { batch_id } = req.params;
  try {
    const [r]: any = await pool.query(
      `UPDATE student_import_staging
       SET match_status = 'pending', geo_lat = NULL, geo_lng = NULL
       WHERE batch_id = ?`,
      [batch_id]
    );
    res.json({ ok: true, reset: r.affectedRows });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
