// ============================================================
// backend/src/server.ts  ─  師傅管理系統 Express API（完整合併版）
// ============================================================
// 環境變數（.env）：
//   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
//   PORT=4000
//   LATE_THRESHOLD_HOUR=8
//   LATE_THRESHOLD_MINUTE=0
//   OFFLINE_MINUTES=10
//   TZ=Asia/Taipei   ← 必須設定，否則遲到判斷在 UTC 伺服器上會錯
// ============================================================

import express, { Request, Response } from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ── DB Pool ─────────────────────────────────────────────────
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               Number(process.env.DB_PORT) || 3306,
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',
  database:           process.env.DB_NAME     || 'zeabur',
  waitForConnections: true,
  connectionLimit:    10,
  timezone:           '+08:00',
});

const db = async (sql: string, params?: any[]): Promise<any[]> => {
  const [rows] = await pool.execute(sql, params);
  return rows as any[];
};

const LATE_H  = Number(process.env.LATE_THRESHOLD_HOUR   ?? 8);
const LATE_M  = Number(process.env.LATE_THRESHOLD_MINUTE ?? 0);
const OFFLINE = Number(process.env.OFFLINE_MINUTES       ?? 10);

// 遲到判斷 — 依賴 TZ=Asia/Taipei，setHours 使用 process 本地時間
function isLate(now: Date): { late: boolean; minutes: number } {
  const threshold = new Date(now);
  threshold.setHours(LATE_H, LATE_M, 0, 0);
  const diff = Math.floor((now.getTime() - threshold.getTime()) / 60000);
  return { late: diff > 0, minutes: diff > 0 ? diff : 0 };
}

function offlineCutoffStr(): string {
  return new Date(Date.now() - OFFLINE * 60 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');
}

// ── 健康檢查 ─────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

// ============================================================
// 1. 師傅 API
// ============================================================

app.get('/api/workers', async (_req: Request, res: Response) => {
  try {
    const cutoff = offlineCutoffStr();
    const workers = await db(`
      SELECT
        w.id, w.name, w.phone, w.is_active,
        ll.latitude, ll.longitude, ll.created_at AS last_location_at,
        al.id        AS attendance_id,
        al.start_time, al.end_time, al.is_late, al.late_minutes,
        CASE
          WHEN al.id IS NOT NULL AND al.end_time IS NULL AND ll.created_at >= ?
          THEN 1 ELSE 0
        END AS is_online
      FROM workers w
      LEFT JOIN (
        SELECT l1.worker_id, l1.latitude, l1.longitude, l1.created_at
        FROM location_logs l1
        INNER JOIN (
          SELECT worker_id, MAX(created_at) AS max_at FROM location_logs GROUP BY worker_id
        ) l2 ON l1.worker_id = l2.worker_id AND l1.created_at = l2.max_at
      ) ll ON ll.worker_id = w.id
      LEFT JOIN attendance_logs al ON al.worker_id = w.id AND al.work_date = CURDATE()
      WHERE w.is_active = 1
      ORDER BY is_online DESC, w.name
    `, [cutoff]);
    res.json({ success: true, data: workers });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/workers/:id', async (req: Request, res: Response) => {
  try {
    const [worker] = await db('SELECT * FROM workers WHERE id = ?', [req.params.id]);
    if (!worker) return res.status(404).json({ success: false, error: '找不到師傅' });
    res.json({ success: true, data: worker });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/workers', async (req: Request, res: Response) => {
  const { name, phone, role = 'worker', line_user_id } = req.body;
  if (!name || !phone) return res.status(400).json({ success: false, error: '缺少 name / phone' });
  try {
    const [result]: any = await pool.execute(
      'INSERT INTO workers (name, phone, role, line_user_id) VALUES (?,?,?,?)',
      [name, phone, role, line_user_id || null]
    );
    res.json({ success: true, data: { id: result.insertId } });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.patch('/api/workers/:id', async (req: Request, res: Response) => {
  const { name, phone, is_active } = req.body;
  try {
    await pool.execute(
      'UPDATE workers SET name=COALESCE(?,name), phone=COALESCE(?,phone), is_active=COALESCE(?,is_active) WHERE id=?',
      [name ?? null, phone ?? null, is_active ?? null, req.params.id]
    );
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============================================================
// 2. 出勤打卡 API
// ============================================================

app.post('/api/attendance/start', async (req: Request, res: Response) => {
  const { worker_id, latitude, longitude } = req.body;
  if (!worker_id) return res.status(400).json({ success: false, error: '缺少 worker_id' });
  try {
    const existing = await db(
      'SELECT id FROM attendance_logs WHERE worker_id = ? AND work_date = CURDATE() AND end_time IS NULL',
      [worker_id]
    );
    if (existing.length > 0)
      return res.status(409).json({ success: false, error: '今日已有未結束的出勤紀錄' });

    const now = new Date();
    const { late, minutes } = isLate(now);
    const workDate = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`;

    const [result]: any = await pool.execute(
      'INSERT INTO attendance_logs (worker_id, start_time, is_late, late_minutes, work_date) VALUES (?,?,?,?,?)',
      [worker_id, now, late ? 1 : 0, minutes, workDate]
    );
    const attendance_id = result.insertId;

    if (latitude != null && longitude != null) {
      await pool.execute(
        'INSERT INTO location_logs (worker_id, attendance_id, latitude, longitude) VALUES (?,?,?,?)',
        [worker_id, attendance_id, latitude, longitude]
      );
    }
    res.json({ success: true, data: { attendance_id, start_time: now, is_late: late, late_minutes: minutes } });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/attendance/end', async (req: Request, res: Response) => {
  const { worker_id } = req.body;
  if (!worker_id) return res.status(400).json({ success: false, error: '缺少 worker_id' });
  try {
    const [active] = await db(
      'SELECT id, start_time FROM attendance_logs WHERE worker_id = ? AND work_date = CURDATE() AND end_time IS NULL',
      [worker_id]
    );
    if (!active) return res.status(404).json({ success: false, error: '找不到今日出勤紀錄' });

    const now = new Date();
    await pool.execute('UPDATE attendance_logs SET end_time = ? WHERE id = ?', [now, active.id]);
    const workMinutes = Math.floor((now.getTime() - new Date(active.start_time).getTime()) / 60000);
    res.json({ success: true, data: { end_time: now, work_minutes: workMinutes } });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/attendance/today/:worker_id', async (req: Request, res: Response) => {
  try {
    const [log] = await db(
      'SELECT * FROM attendance_logs WHERE worker_id = ? AND work_date = CURDATE() ORDER BY id DESC LIMIT 1',
      [req.params.worker_id]
    );
    res.json({ success: true, data: log || null });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/attendance/monthly/:worker_id', async (req: Request, res: Response) => {
  try {
    const rows = await db(`
      SELECT id, work_date, start_time, end_time, is_late, late_minutes
      FROM attendance_logs
      WHERE worker_id = ?
        AND YEAR(work_date)  = YEAR(CURDATE())
        AND MONTH(work_date) = MONTH(CURDATE())
      ORDER BY work_date DESC
    `, [req.params.worker_id]);
    res.json({ success: true, data: rows });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============================================================
// 3. 定位 API
// ============================================================

// 下班後 /api/location/update 會回傳 403，前端 hook 的 setInterval 仍在跑
// 但資料不會寫入 DB — 這是預期行為，前端靠 is_online flag 停止顯示
app.post('/api/location/update', async (req: Request, res: Response) => {
  const { worker_id, latitude, longitude, accuracy } = req.body;
  if (!worker_id || latitude == null || longitude == null)
    return res.status(400).json({ success: false, error: '缺少必要參數' });
  try {
    const [attendance] = await db(
      'SELECT id FROM attendance_logs WHERE worker_id = ? AND work_date = CURDATE() AND end_time IS NULL',
      [worker_id]
    );
    if (!attendance)
      return res.status(403).json({ success: false, error: '未上班，不接受定位' });

    await pool.execute(
      'INSERT INTO location_logs (worker_id, attendance_id, latitude, longitude, accuracy) VALUES (?,?,?,?,?)',
      [worker_id, attendance.id, latitude, longitude, accuracy ?? null]
    );
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/location/latest', async (_req: Request, res: Response) => {
  try {
    const cutoff = offlineCutoffStr();
    const rows = await db(`
      SELECT
        w.id AS worker_id, w.name,
        ll.latitude, ll.longitude, ll.created_at AS last_seen,
        CASE
          WHEN al.id IS NOT NULL AND al.end_time IS NULL AND ll.created_at >= ?
          THEN 1 ELSE 0
        END AS is_online,
        al.start_time
      FROM workers w
      INNER JOIN (
        SELECT l1.worker_id, l1.latitude, l1.longitude, l1.created_at
        FROM location_logs l1
        INNER JOIN (
          SELECT worker_id, MAX(created_at) AS max_at FROM location_logs GROUP BY worker_id
        ) l2 ON l1.worker_id = l2.worker_id AND l1.created_at = l2.max_at
      ) ll ON ll.worker_id = w.id
      LEFT JOIN attendance_logs al ON al.worker_id = w.id AND al.work_date = CURDATE()
      WHERE w.is_active = 1
    `, [cutoff]);
    res.json({ success: true, data: rows });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/location/trail/:worker_id', async (req: Request, res: Response) => {
  try {
    const date = (req.query.date as string) || new Date().toISOString().slice(0, 10);
    const rows = await db(
      'SELECT latitude, longitude, created_at FROM location_logs WHERE worker_id = ? AND DATE(created_at) = ? ORDER BY created_at ASC',
      [req.params.worker_id, date]
    );
    res.json({ success: true, data: rows });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============================================================
// 4. 工程紀錄 API
// ============================================================

app.post('/api/job/record', async (req: Request, res: Response) => {
  const { worker_id, type, latitude, longitude, note } = req.body;
  if (!worker_id || !type || latitude == null || longitude == null)
    return res.status(400).json({ success: false, error: '缺少必要參數' });
  if (!['arrived', 'left'].includes(type))
    return res.status(400).json({ success: false, error: 'type 只允許 arrived / left' });
  try {
    const [attendance] = await db(
      'SELECT id FROM attendance_logs WHERE worker_id = ? AND work_date = CURDATE() AND end_time IS NULL',
      [worker_id]
    );
    if (!attendance)
      return res.status(403).json({ success: false, error: '尚未開始上班，無法記錄' });

    const [result]: any = await pool.execute(
      'INSERT INTO job_records (worker_id, attendance_id, type, latitude, longitude, note) VALUES (?,?,?,?,?,?)',
      [worker_id, attendance.id, type, latitude, longitude, note ?? null]
    );
    res.json({ success: true, data: { id: result.insertId, type } });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/job/records/:worker_id', async (req: Request, res: Response) => {
  try {
    const date = (req.query.date as string) || new Date().toISOString().slice(0, 10);
    const rows = await db(`
      SELECT jr.id, jr.type, jr.latitude, jr.longitude, jr.note, jr.created_at
      FROM job_records jr
      LEFT JOIN attendance_logs al ON al.id = jr.attendance_id
      WHERE jr.worker_id = ?
        AND DATE(COALESCE(al.work_date, jr.created_at)) = ?
      ORDER BY jr.created_at DESC
    `, [req.params.worker_id, date]);
    res.json({ success: true, data: rows });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============================================================
// 5. 統計 API
// ============================================================

app.get('/api/stats/dashboard', async (_req: Request, res: Response) => {
  try {
    const [[todayJobs]]: any = await pool.execute(
      'SELECT COUNT(*) AS cnt FROM job_records WHERE DATE(created_at) = CURDATE()'
    );
    const [[monthLogs]]: any = await pool.execute(
      'SELECT COUNT(*) AS cnt FROM attendance_logs WHERE YEAR(work_date)=YEAR(CURDATE()) AND MONTH(work_date)=MONTH(CURDATE())'
    );
    const [[customers]]: any = await pool.execute(
      'SELECT COUNT(*) AS cnt FROM customers WHERE is_active=1'
    );
    const [[onlineNow]]: any = await pool.execute(`
      SELECT COUNT(DISTINCT w.id) AS cnt
      FROM workers w
      JOIN attendance_logs al ON al.worker_id=w.id AND al.work_date=CURDATE() AND al.end_time IS NULL
      JOIN location_logs ll ON ll.worker_id=w.id
        AND ll.created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
    `, [OFFLINE]);
    res.json({
      success: true,
      data: {
        today_jobs:      todayJobs.cnt,
        month_records:   monthLogs.cnt,
        total_customers: customers.cnt,
        online_workers:  onlineNow.cnt,
      }
    });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/stats/worker/:id', async (req: Request, res: Response) => {
  try {
    const [stats] = await db(`
      SELECT
        COUNT(*) AS attend_days,
        SUM(is_late) AS late_count,
        SUM(TIMESTAMPDIFF(MINUTE, start_time, IFNULL(end_time, NOW()))) AS total_minutes
      FROM attendance_logs
      WHERE worker_id = ?
        AND YEAR(work_date) = YEAR(CURDATE())
        AND MONTH(work_date) = MONTH(CURDATE())
    `, [req.params.id]);
    res.json({
      success: true,
      data: {
        attend_days:   Number(stats.attend_days)   || 0,
        late_count:    Number(stats.late_count)    || 0,
        total_hours:   Math.floor((Number(stats.total_minutes) || 0) / 60),
        total_minutes: (Number(stats.total_minutes) || 0) % 60,
      }
    });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============================================================
// 6. 客戶 API
// ============================================================

app.get('/api/customers', async (_req: Request, res: Response) => {
  try {
    const rows = await db('SELECT * FROM customers WHERE is_active = 1 ORDER BY name');
    res.json({ success: true, data: rows });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── 啟動 ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ API Server running on port ${PORT}`);
  console.log(`   TZ=${process.env.TZ || '(未設定！遲到判斷將用伺服器本地時間)'}`);
  console.log(`   遲到門檻：${LATE_H}:${String(LATE_M).padStart(2,'0')}`);
  console.log(`   離線門檻：${OFFLINE} 分鐘`);
});

export default app;
