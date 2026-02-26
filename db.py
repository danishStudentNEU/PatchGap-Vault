import os
import psycopg2
from psycopg2.extras import Json, RealDictCursor
import random
from datetime import datetime, timedelta

PG_HOST = os.getenv("DB_HOST", os.getenv("POSTGRES_HOST", "127.0.0.1"))
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB   = os.getenv("POSTGRES_DB", "patchgap")
PG_USER = os.getenv("POSTGRES_USER", "patchgap")
PG_PASS = os.getenv("POSTGRES_PASSWORD", "patchgap")

def create_otp_challenge(client_event_id: str, ttl_seconds: int = 120):
    otp = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM events WHERE event_id = %s;", (client_event_id,))
                row = cur.fetchone()
                if not row:
                    return None
                event_uuid = row[0]

                cur.execute(
                    """
                    INSERT INTO challenges (event_id, type, status, otp_code, expires_at)
                    VALUES (%s, 'OTP', 'PENDING', %s, %s)
                    ON CONFLICT (event_id) DO UPDATE SET
                      status = 'PENDING',
                      otp_code = EXCLUDED.otp_code,
                      expires_at = EXCLUDED.expires_at,
                      created_at = NOW()
                    RETURNING otp_code, expires_at, status;
                    """,
                    (event_uuid, otp, expires_at),
                )
                otp_code, exp, status = cur.fetchone()
                return {"status": status, "expiresAt": str(exp), "otp": otp_code}
    finally:
        conn.close()

def verify_otp_challenge(client_event_id: str, otp: str):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT c.id, c.status, c.otp_code, c.expires_at
                    FROM challenges c
                    JOIN events e ON e.id = c.event_id
                    WHERE e.event_id = %s
                    LIMIT 1;
                    """,
                    (client_event_id,),
                )
                row = cur.fetchone()
                if not row:
                    return {"ok": False, "reason": "NO_CHALLENGE"}

                if row["status"] == "VERIFIED":
                    return {"ok": True, "reason": "ALREADY_VERIFIED"}

                if datetime.utcnow() > row["expires_at"]:
                    cur.execute("UPDATE challenges SET status='EXPIRED' WHERE id=%s;", (row["id"],))
                    return {"ok": False, "reason": "EXPIRED"}

                if otp != row["otp_code"]:
                    return {"ok": False, "reason": "INVALID_OTP"}

                cur.execute("UPDATE challenges SET status='VERIFIED' WHERE id=%s;", (row["id"],))
                # Also update decision to ALLOW after successful OTP
                cur.execute(
                    """
                    SELECT id FROM events WHERE event_id = %s;
                    """,
                    (client_event_id,),
                )
                event_row = cur.fetchone()
                if event_row:
                    event_uuid = event_row[]
                    cur.execute(
                        """
                        UPDATE decisions
                        SET decision = 'ALLOW',
                            model_version = 'rules-v1-otp',
                            created_at = NOW()
                        WHERE event_id = %s;
                        """,
                        (event_uuid,),
                    )

                return {"ok": True, "reason": "VERIFIED"}
    finally:
        conn.close()
    def fetch_event_by_id(client_event_id: str):
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                    e.event_id      AS "eventId",
                    u.user_hash     AS "userIdHash",
                    d.device_hash   AS "deviceIdHash",
                    e.geo           AS "geo",
                    e.event_type    AS "eventType",
                    COALESCE(d.integrity_flags, '{}'::jsonb) AS "deviceIntegrity",
                    COALESCE(e.context, '{}'::jsonb)         AS "context"
                    FROM events e
                    JOIN users u ON u.id = e.user_id
                    LEFT JOIN devices d ON d.id = e.device_id
                    WHERE e.event_id = %s
                    LIMIT 1;
                    """,
                    (client_event_id,),
                )
                return cur.fetchone()
        finally:
            conn.close()



def get_conn():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASS,
    )

def init_db():
    # No-op because schema is created by init.sql
    return

def _upsert_user(cur, user_hash: str):
    cur.execute(
        """
        INSERT INTO users (user_hash)
        VALUES (%s)
        ON CONFLICT (user_hash) DO UPDATE SET last_seen_at = NOW()
        RETURNING id;
        """,
        (user_hash,),
    )
    return cur.fetchone()[0]

def _upsert_device(cur, user_id, device_hash: str, integrity_flags: dict):
    cur.execute(
        """
        INSERT INTO devices (device_hash, user_id, integrity_flags, first_seen_at, last_seen_at)
        VALUES (%s, %s, %s, NOW(), NOW())
        ON CONFLICT (device_hash) DO UPDATE SET
            user_id = EXCLUDED.user_id,
            integrity_flags = EXCLUDED.integrity_flags,
            last_seen_at = NOW()
        RETURNING id;
        """,
        (device_hash, user_id, Json(integrity_flags or {})),
    )
    return cur.fetchone()[0]

def insert_event(evt: dict):
    event_id = evt.get("eventId")
    user_hash = evt.get("userIdHash")
    device_hash = evt.get("deviceIdHash")
    geo = evt.get("geo")
    event_type = evt.get("eventType")
    integrity = evt.get("deviceIntegrity") or {}
    context = evt.get("context") or {}

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                user_uuid = _upsert_user(cur, user_hash)
                device_uuid = _upsert_device(cur, user_uuid, device_hash, integrity)

                cur.execute(
                    """
                    INSERT INTO events (event_id, user_id, device_id, event_type, geo, context, created_at, queued, processed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), FALSE, NULL)
                    ON CONFLICT (event_id) DO NOTHING;
                    """,
                    (event_id, user_uuid, device_uuid, event_type, geo, Json(context)),
                )
    finally:
        conn.close()

def mark_event_queued(event_id: str):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE events SET queued = TRUE WHERE event_id = %s;", (event_id,))
    finally:
        conn.close()

def mark_event_processed(event_id: str):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE events SET processed_at = NOW() WHERE event_id = %s;", (event_id,))
    finally:
        conn.close()

def fetch_unqueued_events(limit: int = 50):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                  e.event_id      AS "eventId",
                  u.user_hash     AS "userIdHash",
                  d.device_hash   AS "deviceIdHash",
                  e.geo           AS "geo",
                  e.event_type    AS "eventType",
                  COALESCE(d.integrity_flags, '{}'::jsonb) AS "deviceIntegrity",
                  COALESCE(e.context, '{}'::jsonb)         AS "context"
                FROM events e
                JOIN users u ON u.id = e.user_id
                LEFT JOIN devices d ON d.id = e.device_id
                WHERE e.queued = FALSE
                ORDER BY e.created_at ASC
                LIMIT %s;
                """,
                (limit,),
            )
            return cur.fetchall()
    finally:
        conn.close()

def insert_decision(client_event_id: str, decision: str, final_risk: int, reasons: list):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM events WHERE event_id = %s;", (client_event_id,))
                row = cur.fetchone()
                if not row:
                    return
                event_uuid = row[0]

                cur.execute(
                    """
                    INSERT INTO decisions (event_id, risk_score, decision, reasons, model_version, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (event_id) DO UPDATE SET
                      risk_score = EXCLUDED.risk_score,
                      decision = EXCLUDED.decision,
                      reasons = EXCLUDED.reasons,
                      model_version = EXCLUDED.model_version,
                      created_at = NOW();
                    """,
                    (event_uuid, int(final_risk), decision, Json(reasons or []), "rules-v1"),
                )
    finally:
        conn.close()

def get_decision(client_event_id: str):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT d.decision AS decision,
                       d.risk_score AS "finalRisk",
                       COALESCE(d.reasons, '[]'::jsonb) AS reasons
                FROM decisions d
                JOIN events e ON e.id = d.event_id
                WHERE e.event_id = %s
                LIMIT 1;
                """,
                (client_event_id,),
            )
            return cur.fetchone()
    finally:
        conn.close()