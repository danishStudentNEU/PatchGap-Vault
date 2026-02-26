import json
import time
import redis
import os
import db
db.init_db()

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

from main import Event, compute_rule_risk, decision_from_risk, QUEUE_NAME, DECISION_PREFIX

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

print("Worker started. Waiting for events...")

def replay_unqueued():
    """
    Re-queue events that were saved in Postgres but never queued to Redis (queued=false),
    e.g., when Redis was down.
    """
    try:
        unqueued = db.fetch_unqueued_events(limit=50)
        for e in unqueued:
            r.lpush(QUEUE_NAME, e["eventId"])
            db.mark_event_queued(e["eventId"])
        if unqueued:
            print(f"[replay] re-queued {len(unqueued)} event(s)")
    except Exception:
        # If Redis is down, or transient DB issue, we’ll try again later.
        pass
ticks = 0

while True:
    ticks += 1
    if ticks % 5 == 0:   # roughly every ~5 seconds (because timeout=1)
        replay_unqueued()

    msg = r.brpop(QUEUE_NAME, timeout=1)
    if not msg:
        continue

    _, event_id = msg
    evt_data = db.fetch_event_by_id(event_id)
    if not evt_data:
        continue
    evt = Event(**evt_data)

    risk, reasons = compute_rule_risk(evt)
    decision = decision_from_risk(risk)

    result = {
        "decision": decision,
        "finalRisk": risk,
        "reasons": reasons
    }

    db.insert_decision(evt.eventId, decision, risk, reasons)
    db.mark_event_processed(evt.eventId)

    # optional: keep caching decision in Redis (fine)
    r.set(f"{DECISION_PREFIX}{evt.eventId}", json.dumps(result), ex=300)

    print(f"Processed {evt.eventId}: {decision} risk={risk}")
    time.sleep(0.05)