from fastapi import FastAPI
from pydantic import BaseModel
from models import Event, DeviceIntegrity, OtpVerifyRequest, DecisionResponse
from typing import Dict, Any, List, Optional
from db import create_otp_challenge, verify_otp_challenge
from pydantic import BaseModel

import json
import redis
import os
import db

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

app = FastAPI(title="PatchGap Guard - Phase 2A (Redis Queue + Worker)")

@app.on_event("startup")
def startup():
    db.init_db()

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

QUEUE_NAME = "telemetry_queue"          
DECISION_PREFIX = "decision:"           


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def compute_rule_risk(evt: Event) -> (int, List[str]):
    reasons = []
    risk = 0

    if evt.deviceIntegrity.isRooted or evt.deviceIntegrity.isEmulator or evt.deviceIntegrity.isDebuggable:
        risk += 50
        reasons.append("DEVICE_INTEGRITY_FAIL")

    failed_10m = int(evt.context.get("loginFailuresLast10m", 0))
    if failed_10m >= 5:
        risk += 40
        reasons.append("FAILED_LOGINS_BURST")

    if evt.eventType == "TRANSFER_INITIATED":
        amount = float(evt.context.get("amount", 0))
        beneficiary_new = bool(evt.context.get("beneficiaryNew", False))

        if beneficiary_new:
            risk += 30
            reasons.append("NEW_BENEFICIARY")

        if amount >= 5000:
            risk += 35
            reasons.append("HIGH_AMOUNT")

    velocity = int(evt.context.get("eventVelocity1m", 0))
    if velocity >= 15:
        risk += 20
        reasons.append("HIGH_VELOCITY")

    return clamp(risk, 0, 100), reasons

def decision_from_risk(risk: int) -> str:
    if risk < 30:
        return "ALLOW"
    if risk < 70:
        return "STEP_UP_AUTH"
    if risk < 85:
        return "BLOCK_TRANSFER"
    return "LOCK_ACCOUNT"

@app.post("/events")
def ingest_event(evt: Event):
    evt_dict = evt.model_dump()

    # 1) Store durably in Postgres first
    db.insert_event(evt_dict)

    # 2) Try to enqueue to Redis
    try:
        # Enhancing code from to push just the event ID to redis, instead of the whole payload, to reduce Redis load. The worker can fetch details from DB using event ID.
        # r.lpush(QUEUE_NAME, json.dumps(evt_dict))
        # db.mark_event_queued(evt_dict["eventId"])
        r.lpush(QUEUE_NAME, evt.eventId)   # only the id
        db.mark_event_queued(evt.eventId)
        return {"accepted": True, "eventId": evt.eventId, "queued": True}
    except Exception:
        # Redis down: still accepted because DB write succeeded
        return {"accepted": True, "eventId": evt.eventId, "queued": False}


@app.get("/decisions/{event_id}", response_model=DecisionResponse)
def get_decision(event_id: str):
    data = db.get_decision(event_id)
    if not data:
        return DecisionResponse(status="PENDING")
    return DecisionResponse(status="READY", **data)

@app.post("/challenges/{event_id}")
def create_challenge(event_id: str):
    result = create_otp_challenge(event_id)
    if not result:
        return {"ok": False, "reason": "EVENT_NOT_FOUND"}
    return {"ok": True, **result}

@app.post("/challenges/{event_id}/verify")
def verify_challenge(event_id: str, body: OtpVerifyRequest):
    return verify_otp_challenge(event_id, body.otp)