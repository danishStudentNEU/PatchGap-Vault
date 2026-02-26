from pydantic import BaseModel
from typing import Dict, Any, List, Optional


class DeviceIntegrity(BaseModel):
    isEmulator: bool = False
    isDebuggable: bool = False
    isRooted: bool = False


class Event(BaseModel):
    eventId: str
    userIdHash: str
    deviceIdHash: str
    geo: str
    eventType: str
    deviceIntegrity: DeviceIntegrity = DeviceIntegrity()
    context: Dict[str, Any] = {}


class OtpVerifyRequest(BaseModel):
    otp: str


class DecisionResponse(BaseModel):
    status: str
    decision: Optional[str] = None
    finalRisk: Optional[int] = None
    reasons: List[str] = []