from fastapi import FastAPI
from pydantic import BaseModel
from database import SessionLocal, engine
from models import Log, Alert, Base
from detector import run_detection

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Mini SIEM")

class LogPayload(BaseModel):
    logs: list
    source: str

@app.post("/logs")
def receive_logs(payload: LogPayload):
    db = SessionLocal()

    for entry in payload.logs:
        log = Log(
            hostname=payload.source,
            message=entry,
            severity="INFO"
        )
        db.add(log)
        db.commit()

        run_detection(db, log)

    db.close()
    return {"status": "ok", "received": len(payload.logs)}
