from models import Alert
from datetime import datetime, timedelta

# Keywords
SSH_FAIL = ["Failed password", "authentication failure"]
SUDO_KEYWORDS = ["sudo", "pam_unix(sudo"]
USER_ENUM = ["Invalid user"]
SUSPICIOUS_CMDS = ["chmod 777", "curl http", "wget http", "nc -e", "bash -i"]
CRASH_KEYWORDS = ["segfault", "core dumped", "kernel panic"]

def create_alert(db, alert_type, severity, description):
    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        description=description
    )
    db.add(alert)
    db.commit()

def run_detection(db, log):
    msg = log.message.lower()

    # 1️⃣ SSH Brute Force
    if any(k.lower() in msg for k in SSH_FAIL):
        create_alert(
            db,
            "SSH Brute Force",
            "High",
            f"Multiple failed SSH attempts on {log.hostname}"
        )

    # 2️⃣ User Enumeration
    if any(k.lower() in msg for k in USER_ENUM):
        create_alert(
            db,
            "User Enumeration",
            "Medium",
            f"Invalid user attempts detected on {log.hostname}"
        )

    # 3️⃣ Sudo Abuse
    if any(k.lower() in msg for k in SUDO_KEYWORDS):
        create_alert(
            db,
            "Privilege Escalation (sudo)",
            "High",
            f"Sudo usage detected on {log.hostname}"
        )

    # 4️⃣ Suspicious Command Execution
    if any(k.lower() in msg for k in SUSPICIOUS_CMDS):
        create_alert(
            db,
            "Suspicious Command Execution",
            "Critical",
            f"Potential malware command detected on {log.hostname}"
        )

    # 5️⃣ Night-time Login (simple heuristic)
    hour = datetime.utcnow().hour
    if "session opened" in msg and (hour < 6 or hour > 22):
        create_alert(
            db,
            "Anomalous Login Time",
            "Medium",
            f"Login outside business hours on {log.hostname}"
        )

    # 6️⃣ Kernel / Service Crash
    if any(k.lower() in msg for k in CRASH_KEYWORDS):
        create_alert(
            db,
            "System Crash / Kernel Panic",
            "Critical",
            f"Crash detected on {log.hostname}"
        )
