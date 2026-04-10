from flask import Flask, render_template, redirect, url_for, request, Response
from datetime import datetime, timedelta
import secrets
import string
import random
import subprocess

from apscheduler.schedulers.background import BackgroundScheduler
import db

app = Flask(__name__)
db.init_db()

OFFICIAL_SSID = "InsideScoop_WiFi"
OFFICIAL_BSSID = "AA:BB:CC:DD:EE:FF"
OFFICIAL_SECURITY = "WPA2"
ROTATION_DAYS = 30

ADMIN_USERNAME = "insidescoop"
ADMIN_PASSWORD = "pubwisec123"

scheduler = BackgroundScheduler()

# =========================
# HELPERS
# =========================

def generate_password(length: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def days_since_changed(latest_row) -> int:
    if not latest_row:
        return 0
    dt = datetime.strptime(latest_row["changed_at"], "%Y-%m-%d %H:%M:%S")
    return (datetime.now() - dt).days


def filter_alerts_last_24h(alerts_list):
    recent = []
    now = datetime.now()

    for a in alerts_list:
        try:
            t = datetime.strptime(a["created_at"], "%Y-%m-%d %H:%M:%S")
            if (now - t).total_seconds() <= 24 * 3600:
                recent.append(a)
        except Exception:
            pass

    return recent


def compute_system_status_from_alerts(alerts_list):
    """
    SAFE: no HIGH/CRITICAL
    WARNING: >=1 HIGH/CRITICAL
    CRITICAL: >=3 HIGH/CRITICAL OR >=1 CRITICAL
    """
    high = 0
    critical = 0

    for a in alerts_list:
        sev = (a["severity"] if a["severity"] else "").upper()

        if sev == "CRITICAL":
            critical += 1
        if sev in ["HIGH", "CRITICAL"]:
            high += 1

    if critical >= 1 or high >= 3:
        return "CRITICAL"
    if high >= 1:
        return "WARNING"
    return "SAFE"


def get_dashboard_graph_data(days=7):
    alerts_list = db.get_alerts(limit=1000)

    today = datetime.now().date()
    labels = []
    values = []

    for i in range(days):
        target_day = today - timedelta(days=(days - 1 - i))
        labels.append(target_day.strftime("%d %b"))

        day_alerts = []
        for a in alerts_list:
            try:
                alert_time = datetime.strptime(a["created_at"], "%Y-%m-%d %H:%M:%S")
                if alert_time.date() == target_day:
                    day_alerts.append(a)
            except Exception:
                pass

        status = compute_system_status_from_alerts(day_alerts)

        if status == "SAFE":
            values.append(1)
        elif status == "WARNING":
            values.append(2)
        else:
            values.append(3)

    return {
        "labels": labels,
        "values": values
    }


def scan_wifi_networks():
    """
    Real Wi-Fi scan using nmcli.
    Falls back to demo data if nmcli fails.
    """
    try:
        result = subprocess.check_output(
            ["nmcli", "-f", "SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list"],
            stderr=subprocess.STDOUT
        ).decode("utf-8", errors="ignore")

        networks = []
        lines = result.splitlines()

        if len(lines) > 1:
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                signal = parts[-1]
                security = parts[-2]
                bssid = parts[-3]
                ssid = " ".join(parts[:-3]).strip()

                if not ssid:
                    ssid = "(Hidden)"

                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "security": security,
                    "signal": signal
                })

        return networks

    except Exception as e:
        print("Scan error:", e)

        # fallback supaya system masih jalan masa demo
        return [
            {
                "ssid": "InsideScoop_WiFi",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "security": "WPA2",
                "signal": "85"
            },
            {
                "ssid": "InsideScoop_WiFi",
                "bssid": "11:22:33:44:55:66",
                "security": "OPEN",
                "signal": "72"
            },
            {
                "ssid": "CoffeeShop_FreeWiFi",
                "bssid": "77:88:99:AA:BB:CC",
                "security": "WPA2",
                "signal": "60"
            }
        ]


# =========================
# SCHEDULER JOBS
# =========================

def check_password_rotation():
    try:
        latest = db.get_latest_password()

        if not latest:
            new_pwd = generate_password()
            db.add_password(new_pwd)
            db.add_alert("PASSWORD_ROTATION", "INFO", "Initial Wi-Fi password created automatically.")
            print("[Scheduler] Initial password created.")
            return

        age_days = days_since_changed(latest)

        if age_days >= ROTATION_DAYS:
            new_pwd = generate_password()
            db.add_password(new_pwd)
            db.add_alert(
                "PASSWORD_ROTATION",
                "INFO",
                f"Wi-Fi password rotated automatically after {age_days} day(s)."
            )
            print(f"[Scheduler] Password rotated automatically (age_days={age_days}).")
        else:
            print(f"[Scheduler] Rotation not needed (age_days={age_days}).")

    except Exception as e:
        print("[Scheduler] Rotation error:", e)


def auto_threat_simulation_job():
    try:
        r = random.random()

        if r < 0.10:
            db.add_alert("MITM", "HIGH", "Possible ARP spoofing / MITM attempt detected (auto).")
            print("[Scheduler] Auto threat: MITM inserted.")
        elif r < 0.18:
            db.add_alert("Rogue AP", "HIGH", "Fake Wi-Fi (Evil Twin) detected near cafe (auto).")
            print("[Scheduler] Auto threat: Rogue AP inserted.")
        elif r < 0.25:
            db.add_alert("SUSPICIOUS_LOGIN", "WARNING", "Multiple suspicious login attempts detected (auto).")
            print("[Scheduler] Auto threat: Suspicious login inserted.")
        else:
            print("[Scheduler] No threat generated this cycle.")

    except Exception as e:
        print("[Scheduler] Threat simulation error:", e)


def auto_update_system_status_job():
    try:
        alerts_list = db.get_alerts(limit=50)
        recent = filter_alerts_last_24h(alerts_list)
        status = compute_system_status_from_alerts(recent)
        print("System status (last 24h):", status)
    except Exception as e:
        print("Status update error:", e)


# =========================
# ROUTES
# =========================

@app.before_request
def log_ip():
    print("Access from:", request.remote_addr)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid admin username or password")

    return render_template("login.html", error=None)


@app.route("/login", methods=["GET"])
def login_page_alias():
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    latest = db.get_latest_password()

    if not latest:
        pw = generate_password()
        db.add_password(pw)
        latest = db.get_latest_password()

    days_since = days_since_changed(latest)

    alerts_list = db.get_alerts(limit=100)
    recent24 = filter_alerts_last_24h(alerts_list)
    system_status = compute_system_status_from_alerts(recent24)

    selected_days = request.args.get("days", "7")
    if selected_days not in ["7", "14", "30"]:
        selected_days = "7"
    selected_days = int(selected_days)

    recent_alerts = []
    for a in alerts_list[:3]:
        recent_alerts.append({
            "type": a["alert_type"],
            "severity": a["severity"],
            "when": a["created_at"],
            "message": a["message"]
        })

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    graph_data = get_dashboard_graph_data(days=selected_days)

    password_due = days_since >= ROTATION_DAYS

    return render_template(
        "dashboard.html",
        current_password=latest["password"],
        days_since=days_since,
        current_ssid=OFFICIAL_SSID,
        system_status=system_status,
        recent_alerts=recent_alerts,
        scan_time=scan_time,
        graph_labels=graph_data["labels"],
        graph_values=graph_data["values"],
        selected_days=selected_days,
        password_due=password_due
    )


@app.post("/rotate")
def rotate():
    pw = generate_password()
    db.add_password(pw)
    db.add_alert("PASSWORD_ROTATION", "INFO", "Wi-Fi password rotated successfully (manual).")
    return redirect(url_for("dashboard"))


@app.route("/scan-wifi")
def scan_wifi_route():
    scanned_networks = scan_wifi_networks()
    rogue_detected = False

    for net in scanned_networks:
        if net["ssid"] == OFFICIAL_SSID:
            if net["bssid"] != OFFICIAL_BSSID or net["security"].upper() != OFFICIAL_SECURITY:
                rogue_detected = True
                db.add_alert(
                    "Rogue AP",
                    "HIGH",
                    f"Fake Wi-Fi detected near cafe: SSID '{net['ssid']}' with suspicious BSSID {net['bssid']} and security {net['security']}."
                )

    if not rogue_detected:
        db.add_alert(
            "WIFI_SCAN",
            "INFO",
            "Wi-Fi scan completed. No fake Wi-Fi detected near cafe."
        )

    return redirect(url_for("alerts"))


@app.route("/alerts")
def alerts():
    return render_template(
        "alerts.html",
        alerts=db.get_alerts(limit=50)
    )


@app.route("/simulate/mitm")
def simulate_mitm():
    db.add_alert("MITM", "HIGH", "Possible ARP spoofing / MITM attempt detected.")
    return redirect(url_for("alerts"))


@app.route("/simulate/rogue")
def simulate_rogue():
    db.add_alert("Rogue AP", "HIGH", "Fake Wi-Fi (Evil Twin) detected near cafe.")
    return redirect(url_for("alerts"))


@app.route("/password-history")
def password_history():
    return render_template(
        "password_history.html",
        history=db.get_password_history()
    )


@app.route("/advisory")
def advisory():
    alerts_list = db.get_alerts(limit=50)

    recent24 = filter_alerts_last_24h(alerts_list)
    system_status = compute_system_status_from_alerts(recent24)

    warning = system_status in ["WARNING", "CRITICAL"]
    critical = system_status == "CRITICAL"

    return render_template(
        "advisory.html",
        official_ssid=OFFICIAL_SSID,
        warning=warning,
        critical=critical,
        system_status=system_status
    )


@app.route("/logout")
def logout():
    return redirect(url_for("login"))


@app.route("/acknowledge")
def acknowledge_all():
    if hasattr(db, "acknowledge_all_alerts"):
        db.acknowledge_all_alerts()
    return redirect(url_for("alerts"))


@app.route("/export")
def export_alerts():
    alerts_list = db.get_alerts(limit=500)

    csv_data = "Date/Time,Type,Severity,Message\n"

    for a in alerts_list:
        created_at = str(a["created_at"]).replace('"', '""')
        alert_type = str(a["alert_type"]).replace('"', '""')
        severity = str(a["severity"]).replace('"', '""')
        message = str(a["message"]).replace('"', '""')

        csv_data += f'"{created_at}","{alert_type}","{severity}","{message}"\n'

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=pubwisec_alerts_report.csv"}
    )

# =========================
# QR CODE (ADVISORY)
# =========================
import qrcode
import os
from flask import send_file

@app.route("/qr")
def qr_code():
    advisory_url = request.host_url + "advisory"

    qr = qrcode.make(advisory_url)

    qr_path = os.path.join("static", "qr.png")
    qr.save(qr_path)

    return send_file(qr_path, mimetype="image/png")


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    scheduler.add_job(check_password_rotation, "interval", seconds=20)
    scheduler.add_job(auto_threat_simulation_job, "interval", seconds=60)
    scheduler.add_job(auto_update_system_status_job, "interval", seconds=30)

    if not scheduler.running:
        scheduler.start()

    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)