from flask import Flask, render_template, request

app = Flask(__name__)

# ---------------------------
# 🔍 Scan Ports (simulation)
# ---------------------------
def scan_ports(target):
    if not target:
        return []
    return [22, 80, 443]  # simulation

# ---------------------------
# 🔐 Password Strength
# ---------------------------
def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 25
    if any(c.isdigit() for c in password):
        score += 25
    if any(c.isupper() for c in password):
        score += 25
    if any(c in "!@#$%^&*()" for c in password):
        score += 25

    if score >= 75:
        level = "Strong"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Weak"

    return level, score

# ---------------------------
# 🛡️ Detect Vulnerabilities
# ---------------------------
def detect_vulnerabilities(open_ports):
    vulns = []

    if 22 in open_ports:
        vulns.append("Port 22 SSH: Risque si mot de passe faible")
    if 80 in open_ports:
        vulns.append("Port 80 HTTP: Non chiffré")
    if 443 not in open_ports:
        vulns.append("Port 443 HTTPS: Manquant")

    return vulns

# ---------------------------
# 📊 Calculate Score
# ---------------------------
def calculate_score(pwd_level, open_ports, vulns):
    score = 100

    score -= len(vulns) * 15

    if pwd_level == "Weak":
        score -= 30
    elif pwd_level == "Medium":
        score -= 15
    elif pwd_level == "Not Checked":
        score -= 5

    return max(0, score)

# ---------------------------
# 🌐 Route
# ---------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        target = request.form["target"]
        password = request.form.get("password")

        open_ports = scan_ports(target)

        if password and password.strip():
            pwd_level, pwd_score = password_strength(password)
        else:
            pwd_level, pwd_score = "Not Checked", 0

        vulns = detect_vulnerabilities(open_ports)
        score = calculate_score(pwd_level, open_ports, vulns)

        result = {
            "target": target,
            "open_ports": open_ports,
            "pwd_level": pwd_level,
            "pwd_score": pwd_score,
            "vulns": vulns,
            "score": score
        }

    return render_template("index.html", result=result)

# ---------------------------
# 🚀 Run App
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
