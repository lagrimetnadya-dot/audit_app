from flask import Flask, render_template, request

app = Flask(__name__)

# -------------------------------
# 🔍 Scan Ports (simulation)
# -------------------------------
def scan_ports(target):
    # تقدر تبدلها بـ nmap من بعد
    return [22, 80, 443]


# -------------------------------
# 🔐 Password Strength
# -------------------------------
def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*" for c in password):
        score += 1

    if score <= 1:
        return "Weak", score
    elif score <= 3:
        return "Medium", score
    else:
        return "Strong", score


# -------------------------------
# 🛡️ Vulnerabilities
# -------------------------------
def detect_vulnerabilities(open_ports):
    vulns = []

    if 22 in open_ports:
        vulns.append("SSH Port exposed")

    if 80 in open_ports:
        vulns.append("HTTP not secure (use HTTPS)")

    return vulns


# -------------------------------
# 📊 Score
# -------------------------------
def calculate_score(pwd_level, open_ports, vulns):
    score = 100

    score -= len(open_ports) * 5
    score -= len(vulns) * 10

    # password غير إلا كاين
    if pwd_level:
        if pwd_level == "Weak":
            score -= 20
        elif pwd_level == "Medium":
            score -= 10

    return max(score, 0)


# -------------------------------
# 💡 Recommendations
# -------------------------------
def generate_recommendations(open_ports, vulns, pwd_level):
    recs = []

    if pwd_level == "Weak":
        recs.append("استعمل password قوية")

    if 22 in open_ports:
        recs.append("Secure SSH (port 22)")

    if vulns:
        recs.append("Fix vulnerabilities")

    return recs


# -------------------------------
# 🌐 Main Route
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        target = request.form.get("target")
        password = request.form.get("password")

        # ✅ target ضروري
        if not target or not target.strip():
            error = "دخل IP أو Domain صحيح"
            return render_template("index.html", result=result, error=error)

        try:
            # 🔍 scan
            open_ports = scan_ports(target) or []

            # 🔐 password اختياري
            if password and password.strip():
                pwd_level, pwd_score = password_strength(password)
            else:
                pwd_level, pwd_score = None, None

            # 🛡️ vulnerabilities
            vulns = detect_vulnerabilities(open_ports) or []

            # 📊 score
            score = calculate_score(pwd_level, open_ports, vulns)

            # 💡 recommendations
            recommendations = generate_recommendations(open_ports, vulns, pwd_level)

            # 📦 result
            result = {
                "target": target,
                "open_ports": open_ports,
                "password_level": pwd_level,
                "password_score": pwd_score,
                "vulnerabilities": vulns,
                "score": score,
                "recommendations": recommendations
            }

        except Exception as e:
            error = f"وقع خطأ: {str(e)}"

    return render_template("index.html", result=result, error=error)


# -------------------------------
# 🚀 Run
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)