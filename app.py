from flask import Flask, render_template, request
from scanner import scan_ports
from security import password_strength, detect_vulnerabilities, calculate_score, recommendations

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        target = request.form["target"]
        password = request.form["password"]

        # scan
        open_ports = scan_ports(target)

        # password check
        pwd_level, pwd_score = password_strength(password)

        # vulnerabilities
        vulns = detect_vulnerabilities(open_ports)

        # score
        score = calculate_score(pwd_level, open_ports, vulns)

        # recommendations
        rec = recommendations(vulns, pwd_level)

        result = {
            "target": target,
            "open_ports": open_ports,
            "password_level": pwd_level,
            "vulnerabilities": vulns,
            "score": score,
            "recommendations": rec
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)