def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1

    if score <= 2:
        return "Weak 🔴", score
    elif score <= 4:
        return "Medium 🟠", score
    else:
        return "Strong 🟢", score


def detect_vulnerabilities(open_ports):
    vulnerabilities = []

    vuln_map = {
        21: "FTP insecure",
        22: "SSH brute-force risk",
        23: "Telnet not secure",
        80: "HTTP not encrypted",
        443: "SSL config check needed",
        445: "SMB vulnerable (WannaCry)",
        3389: "RDP brute-force risk"
    }

    for port in open_ports:
        if port in vuln_map:
            vulnerabilities.append({
                "port": port,
                "issue": vuln_map[port],
                "level": "HIGH 🔴"
            })

    if not vulnerabilities:
        vulnerabilities.append({
            "port": "-",
            "issue": "No vulnerabilities detected",
            "level": "SAFE 🟢"
        })

    return vulnerabilities


def calculate_score(password_level, open_ports, vulns):
    score = 100

    if password_level == "Weak 🔴":
        score -= 30
    elif password_level == "Medium 🟠":
        score -= 15
    else:
        score += 10

    score -= len(open_ports) * 10
    score -= len(vulns) * 10

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score


def recommendations(vulns, password_level):
    rec = []

    for v in vulns:
        if "FTP" in v["issue"]:
            rec.append("Close FTP service")
        if "SSH" in v["issue"]:
            rec.append("Use strong SSH password or keys")
        if "HTTP" in v["issue"]:
            rec.append("Use HTTPS instead of HTTP")
        if "SMB" in v["issue"]:
            rec.append("Disable SMB if not needed")

    if password_level == "Weak 🔴":
        rec.append("Use stronger password (12+ chars, symbols, numbers)")

    if not rec:
        rec.append("System is secure 👍")

    return rec