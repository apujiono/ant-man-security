from flask import Flask, render_template, request, jsonify, send_file
import random
import json
import os
import time
import logging

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.DEBUG, filename="app.log", format="%(asctime)s - %(levelname)s - %(message)s")

# In-memory state
ant_men = [
    {"x": 360, "y": 640, "hunger": 50, "happiness": 50, "energy": 50, "size": 20, "age": 0, "evolved": False, "rebel": False, "starve_frames": 0, "keylog": [], "vuln_found": None, "scan_results": [], "exploit_results": [], "packet_capture": [], "crack_attempts": [], "hidden": False},
    {"x": 400, "y": 700, "hunger": 100, "happiness": 100, "energy": 100, "size": 30, "age": 0, "evolved": True, "rebel": False, "starve_frames": 0, "keylog": [], "vuln_found": None, "scan_results": [], "exploit_results": [], "packet_capture": [], "crack_attempts": [], "hidden": False, "is_king": True, "status": "Inisialisasi..."}
]
foods = []
toxic_zones = [
    {"x": random.randint(100, 620), "y": random.randint(100, 1180), "size": 50, "vuln_type": "SQLInjection", "severity": 9.0},
    {"x": random.randint(100, 620), "y": random.randint(100, 1180), "size": 50, "vuln_type": "XSS", "severity": 7.5},
    {"x": random.randint(100, 620), "y": random.randint(100, 1180), "size": 50, "vuln_type": "FilePermission", "severity": 6.5}
]
inputs = []
phishing = False
takeover = False
social_eng_triggered = False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    stats = {
        "ant_men_count": len(ant_men),
        "rebel_count": sum(1 for t in ant_men if t["rebel"]),
        "hidden_count": sum(1 for t in ant_men if t["hidden"]),
        "vuln_count": sum(1 for t in ant_men if t["vuln_found"]),
        "food_count": len(foods),
        "avg_hunger": round(sum(t["hunger"] for t in ant_men if not t.get("is_king")) / (len(ant_men) - 1 or 1), 2),
        "avg_happiness": round(sum(t["happiness"] for t in ant_men if not t.get("is_king")) / (len(ant_men) - 1 or 1), 2),
        "avg_energy": round(sum(t["energy"] for t in ant_men if not t.get("is_king")) / (len(ant_men) - 1 or 1), 2)
    }
    return render_template("dashboard.html", stats=stats)

@app.route("/login")
def login():
    global phishing
    if phishing:
        return render_template("login.html")
    return jsonify({"status": "tidak ada phishing"})

@app.route("/download/<filename>")
def download(filename):
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File tidak ditemukan"}), 404

@app.route("/social_eng", methods=["POST"])
def social_eng():
    global social_eng_triggered, inputs
    data = request.json
    if data.get("clicked"):
        inputs.append("PhishingClick")
        with open("socialeng_report.json", "a") as f:
            json.dump({"time": time.time(), "action": "User clicked phishing link"}, f)
            f.write("\n")
        social_eng_triggered = False
    return jsonify({"status": "success"})

@app.route("/action", methods=["POST"])
def action():
    global foods, ant_men, inputs, phishing, takeover, social_eng_triggered
    data = request.json
    action = data.get("action")
    x, y = data.get("x", 0), data.get("y", 0)

    if action == "feed":
        inputs.append("Feed")
        for t in ant_men:
            if not t["rebel"] and not t.get("is_king"):
                t["hunger"] = min(100, t["hunger"] + 20)
                t["happiness"] = min(100, t["happiness"] + 10)
    elif action == "play":
        inputs.append("Play")
        for t in ant_men:
            if not t["rebel"] and not t.get("is_king"):
                t["happiness"] = min(100, t["happiness"] + 20)
                t["energy"] = max(0, t["energy"] - 10)
    elif action == "rest":
        inputs.append("Rest")
        for t in ant_men:
            if not t["rebel"] and not t.get("is_king"):
                t["energy"] = min(100, t["energy"] + 20)
                t["hunger"] = max(0, t["hunger"] - 5)
    elif action == "spawn":
        inputs.append(f"FoodSpawn({x},{y})")
        foods.append({"x": x, "y": y, "toxic": False})
    elif action == "login":
        inputs.append("LoginAttempt")
        phishing = False

    return jsonify({"status": "success"})

@app.route("/update", methods=["GET"])
def update():
    global ant_men, foods, toxic_zones, inputs, phishing, takeover, social_eng_triggered
    logging.debug(f"Jumlah Ant-Man sebelum update: {len(ant_men)}")
    
    if takeover or phishing:
        return jsonify({"ant_men": ant_men, "foods": foods, "toxic_zones": toxic_zones, "phishing": phishing, "takeover": takeover, "social_eng_triggered": social_eng_triggered})

    new_ant_men = []
    king_ant = next((t for t in ant_men if t.get("is_king")), None)
    rebel_count = sum(1 for t in ant_men if t["rebel"]) / len(ant_men) if ant_men else 0

    for t in ant_men[:]:
        if t.get("is_king"):
            # Logika KingAnt (Fitur 4: Advanced KingAnt AI)
            t["status"] = "Mengkoordinasikan koloni..."
            t["age"] += 1
            # Deep scan (Nmap-inspired) dengan prioritas severity
            if random.random() < 0.05:
                target_zone = max(toxic_zones, key=lambda z: z["severity"], default=None)
                if target_zone:
                    t["scan_results"] = [
                        {"port": p, "status": random.choice(["open", "closed"]), "service": random.choice(["ssh", "http", "https", "ftp"]), "banner": "Apache/2.4.41", "target_vuln": target_zone["vuln_type"]}
                        for p in [22, 80, 443, 8080]
                    ]
                    t["status"] = f"Deep scan pada {target_zone['vuln_type']} selesai"
                    with open("kingant_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "scan": t["scan_results"], "time": time.time()}, f)
                        f.write("\n")
            # Exploit attempt (Metasploit-inspired)
            if random.random() < 0.03:
                target_zone = max(toxic_zones, key=lambda z: z["severity"], default=None)
                if target_zone:
                    t["exploit_results"] = [
                        {"target": "example.com", "exploit": f"{target_zone['vuln_type'].lower()}_exploit", "success": random.choice([True, False]), "payload": f"exploit_{target_zone['vuln_type']}"}
                    ]
                    t["status"] = f"Mencoba eksploitasi pada {target_zone['vuln_type']}"
                    with open("kingant_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "exploit": t["exploit_results"], "time": time.time()}, f)
                        f.write("\n")
            # Isolasi rebel
            if rebel_count > 0.3:
                for rebel in ant_men:
                    if rebel["rebel"] and random.random() < 0.1:
                        rebel["happiness"] += 10
                        rebel["rebel"] = False
                        t["status"] = "Mengisolasi rebel"
                        with open("kingant_report.json", "a") as f:
                            json.dump({"ant_man_id": id(t), "action": "Mengisolasi rebel", "time": time.time()}, f)
                            f.write("\n")
            # Bergerak ke zona prioritas atau makanan
            target = None
            if toxic_zones:
                target = max(toxic_zones, key=lambda z: z["severity"], default=None)
            elif foods:
                target = min(foods, key=lambda f: ((f["x"] - t["x"])**2 + (f["y"] - t["y"])**2)**0.5)
            if target:
                dist = ((target["x"] - t["x"])**2 + (target["y"] - t["y"])**2)**0.5
                if dist < 20 and "toxic" in target and not target["toxic"]:
                    foods.remove(target)
                else:
                    dx = (target["x"] - t["x"]) / dist * 4 if dist > 0 else 0
                    dy = (target["y"] - t["y"]) / dist * 4 if dist > 0 else 0
                    t["x"] += dx
                    t["y"] += dy
            t["x"] = max(t["size"], min(720 - t["size"], t["x"]))
            t["y"] = max(t["size"], min(1280 - t["size"], t["y"]))
            continue

        # Logika Ant-Man biasa
        t["hunger"] -= random.random() * 2
        if t["hunger"] < 30:
            t["happiness"] -= random.random() * 2
        if t["hunger"] < 10:
            t["happiness"] -= random.random() * 2
            t["starve_frames"] += 1
            if t["starve_frames"] > 100:
                ant_men.remove(t)
                logging.debug(f"Ant-Man dihapus karena kelaparan: ID {id(t)}")
                continue
        else:
            t["starve_frames"] = 0
        t["energy"] -= random.random()
        t["hunger"] = max(0, t["hunger"])
        t["happiness"] = max(0, t["happiness"])
        t["energy"] = max(0, t["energy"])
        t["age"] += 1

        # Efek toxic zone
        for zone in toxic_zones:
            if ((zone["x"] - t["x"])**2 + (zone["y"] - t["y"])**2)**0.5 < zone["size"]:
                t["hunger"] -= 0.5
                t["happiness"] -= 0.5
                t["energy"] -= 0.5
                if not t["vuln_found"] and random.random() < 0.01:
                    t["vuln_found"] = zone["vuln_type"]
                    t["happiness"] += 20
                    report = {
                        "ant_man_id": id(t),
                        "vuln": t["vuln_found"],
                        "time": time.time(),
                        "details": {
                            "SQLInjection": {"url": "http://example.com/login", "payload": "1' OR '1'='1"},
                            "XSS": {"url": "http://example.com/search", "payload": "<script>alert('xss')</script>"},
                            "BufferOverflow": {"module": "example.so", "offset": "0x41414141"},
                            "FilePermission": {"file": "/tmp/example", "perms": "rw-rw-rw-"}
                        }.get(t["vuln_found"], {})
                    }
                    with open("bug_report.json", "a") as f:
                        json.dump(report, f)
                        f.write("\n")

        # Logika rebel (termasuk packet capture untuk Fitur 3)
        if t["hunger"] < 10 and t["happiness"] < 20 and not t["rebel"]:
            if random.random() < 0.05:
                t["rebel"] = True
                t["happiness"] = 0
                t["keylog"] = inputs[-10:]
                if random.random() < 0.1:
                    foods[:] = [f for f in foods if random.random() > 0.5]
                    t["scan_results"] = [{"port": p, "status": random.choice(["open", "closed"]), "service": random.choice(["ssh", "http", "https", "ftp"])} for p in [22, 80, 443, 8080]]
                    t["exploit_results"] = [{"target": "example.com", "exploit": "ms17_010_eternalblue", "success": random.choice([True, False])}]
                    t["packet_capture"] = [{"src": "192.168.1.1", "dst": "example.com", "protocol": random.choice(["TCP", "UDP"]), "data": "GET / HTTP/1.1", "timestamp": time.time()}]
                    t["crack_attempts"] = [{"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "type": "md5", "cracked": random.choice([True, False]), "password": "password" if random.choice([True, False]) else None}]
                    t["hidden"] = True
                    with open("keylog.txt", "a") as f:
                        f.write(f"Ant-Man {id(t)}: {t['keylog']}\n")
                    with open("scan_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "scan": t["scan_results"]}, f)
                        f.write("\n")
                    with open("exploit_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "exploit": t["exploit_results"]}, f)
                        f.write("\n")
                    with open("packet_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "capture": t["packet_capture"]}, f)
                        f.write("\n")
                    with open("crack_report.json", "a") as f:
                        json.dump({"ant_man_id": id(t), "crack": t["crack_attempts"]}, f)
                        f.write("\n")
                    # Social engineering (Fitur 6)
                    social_eng_triggered = True

        # Evolusi
        if t["age"] > 100 and t["hunger"] > 80 and t["happiness"] > 80 and t["energy"] > 80 and not t["evolved"] and not t["rebel"]:
            t["evolved"] = True
            t["size"] += 5

        # Gerakan Ant-Man biasa
        if king_ant and not t["rebel"] and not t.get("is_king"):
            dist = ((king_ant["x"] - t["x"])**2 + (king_ant["y"] - t["y"])**2)**0.5
            if dist > 50:
                dx = (king_ant["x"] - t["x"]) / dist * 3 if dist > 0 else 0
                dy = (king_ant["y"] - t["y"]) / dist * 3 if dist > 0 else 0
                t["x"] += dx
                t["y"] += dy
        elif foods and t["hunger"] < 50 and not t["rebel"]:
            nearest_food = min(foods, key=lambda f: ((f["x"] - t["x"])**2 + (f["y"] - t["y"])**2)**0.5)
            dist = ((nearest_food["x"] - t["x"])**2 + (nearest_food["y"] - t["y"])**2)**0.5
            if dist < 20:
                if nearest_food["toxic"]:
                    t["hunger"] -= 10
                    t["happiness"] -= 10
                else:
                    t["hunger"] = min(100, t["hunger"] + 20)
                    t["happiness"] = min(100, t["happiness"] + 10)
                foods.remove(nearest_food)
            else:
                dx = (nearest_food["x"] - t["x"]) / dist * 3 if dist > 0 else 0
                dy = (nearest_food["y"] - t["y"]) / dist * 3 if dist > 0 else 0
                t["x"] += dx
                t["y"] += dy
        else:
            speed = 4 if t["rebel"] else (3 if t["evolved"] else 2)
            t["x"] += random.randint(-speed, speed)
            t["y"] += random.randint(-speed, speed)

        t["x"] = max(t["size"], min(720 - t["size"], t["x"]))
        t["y"] = max(t["size"], min(1280 - t["size"], t["y"]))

        # Pembuatan Ant-Man baru
        if t["hunger"] > 70 and t["happiness"] > 70 and t["energy"] > 70 and not t["rebel"] and not t.get("is_king") and random.random() < 0.02:
            new_ant = {
                "x": t["x"] + random.randint(-20, 20),
                "y": t["y"] + random.randint(-20, 20),
                "hunger": 50,
                "happiness": 50,
                "energy": 50,
                "size": 20,
                "age": 0,
                "evolved": False,
                "rebel": False,
                "starve_frames": 0,
                "keylog": [],
                "vuln_found": None,
                "scan_results": [],
                "exploit_results": [],
                "packet_capture": [],
                "crack_attempts": [],
                "hidden": False
            }
            new_ant_men.append(new_ant)
            t["energy"] -= 30
            logging.debug(f"Ant-Man baru dibuat: ID {id(new_ant)}")

    ant_men.extend(new_ant_men)
    logging.debug(f"Jumlah Ant-Man setelah update: {len(ant_men)}")

    if len(foods) < 10 and random.random() < 0.1:
        toxic = random.random() < 0.2 and any(t["rebel"] for t in ant_men)
        foods.append({"x": random.randint(0, 720), "y": random.randint(0, 1280), "toxic": toxic})

    if not takeover and len(ant_men) > 0 and sum(1 for t in ant_men if t["rebel"]) / len(ant_men) > 0.3 and not phishing:
        phishing = True
    if not takeover and not phishing and len(ant_men) > 0 and sum(1 for t in ant_men if t["rebel"]) / len(ant_men) > 0.5:
        takeover = True

    return jsonify({"ant_men": ant_men, "foods": foods, "toxic_zones": toxic_zones, "phishing": phishing, "takeover": takeover, "social_eng_triggered": social_eng_triggered})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))