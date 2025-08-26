const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");
let packetAnimations = [];

function sendAction(action, x = 0, y = 0) {
    fetch("/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, x, y })
    }).then(response => response.json()).then(data => console.log(data));
}

function sendSocialEngClick(clicked) {
    fetch("/social_eng", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clicked })
    }).then(response => response.json()).then(data => console.log(data));
}

function draw() {
    fetch("/update").then(response => response.json()).then(data => {
        ctx.fillStyle = "green";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        if (data.phishing) {
            window.location.href = "/login";
            return;
        }

        if (data.takeover) {
            ctx.fillStyle = "black";
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = "white";
            ctx.font = "24px Arial";
            ctx.fillText("Ant-Man Takeover! Sistem Terinfeksi!", 100, canvas.height / 2);
            ctx.fillRect(canvas.width / 2 - 50, canvas.height / 2 + 50, 100, 100);
            for (let i = 0; i < 20; i++) {
                let x = canvas.width / 2 - 50 + Math.random() * 100;
                let y = canvas.height / 2 + 50 + Math.random() * 100;
                ctx.fillStyle = "black";
                ctx.fillRect(x, y, 5, 5);
            }
            let reports = ["keylog.txt", "bug_report.json", "scan_report.json", "exploit_report.json", "packet_report.json", "crack_report.json", "kingant_report.json", "socialeng_report.json"];
            ctx.fillStyle = "white";
            ctx.font = "16px Arial";
            reports.forEach((report, i) => {
                ctx.fillText(`Download ${report}: /download/${report}`, 10, canvas.height - 120 + i * 20);
            });
            if (data.ant_men.some(t => t.keylog.length > 0)) {
                ctx.fillText("Keylog: " + data.ant_men[0].keylog.slice(-5).join(", "), 10, canvas.height - 50);
            }
            if (data.ant_men.some(t => t.vuln_found)) {
                ctx.fillText("Kerentanan Ditemukan: " + data.ant_men.filter(t => t.vuln_found).length, 10, canvas.height - 80);
            }
            return;
        }

        // Social engineering pop-up (Fitur 6)
        if (data.social_eng_triggered) {
            ctx.fillStyle = "rgba(0, 0, 0, 0.8)";
            ctx.fillRect(200, 400, 320, 200);
            ctx.fillStyle = "white";
            ctx.font = "20px Arial";
            ctx.fillText("Peringatan: Email Mencurigakan!", 220, 450);
            ctx.fillText("Klik untuk melihat detail", 220, 480);
            canvas.onclick = e => {
                let rect = canvas.getBoundingClientRect();
                let x = e.clientX - rect.left;
                let y = e.clientY - rect.top;
                if (x >= 200 && x <= 520 && y >= 400 && y <= 600) {
                    sendSocialEngClick(true);
                    canvas.onclick = e => {
                        let rect = canvas.getBoundingClientRect();
                        let x = e.clientX - rect.left;
                        let y = e.clientY - rect.top;
                        sendAction("spawn", x, y);
                    };
                }
            };
        } else {
            canvas.onclick = e => {
                let rect = canvas.getBoundingClientRect();
                let x = e.clientX - rect.left;
                let y = e.clientY - rect.top;
                sendAction("spawn", x, y);
            };
        }

        data.toxic_zones.forEach(zone => {
            ctx.strokeStyle = "red";
            ctx.beginPath();
            ctx.arc(zone.x, zone.y, zone.size, 0, Math.PI * 2);
            ctx.stroke();
        });

        data.foods.forEach(food => {
            ctx.fillStyle = food.toxic ? "rgb(200, 0, 0)" : "rgb(0, 150, 0)";
            ctx.beginPath();
            ctx.arc(food.x, food.y, food.size || 5, 0, Math.PI * 2);
            ctx.fill();
        });

        // Animasi packet sniffing (Fitur 3)
        data.ant_men.forEach(t => {
            if (t.packet_capture.length > 0 && t.rebel) {
                let nearest_zone = data.toxic_zones.reduce((min, zone) => {
                    let dist = ((zone.x - t.x)**2 + (zone.y - t.y)**2)**0.5;
                    return dist < min.dist ? {zone, dist} : min;
                }, {zone: null, dist: Infinity}).zone;
                if (nearest_zone) {
                    packetAnimations.push({
                        x1: t.x,
                        y1: t.y,
                        x2: nearest_zone.x,
                        y2: nearest_zone.y,
                        progress: 0
                    });
                }
            }
        });

        packetAnimations = packetAnimations.filter(anim => anim.progress < 1);
        packetAnimations.forEach(anim => {
            anim.progress += 0.05;
            let x = anim.x1 + (anim.x2 - anim.x1) * anim.progress;
            let y = anim.y1 + (anim.y2 - anim.y1) * anim.progress;
            ctx.strokeStyle = "cyan";
            ctx.beginPath();
            ctx.moveTo(anim.x1, anim.y1);
            ctx.lineTo(x, y);
            ctx.stroke();
        });

        data.ant_men.forEach(t => {
            ctx.fillStyle = t.is_king ? "gold" : (t.rebel ? (t.hidden ? "gray" : "purple") : (t.evolved ? "orange" : "yellow"));
            ctx.beginPath();
            ctx.arc(t.x, t.y, t.size, 0, Math.PI * 2);
            ctx.fill();
            ctx.fillStyle = "blue";
            ctx.fillRect(t.x - t.size / 2, t.y + t.size / 2, t.size, t.size / 2);
            ctx.fillStyle = "black";
            ctx.beginPath();
            ctx.arc(t.x - 5, t.y - 5, 3, 0, Math.PI * 2);
            ctx.fill();
            ctx.beginPath();
            ctx.arc(t.x + 5, t.y - 5, 3, 0, Math.PI * 2);
            ctx.fill();
            if (t.hunger < 30 && !t.is_king) {
                ctx.fillStyle = "red";
                ctx.beginPath();
                ctx.arc(t.x, t.y - t.size - 5, 5, 0, Math.PI * 2);
                ctx.fill();
            }
            if (t.vuln_found) {
                ctx.fillStyle = "white";
                ctx.font = "12px Arial";
                ctx.fillText(t.vuln_found, t.x - t.size, t.y - t.size - 10);
            }
            if (t.is_king) {
                ctx.fillStyle = "white";
                ctx.font = "14px Arial";
                ctx.fillText(`KingAnt: ${t.status}`, t.x - t.size, t.y - t.size - 25);
            }
        });

        data.ant_men.forEach((t1, i) => {
            data.ant_men.slice(i + 1).forEach(t2 => {
                if (((t1.x - t2.x)**2 + (t1.y - t2.y)**2)**0.5 < 50 && !t1.rebel && !t2.rebel) {
                    ctx.strokeStyle = t1.is_king || t2.is_king ? "gold" : "white";
                    ctx.beginPath();
                    ctx.moveTo(t1.x, t1.y);
                    ctx.lineTo(t2.x, t2.y);
                    ctx.stroke();
                }
            });
        });

        let stats = `Ant-Man: ${data.ant_men.length} | Rebel: ${data.ant_men.filter(t => t.rebel).length} | Hidden: ${data.ant_men.filter(t => t.hidden).length} | Kerentanan: ${data.ant_men.filter(t => t.vuln_found).length} | Makanan: ${data.foods.length} | Rata-rata: H:${Math.round(data.ant_men.filter(t => !t.is_king).reduce((s, t) => s + t.hunger, 0) / (data.ant_men.length - 1 || 1))} Hap:${Math.round(data.ant_men.filter(t => !t.is_king).reduce((s, t) => s + t.happiness, 0) / (data.ant_men.length - 1 || 1))} E:${Math.round(data.ant_men.filter(t => !t.is_king).reduce((s, t) => s + t.energy, 0) / (data.ant_men.length - 1 || 1))}`;
        document.getElementById("stats").innerText = stats;
    }).catch(err => console.error("Error fetching update:", err));

    requestAnimationFrame(draw);
}

canvas.addEventListener("click", e => {
    let rect = canvas.getBoundingClientRect();
    let x = e.clientX - rect.left;
    let y = e.clientY - rect.top;
    sendAction("spawn", x, y);
});

draw();