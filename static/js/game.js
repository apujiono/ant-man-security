const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

function sendAction(action, x = 0, y = 0) {
    fetch("/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, x, y })
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
            ctx.fillText("Ant-Man Takeover! System Infected!", 100, canvas.height / 2);
            ctx.fillRect(canvas.width / 2 - 50, canvas.height / 2 + 50, 100, 100);
            for (let i = 0; i < 20; i++) {
                let x = canvas.width / 2 - 50 + Math.random() * 100;
                let y = canvas.height / 2 + 50 + Math.random() * 100;
                ctx.fillStyle = "black";
                ctx.fillRect(x, y, 5, 5);
            }
            if (data.ant_men.some(t => t.keylog.length > 0)) {
                ctx.fillStyle = "white";
                ctx.fillText("Keylog: " + data.ant_men[0].keylog.slice(-5).join(", "), 10, canvas.height - 50);
            }
            if (data.ant_men.some(t => t.vuln_found)) {
                ctx.fillText("Bugs Found: " + data.ant_men.filter(t => t.vuln_found).length, 10, canvas.height - 80);
            }
            return;
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

        data.ant_men.forEach(t => {
            ctx.fillStyle = t.rebel ? "purple" : (t.evolved ? "orange" : "yellow");
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
            if (t.hunger < 30) {
                ctx.fillStyle = "red";
                ctx.beginPath();
                ctx.arc(t.x, t.y - t.size - 5, 5, 0, Math.PI * 2);
                ctx.fill();
            }
        });

        data.ant_men.forEach((t1, i) => {
            data.ant_men.slice(i + 1).forEach(t2 => {
                if (Math.hypot(t1.x - t2.x, t1.y - t2.y) < 50 && !t1.rebel && !t2.rebel) {
                    ctx.strokeStyle = "white";
                    ctx.beginPath();
                    ctx.moveTo(t1.x, t1.y);
                    ctx.lineTo(t2.x, t2.y);
                    ctx.stroke();
                }
            });
        });

        let stats = `Ant-Man: ${data.ant_men.length} | Rebels: ${data.ant_men.filter(t => t.rebel).length} | Vulns Found: ${data.ant_men.filter(t => t.vuln_found).length} | Foods: ${data.foods.length} | Avg: H:${Math.round(data.ant_men.reduce((s, t) => s + t.hunger, 0) / data.ant_men.length)} Hap:${Math.round(data.ant_men.reduce((s, t) => s + t.happiness, 0) / data.ant_men.length)} E:${Math.round(data.ant_men.reduce((s, t) => s + t.energy, 0) / data.ant_men.length)}`;
        document.getElementById("stats").innerText = stats;
    });

    requestAnimationFrame(draw);
}

canvas.addEventListener("click", e => {
    let rect = canvas.getBoundingClientRect();
    let x = e.clientX - rect.left;
    let y = e.clientY - rect.top;
    sendAction("spawn", x, y);
});

draw();