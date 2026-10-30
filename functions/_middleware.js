const COOKIE_NAME = "kiro_access";
const SESSION_DURATION = 12 * 60 * 60;

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hmac(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))
  );
}

async function verifyPassword(input, expected) {
  const encoder = new TextEncoder();
  const a = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(input)));
  const b = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(expected)));

  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  if (!match) return false;

  try {
    const [time, signature] = match[1].split(".");
    const issued = Number(time);
    const now = Math.floor(Date.now() / 1000);

    if (!Number.isSafeInteger(issued) || now < issued || now - issued > SESSION_DURATION) {
      return false;
    }

    const expected = await hmac(time, secret);
    const supplied = fromBase64url(signature);

    if (expected.length !== supplied.length) return false;

    let difference = 0;
    for (let i = 0; i < expected.length; i++) difference |= expected[i] ^ supplied[i];

    return difference === 0;
  } catch {
    return false;
  }
}

function loginPage(message = "") {
  const safeMessage = message.replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);

  return new Response(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#030712">
<title>Kiro — Acceso privado</title>

<style>
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  font-family: 'Segoe UI', Roboto, Arial, sans-serif;
}

body {
  background: #030712;
  color: #f3f4f6;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 18px;
  overflow-x: hidden;
}

#neural-canvas {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  z-index: 1;
}

.hud-container {
  position: relative;
  z-index: 2;
  width: 100%;
  max-width: 850px;
  min-height: 440px;
  background: rgba(13, 17, 23, .88);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(0, 255, 255, .25);
  border-radius: 16px;
  box-shadow: 0 0 35px rgba(0, 255, 255, .15),
              inset 0 0 20px rgba(0, 255, 255, .05);
  overflow: hidden;
}

.hud-header {
  padding: 17px 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  border-bottom: 1px solid rgba(0, 255, 255, .15);
  background: rgba(0, 0, 0, .3);
}

.server-title {
  font-size: 1.4rem;
  font-weight: 800;
  letter-spacing: 2px;
  color: #fff;
  text-shadow: 0 0 10px rgba(0, 255, 255, .6);
}

.server-title span {
  color: #00ffff;
}

.hud-status {
  display: flex;
  align-items: center;
  gap: 9px;
  color: #9ca3af;
  font-size: .75rem;
}

.status-dot {
  width: 8px;
  height: 8px;
  background: #10b981;
  border-radius: 50%;
  box-shadow: 0 0 8px #10b981;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  50% { opacity: .35; }
}

.hud-body {
  display: flex;
  min-height: 390px;
}

.hud-sidebar {
  width: 35%;
  padding: 28px 24px;
  border-right: 1px solid rgba(0, 255, 255, .1);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  background: rgba(0, 255, 255, .02);
}

.sidebar-info h3 {
  color: #00ffff;
  font-size: .9rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  margin-bottom: 12px;
}

.sidebar-info p {
  color: #9ca3af;
  font-size: .85rem;
  line-height: 1.6;
}

.audio-toggle {
  width: fit-content;
  background: rgba(0, 255, 255, .05);
  border: 1px solid rgba(0, 255, 255, .3);
  color: #00ffff;
  padding: 9px 12px;
  border-radius: 6px;
  cursor: pointer;
}

.hud-content {
  width: 65%;
  padding: 30px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.access-title {
  color: #00ffff;
  font-size: .9rem;
  letter-spacing: 1.5px;
  margin-bottom: 24px;
  text-transform: uppercase;
}

.input-group {
  display: flex;
  flex-direction: column;
  gap: 9px;
}

.input-group label {
  color: #00ffff;
  font-size: .75rem;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
}

.input-group input {
  width: 100%;
  background: rgba(0, 0, 0, .5);
  border: 1px solid rgba(0, 255, 255, .25);
  border-radius: 8px;
  padding: 14px;
  color: white;
  font-size: 16px;
  outline: none;
}

.input-group input:focus {
  border-color: #00ffff;
  box-shadow: 0 0 12px rgba(0, 255, 255, .3);
}

.btn-submit {
  width: 100%;
  background: linear-gradient(135deg, #00ffff, #9900ff);
  border: none;
  border-radius: 8px;
  padding: 14px;
  margin-top: 20px;
  color: #030712;
  font-weight: 800;
  font-size: .9rem;
  letter-spacing: 1.5px;
  cursor: pointer;
  box-shadow: 0 0 20px rgba(0, 255, 255, .25);
}

.btn-submit:active {
  transform: scale(.98);
}

.status-terminal {
  margin-top: 28px;
  font-size: .75rem;
  color: #10b981;
  background: rgba(0, 0, 0, .5);
  padding: 10px 12px;
  border-radius: 6px;
  border-left: 3px solid #10b981;
  font-family: monospace;
  line-height: 1.5;
}

.error {
  color: #ef4444;
  border-left-color: #ef4444;
}

.footer {
  margin-top: 18px;
  text-align: center;
  color: #6b7280;
  font-size: .7rem;
  letter-spacing: 1px;
}

@media(max-width: 600px) {
  body {
    padding: 12px;
  }

  .hud-container {
    max-width: 430px;
    min-height: 0;
  }

  .hud-header {
    padding: 15px;
  }

  .server-title {
    font-size: 1.15rem;
  }

  .hud-status {
    font-size: .6rem;
  }

  .hud-body {
    flex-direction: column;
  }

  .hud-sidebar,
  .hud-content {
    width: 100%;
  }

  .hud-sidebar {
    border-right: none;
    border-bottom: 1px solid rgba(0, 255, 255, .1);
    padding: 20px;
    gap: 18px;
  }

  .hud-sidebar p {
    max-width: 330px;
  }

  .hud-content {
    padding: 24px 20px;
  }
}
</style>
</head>

<body>

<canvas id="neural-canvas"></canvas>

<main class="hud-container">

  <header class="hud-header">
    <div class="server-title">KIRO <span>🐱</span></div>

    <div class="hud-status">
      <div class="status-dot"></div>
      <span>RED PRIVADA // ONLINE</span>
    </div>
  </header>

  <section class="hud-body">

    <aside class="hud-sidebar">
      <div class="sidebar-info">
        <h3>Terminal de acceso</h3>
        <p>
          Bienvenido al centro de información de Kiro.
          Introduce la contraseña compartida para acceder
          a la documentación privada.
        </p>
      </div>

      <button class="audio-toggle" id="audioToggle" type="button">
        🔊 AUDIO: ON
      </button>
    </aside>

    <section class="hud-content">

      <div class="access-title">
        IDENTIFICACIÓN DE ACCESO
      </div>

      <form method="POST" action="/__kiro_login" id="loginForm">

        <div class="input-group">
          <label for="password">Contraseña compartida</label>

          <input
            type="password"
            id="password"
            name="password"
            placeholder="Introduce la contraseña..."
            required
            autocomplete="current-password"
            autofocus
          >
        </div>

        <button class="btn-submit" type="submit">
          ACCEDER A KIRO
        </button>

      </form>

      <div class="status-terminal ${safeMessage ? "error" : ""}" id="statusLog" role="status">
        ${safeMessage ? "> ERROR: " + safeMessage : "> Estado: Sistema operativo y listo para conexión."}
      </div>

      <div class="footer">
        KIRO PRIVATE NETWORK · ACCESO RESTRINGIDO
      </div>

    </section>
  </section>
</main>

<script>
let audioEnabled = true;
let audioCtx = null;

function playClick() {
  if (!audioEnabled) return;

  try {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }

    if (audioCtx.state === "suspended") audioCtx.resume();

    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(800, audioCtx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(400, audioCtx.currentTime + .08);

    gain.gain.setValueAtTime(.08, audioCtx.currentTime);
    gain.gain.linearRampToValueAtTime(.01, audioCtx.currentTime + .08);

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.start();
    osc.stop(audioCtx.currentTime + .08);
  } catch (e) {}
}

const audioButton = document.getElementById("audioToggle");

audioButton.addEventListener("click", () => {
  audioEnabled = !audioEnabled;
  audioButton.textContent = audioEnabled ? "🔊 AUDIO: ON" : "🔇 AUDIO: OFF";
  playClick();
});

document.getElementById("loginForm").addEventListener("submit", () => {
  playClick();

  const status = document.getElementById("statusLog");
  status.classList.remove("error");
  status.textContent = "> Estableciendo conexión segura con Kiro...";
});

// Fondo animado de partículas
const canvas = document.getElementById("neural-canvas");
const ctx = canvas.getContext("2d");

let particles = [];

function resizeCanvas() {
  const ratio = Math.min(window.devicePixelRatio || 1, 2);

  canvas.width = window.innerWidth * ratio;
  canvas.height = window.innerHeight * ratio;

  canvas.style.width = window.innerWidth + "px";
  canvas.style.height = window.innerHeight + "px";

  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
}

window.addEventListener("resize", resizeCanvas);
resizeCanvas();

for (let i = 0; i < 40; i++) {
  particles.push({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    vx: (Math.random() - .5) * .5,
    vy: (Math.random() - .5) * .5,
    radius: Math.random() * 1.5 + 1
  });
}

function animateCanvas() {
  ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

  ctx.fillStyle = "rgba(0,255,255,.4)";
  ctx.strokeStyle = "rgba(0,255,255,.08)";

  particles.forEach((p, index) => {
    p.x += p.vx;
    p.y += p.vy;

    if (p.x < 0 || p.x > window.innerWidth) p.vx *= -1;
    if (p.y < 0 || p.y > window.innerHeight) p.vy *= -1;

    ctx.beginPath();
    ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
    ctx.fill();

    for (let j = index + 1; j < particles.length; j++) {
      const p2 = particles[j];
      const dist = Math.hypot(p.x - p2.x, p.y - p2.y);

      if (dist < 120) {
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      }
    }
  });

  requestAnimationFrame(animateCanvas);
}

animateCanvas();
</script>

</body>
</html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const password = env.KIRO_PASSWORD;
  const secret = env.KIRO_SESSION_SECRET;

  if (!password || !secret) {
    return new Response("El acceso privado aún no está configurado.", { status: 503 });
  }

  const url = new URL(request.url);

  if (url.pathname === "/__kiro_login" && request.method === "POST") {
    const form = await request.formData();
    const supplied = String(form.get("password") || "");

    if (await verifyPassword(supplied, password)) {
      const issued = String(Math.floor(Date.now() / 1000));
      const signature = base64url(await hmac(issued, secret));

      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/",
          "Set-Cookie": `${COOKIE_NAME}=${issued}.${signature}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DURATION}`,
          "Cache-Control": "no-store"
        }
      });
    }

    return loginPage("Contraseña incorrecta. Inténtalo de nuevo.");
  }

  if (url.pathname === "/__kiro_logout") {
    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (await validSession(request, secret)) {
    return next();
  }

  return loginPage();
}
