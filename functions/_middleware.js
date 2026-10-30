
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
    ["sign", "verify"]
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
  return new Response(`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kiro — Acceso privado</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080b14;color:#e5e7eb;font-family:Arial,sans-serif;padding:20px}
main{width:100%;max-width:390px;background:#111827;border:1px solid #263449;border-radius:18px;padding:28px;box-shadow:0 20px 60px #0008}
h1{color:#60a5fa;text-align:center;margin:0 0 8px}p{text-align:center;color:#9ca3af}
input,button{width:100%;padding:14px;border-radius:10px;font-size:16px;margin-top:14px}
input{background:#080b14;border:1px solid #374151;color:white}
button{background:#22c55e;color:#052e16;font-weight:bold;border:0}
.error{color:#fca5a5;font-size:14px}
</style>
</head>
<body><main>
<h1>Kiro 🐱</h1>
<p>Acceso privado a la documentación</p>
<form method="POST" action="/__kiro_login">
<input type="password" name="password" placeholder="Contraseña de acceso" required autocomplete="current-password">
<button type="submit">ACCEDER</button>
</form>
<p class="error">${message}</p>
</main></body></html>`, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
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
