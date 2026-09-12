// CORS y cookies: dos fallos que se detectan sin explotar nada, solo leyendo
// la respuesta a una petición con Origin falso.
export async function checkCorsCookies(ctx) {
  const { domain, findings, request } = ctx; const C = "cors-cookies";
  const evil = "https://evil-checkup.example";

  // CORS: pedimos con un Origin atacante y miramos qué nos deja hacer.
  const api = ctx.apiBase || `https://${domain}/`;
  const pre = await request(api, { method: "OPTIONS", headers: { origin: evil, "access-control-request-method": "GET" } });
  const acao = pre.headers.get("access-control-allow-origin");
  const acac = pre.headers.get("access-control-allow-credentials");
  if (acao === "*" && /true/i.test(acac || "")) {
    findings.add(C, { id: "CORS-STAR-CREDS", severity: "high", title: "CORS con '*' y credenciales", evidence: `ACAO: * · ACAC: true en ${api}`, why: "Combinación inválida que algunos navegadores/servidores aún aceptan: cualquier web leería respuestas autenticadas del usuario.", fix: "Nunca '*' con credentials. Refleja solo orígenes de una allowlist." });
  } else if (acao && (acao === evil || acao === "null")) {
    findings.add(C, { id: "CORS-REFLECT", severity: /true/i.test(acac || "") ? "high" : "medium", title: "CORS refleja cualquier Origin", evidence: `Enviado Origin: ${evil} → ACAO: ${acao}${acac ? " · ACAC: " + acac : ""}`, why: "El servidor devuelve el Origin que le mandes: una web atacante puede leer respuestas de tu API" + (/true/i.test(acac || "") ? ", incluidas las autenticadas del usuario." : "."), fix: "Valida el Origin contra una lista cerrada; si no está, no pongas ACAO." });
  } else findings.pass(C, "CORS no refleja orígenes arbitrarios");

  // Cookies: banderas de sesión. Solo miramos Set-Cookie de la home.
  const raw = ctx.home.headers.getSetCookie?.() || [];
  const sessionish = raw.filter((c) => /sess|sid|token|auth|jwt|csrf/i.test(c.split("=")[0]));
  for (const c of sessionish) {
    const name = c.split("=")[0]; const flags = c.toLowerCase();
    const missing = [];
    if (!/;\s*secure/.test(flags)) missing.push("Secure");
    if (!/;\s*httponly/.test(flags) && !/csrf/i.test(name)) missing.push("HttpOnly");
    if (!/;\s*samesite/.test(flags)) missing.push("SameSite");
    if (missing.length) findings.add(C, { id: "COOKIE-FLAGS", severity: missing.includes("HttpOnly") ? "high" : "medium", title: `Cookie '${name}' sin ${missing.join("/")}`, evidence: c.split(";")[0] + "; …", why: (missing.includes("HttpOnly") ? "Sin HttpOnly, un XSS lee la cookie de sesión directamente. " : "") + (missing.includes("Secure") ? "Sin Secure viaja en http. " : "") + (missing.includes("SameSite") ? "Sin SameSite queda expuesta a CSRF." : ""), fix: `Marca la cookie ${name} con ${missing.join(", ")} (SameSite=Lax o Strict).` });
  }
  if (sessionish.length && !findings.items.some((f) => f.id === "COOKIE-FLAGS")) findings.pass(C, "Cookies de sesión con flags correctas");
  if (!sessionish.length) findings.skip(C, "Flags de cookies", "la home no pone cookies de sesión (probablemente se ponen tras login)");
}
