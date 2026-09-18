// CORS y cookies: dos fallos que se detectan sin explotar nada, solo leyendo
// la respuesta a una petición con Origin falso.
import { curl } from "../findings.mjs";
export async function checkCorsCookies(ctx) {
  const { domain, findings, request } = ctx; const C = "cors-cookies";
  const evil = "https://evil-checkup.example";

  // CORS: pedimos con un Origin atacante y miramos qué nos deja hacer.
  const api = ctx.apiBase || `https://${domain}/`;
  const pre = await request(api, { method: "OPTIONS", headers: { origin: evil, "access-control-request-method": "GET" } });
  const acao = pre.headers.get("access-control-allow-origin");
  const acac = pre.headers.get("access-control-allow-credentials");
  if (acao === "*" && /true/i.test(acac || "")) {
    findings.add(C, { id: "CORS-STAR-CREDS", status: "hardening", priority: "medium", repro: curl(api, { method: "OPTIONS", headers: { Origin: evil, "Access-Control-Request-Method": "GET" } }), title: "CORS con '*' y credenciales", evidence: `ACAO: * · ACAC: true en ${api}`, why: "Los navegadores rechazan esta combinación, así que hoy no es explotable tal cual; pero delata una configuración CORS que alguien intentó abrir de más y que un cambio pequeño convierte en reflejo con credenciales.", fix: "Nunca '*' con credentials. Refleja solo orígenes de una allowlist." });
  } else if (acao && (acao === evil || acao === "null")) {
    findings.add(C, { id: "CORS-REFLECT", ...(/true/i.test(acac || "") ? { status: "needs_validation", unresolved: `¿${api} u otra ruta con la misma política devuelve datos del usuario autenticado? Si sí, cualquier web los lee: es un hallazgo alto.` } : { status: "hardening", priority: "medium" }), repro: curl(api, { method: "OPTIONS", headers: { Origin: evil, "Access-Control-Request-Method": "GET" } }), title: "CORS refleja cualquier Origin", evidence: `Enviado Origin: ${evil} → ACAO: ${acao}${acac ? " · ACAC: " + acac : ""}`, why: "El servidor devuelve el Origin que le mandes: una web atacante puede leer respuestas de tu API" + (/true/i.test(acac || "") ? ", incluidas las autenticadas del usuario." : "."), fix: "Valida el Origin contra una lista cerrada; si no está, no pongas ACAO." });
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
    if (missing.length) findings.add(C, { id: "COOKIE-FLAGS", status: "hardening", priority: missing.includes("HttpOnly") || missing.includes("Secure") ? "high" : "medium", repro: curl(`https://${domain}/`), title: `Cookie '${name}' sin ${missing.join("/")}`, evidence: c.split(";")[0] + "; …", why: (missing.includes("HttpOnly") ? "Sin HttpOnly, un XSS lee la cookie de sesión directamente. " : "") + (missing.includes("Secure") ? "Sin Secure viaja en http. " : "") + (missing.includes("SameSite") ? "Sin SameSite queda expuesta a CSRF." : ""), fix: `Marca la cookie ${name} con ${missing.join(", ")} (SameSite=Lax o Strict).` });
  }
  if (sessionish.length && !findings.items.some((f) => f.id === "COOKIE-FLAGS")) findings.pass(C, "Cookies de sesión con flags correctas");
  // Una respuesta que pone cookie de sesión y es cacheable por el CDN puede
  // servir la cookie de un usuario a otro. Solo se ve si hay cookie en la home.
  const cc = (ctx.home.headers.get("cache-control") || "").toLowerCase();
  if (sessionish.length && !/private|no-store/.test(cc) && (/public|s-maxage|max-age=[1-9]/.test(cc) || !cc)) {
    findings.add(C, { id: "CACHE-SET-COOKIE", status: "needs_validation", title: "Respuesta con cookie de sesión que el CDN podría cachear",
      evidence: `Set-Cookie: ${sessionish.map((c) => c.split("=")[0]).join(", ")} · Cache-Control: ${cc || "(ausente)"}`, repro: curl(`https://${domain}/`),
      unresolved: "¿Tu CDN guarda en caché esta respuesta? Pídela dos veces desde navegadores distintos: si la segunda trae la misma cookie (o cf-cache-status / x-vercel-cache: HIT), un usuario recibe la sesión de otro.",
      why: "Si el borde cachea una respuesta con Set-Cookie, sirve la misma sesión a todos los que la pidan después.",
      fix: "Cache-Control: private, no-store en toda respuesta que ponga cookies de sesión, y excluye esas rutas de las reglas de caché del CDN." });
  }
  if (!sessionish.length) findings.skip(C, "Flags de cookies", "la home no pone cookies de sesión (probablemente se ponen tras login)");
}
