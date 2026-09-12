// Reflexión de parámetros (indicador de XSS) SIN explotación: mandamos un
// marcador único con los caracteres que un contexto HTML DEBE escapar
// (< > " '), y miramos si vuelven crudos en una respuesta HTML. No inyecta
// <script>, no ejecuta nada: solo detecta que el input se refleja sin escapar,
// que es la condición necesaria de un XSS reflejado. Confirmar a mano.
export async function checkReflection(ctx) {
  const { domain, findings, request } = ctx; const C = "reflexión-xss";
  const marker = "zqx" + Math.random().toString(36).slice(2, 8);
  const probe = `${marker}<x">'`; // los 4 chars peligrosos + marcador
  const params = ["q", "s", "search", "query", "name", "message", "error", "msg", "redirect", "lang", "page", "id", "ref", "callback"];
  const found = [];
  for (const p of params) {
    const res = await request(`https://${domain}/?${p}=${encodeURIComponent(probe)}`, { method: "GET" });
    if (!res.ok || res.bytes === 0) continue;
    const ct = res.headers.get("content-type") || "";
    if (!/text\/html/.test(ct)) continue;
    // ¿vuelve el marcador con < o " sin escapar? (si viniera como &lt; está bien escapado)
    const raw = res.body.includes(`${marker}<x`) || res.body.includes(`${marker}<`);
    const rawQuote = res.body.includes(`${marker}<x">`);
    if (raw || rawQuote) { found.push(p); if (found.length >= 3) break; }
  }
  if (found.length) {
    findings.add(C, { id: "XSS-REFLECTION", severity: "high", title: `Parámetro reflejado sin escapar en HTML (posible XSS): ?${found.join(", ?")}`,
      evidence: `El marcador con caracteres < > " ' se devolvió crudo en la respuesta HTML (parámetros: ${found.join(", ")}). No se inyectó ningún script.`,
      why: "Si el input del usuario llega al HTML sin escaparse, un atacante puede inyectar <script> y ejecutar código en el navegador de tus usuarios (robo de sesión, acciones en su nombre). Es la condición base del XSS reflejado.",
      fix: "Escapa/encodea toda salida según su contexto (HTML, atributo, JS). En frameworks modernos usa el binding por defecto (no dangerouslySetInnerHTML/v-html/|safe). Y una CSP sin 'unsafe-inline' como red de seguridad." });
  } else findings.pass(C, `Sin reflexión sin escapar en ${params.length} parámetros probados`);
}
