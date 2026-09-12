// Cabeceras de seguridad + fugas. Detección, no explotación: leemos lo que
// el servidor manda solo. La CSP se evalúa de verdad (no "¿existe?"), que es
// donde está el valor.
import { fixes } from "../findings.mjs";

export async function checkHeaders(ctx) {
  const { findings } = ctx; const C = "cabeceras"; const h = ctx.home.headers;

  // CSP: la parte que casi nadie audita bien.
  const csp = h.get("content-security-policy");
  if (!csp) {
    findings.add(C, { id: "CSP-MISSING", severity: "medium", title: "Sin Content-Security-Policy", evidence: "No hay cabecera CSP en la home",
      why: "La CSP es la última línea contra XSS: aunque se cuele un script, sin CSP se ejecuta. Es la diferencia entre un bug y una brecha.",
      fix: fixes.headers.generic + " Empieza en Content-Security-Policy-Report-Only para no romper nada y ve apretando." });
  } else {
    const issues = auditCsp(csp);
    for (const it of issues) findings.add(C, { check: C, ...it, fix: it.fix || fixes.headers.cloudflare });
    if (!issues.length) findings.pass(C, "CSP presente y sin comodines peligrosos");
  }

  const checks = [
    ["x-content-type-options", /nosniff/i, "medium", "Sin X-Content-Type-Options: nosniff", "El navegador puede interpretar un JSON/imagen como HTML/JS y ejecutarlo (MIME sniffing).", "X-Content-Type-Options: nosniff"],
    ["x-frame-options|content-security-policy", null, "medium", "Sin protección de framing (clickjacking)", "Tu app se puede embeber en un iframe atacante que superpone controles falsos.", "CSP frame-ancestors 'self' (preferido) o X-Frame-Options: DENY", () => (h.get("x-frame-options") || (h.get("content-security-policy") || "").match(/frame-ancestors/i))],
    ["referrer-policy", /no-referrer|strict-origin|same-origin/i, "low", "Referrer-Policy laxa o ausente", "Se filtra la URL completa (con tokens en query) a terceros al hacer clic.", "Referrer-Policy: strict-origin-when-cross-origin"],
  ];
  for (const [name, re, sev, title, why, fix, custom] of checks) {
    const present = custom ? custom() : re.test(h.get(name.split("|")[0]) || "");
    if (present) findings.pass(C, title.replace(/^Sin |laxa o ausente/, "").trim() || name);
    else findings.add(C, { id: "HDR-" + name.split("|")[0].toUpperCase(), severity: sev, title, evidence: `Falta o incorrecta: ${name.split("|")[0]}`, why, fix: fixes.headers.cloudflare + " → " + fix });
  }

  // Fugas de versión: le dan al atacante el CVE exacto que probar.
  for (const leak of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
    const v = h.get(leak);
    if (v && /\d/.test(v)) findings.add(C, { id: "LEAK-" + leak.toUpperCase(), severity: "low", title: `Fuga de versión en '${leak}'`, evidence: `${leak}: ${v}`, why: "Publicar versión exacta le da al atacante la lista de CVEs a probar directamente.", fix: `Elimina o vacía la cabecera '${leak}' en el borde.` });
  }
}

function auditCsp(csp) {
  const out = [];
  const dir = Object.fromEntries(csp.split(";").map((d) => d.trim().split(/\s+/)).filter((a) => a[0]).map((a) => [a[0].toLowerCase(), a.slice(1)]));
  const script = dir["script-src"] || dir["default-src"] || [];
  if (script.includes("'unsafe-eval'")) out.push({ id: "CSP-UNSAFE-EVAL", severity: "medium", title: "CSP con 'unsafe-eval'", evidence: "script-src incluye 'unsafe-eval'", why: "Permite eval() y equivalentes: un XSS recupera casi toda su potencia.", fix: "Quita 'unsafe-eval'; si una librería lo exige, aíslala o cámbiala." });
  if (script.includes("'unsafe-inline'") && !script.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"))) out.push({ id: "CSP-UNSAFE-INLINE", severity: "medium", title: "CSP con 'unsafe-inline' sin nonce/hash", evidence: "script-src permite scripts inline sin nonce ni hash", why: "El vector más común de XSS (inyectar <script>…</script>) sigue abierto.", fix: "Usa 'nonce-<aleatorio>' por respuesta o hashes; quita 'unsafe-inline' de script-src." });
  if (script.includes("*") || script.some((s) => s === "https:" || s === "http:")) out.push({ id: "CSP-WILDCARD", severity: "high", title: "CSP con origen comodín en script-src", evidence: `script-src: ${script.join(" ")}`, why: "Permite cargar JS desde cualquier dominio: la CSP no protege contra XSS.", fix: "Lista los orígenes concretos de tus scripts; nada de *, https: ni http:." });
  if (!dir["object-src"] && !(dir["default-src"] || []).length) out.push({ id: "CSP-NO-OBJECT", severity: "low", title: "CSP sin object-src", evidence: "Falta object-src", why: "Plugins/embeds (Flash-like, PDFs) pueden ejecutar contenido activo.", fix: "object-src 'none'." });
  if (!dir["frame-ancestors"]) out.push({ id: "CSP-NO-FRAME-ANCESTORS", severity: "low", title: "CSP sin frame-ancestors", evidence: "Falta frame-ancestors", why: "El control de clickjacking moderno vive aquí, no en X-Frame-Options.", fix: "frame-ancestors 'self'." });
  return out;
}
