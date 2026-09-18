// Chequeos sueltos de alto valor: open redirect, host-header, rate-limit en
// login, y CSP report-only olvidada. Todo detección.
import { curl } from "../findings.mjs";
export async function checkMisc(ctx) {
  const { domain, findings, request } = ctx; const C = "varios";

  // Open redirect: parámetros típicos con un destino externo. Miramos si el
  // 30x nos manda fuera. No seguimos la redirección.
  const evil = "https://evil-checkup.example/x";
  const params = ["next", "redirect", "url", "return", "returnUrl", "returnTo", "continue", "dest", "destination", "redir", "callback"];
  for (const param of params) {
    const res = await request(`https://${domain}/?${param}=${encodeURIComponent(evil)}`, { method: "GET", redirect: "manual" });
    const loc = res.headers.get("location") || "";
    if (res.status >= 301 && res.status <= 308 && /^https?:\/\/evil-checkup\.example/i.test(loc)) {
      findings.add(C, { id: "OPEN-REDIRECT", severity: "low", repro: curl(`https://${domain}/?${param}=${encodeURIComponent(evil)}`), title: `Open redirect vía ?${param}=`, evidence: `?${param}=${evil} → ${res.status} Location: ${loc}`,
        why: "Un enlace a TU dominio que acaba en el del atacante: phishing creíble y robo de tokens OAuth que confían en tu redirect_uri.", fix: "Valida el destino contra una allowlist o permite solo rutas relativas." });
      break;
    }
  }

  // Host header: mandamos un Host falso y miramos si aparece en la respuesta
  // (envenenamiento de enlaces / reset de contraseña).
  const poison = "evil-checkup.example";
  const hh = await request(`https://${domain}/`, { method: "GET", headers: { host: poison, "x-forwarded-host": poison } });
  if (hh.ok && hh.body.includes(poison)) {
    findings.add(C, { id: "HOST-HEADER", status: "needs_validation", unresolved: "¿Los enlaces que la app manda por email (reset de contraseña, verificación, invitaciones) se construyen con este Host? Si sí, es un robo de cuentas.", repro: curl(`https://${domain}/`, { headers: { Host: poison, "X-Forwarded-Host": poison }, head: false }) + ` | grep -c ${poison}`, title: "La app refleja el Host/X-Forwarded-Host recibido", evidence: `Host: ${poison} aparece en el HTML de respuesta`,
      why: "Envenenamiento de host: enlaces de reset de contraseña o de verificación apuntando al dominio del atacante.", fix: "Fija el host canónico en el borde y no confíes en X-Forwarded-Host del cliente." });
  }

  // security.txt (RFC 9116): dónde avisarte si alguien encuentra un fallo.
  const st = await request(`https://${domain}/.well-known/security.txt`);
  const stType = st.headers.get("content-type") || "";
  if (!(st.status === 200 && /text\/plain/.test(stType) && /^contact:/im.test(st.body))) {
    findings.add(C, { id: "NO-SECURITY-TXT", status: "hardening", priority: "low", title: "Sin /.well-known/security.txt", evidence: `HTTP ${st.status}${stType ? " · " + stType : ""}`, repro: curl(`https://${domain}/.well-known/security.txt`, { head: false }),
      why: "Quien encuentre un fallo en tu web no sabe a quién decírselo, y acaba en un tuit o en ningún sitio.",
      fix: "Publica /.well-known/security.txt (text/plain) con Contact: mailto:security@tudominio y Expires: <fecha ISO a menos de un año>." });
  } else if (/^expires:\s*(.+)$/im.test(st.body) && new Date(st.body.match(/^expires:\s*(.+)$/im)[1]) < new Date()) {
    findings.add(C, { id: "SECURITY-TXT-EXPIRED", status: "hardening", priority: "low", title: "security.txt caducado", evidence: st.body.match(/^expires:.*$/im)[0], why: "Un security.txt caducado indica que nadie lo mantiene; los investigadores lo ignoran.", fix: "Actualiza Expires y revisa que el contacto siga vivo." });
  } else findings.pass(C, "security.txt publicado");

  // CSP en Report-Only y nunca aplicada: falsa sensación de seguridad.
  const ro = ctx.home.headers.get("content-security-policy-report-only");
  if (ro && !ctx.home.headers.get("content-security-policy")) {
    findings.add(C, { id: "CSP-REPORT-ONLY", status: "hardening", priority: "medium", title: "CSP solo en Report-Only", evidence: "Hay Content-Security-Policy-Report-Only pero no Content-Security-Policy", why: "Report-Only registra violaciones pero no bloquea nada: no protege.", fix: "Cuando los informes estén limpios, mueve la política a Content-Security-Policy." });
  }
}
