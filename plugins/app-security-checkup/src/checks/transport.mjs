// TLS y redirecciones. Poco glamour, pero HSTS mal puesto o un http:// que
// no redirige es lo que convierte un wifi de aeropuerto en sesión robada.
import { connect } from "node:tls";

export async function checkTransport(ctx) {
  const { domain, findings, request } = ctx; const C = "transporte";
  const http = await request(`http://${domain}/`, { method: "HEAD" });
  if (http.ok && !(http.status >= 301 && http.status <= 308 && /^https:/i.test(http.headers.get("location") || ""))) {
    findings.add(C, { id: "TLS-NO-REDIRECT", severity: "medium", title: "http:// no redirige a https://", evidence: `HEAD http://${domain}/ → ${http.status} ${http.headers.get("location") || ""}`,
      why: "El primer request de cada visita puede ir en claro; ahí se inyecta o se roba.", fix: "Redirección 301 a https en el borde + HSTS." });
  } else findings.pass(C, "http:// redirige a https://");

  const home = ctx.home;
  const hsts = home.headers.get("strict-transport-security") || "";
  const maxAge = Number((hsts.match(/max-age=(\d+)/) || [])[1] || 0);
  if (!hsts) findings.add(C, { id: "TLS-NO-HSTS", severity: "medium", title: "Sin HSTS", evidence: "Falta Strict-Transport-Security", why: "El navegador seguirá probando http:// en visitas futuras.", fix: "Strict-Transport-Security: max-age=31536000; includeSubDomains (preload cuando estés seguro)." });
  else if (maxAge < 15552000) findings.add(C, { id: "TLS-HSTS-SHORT", severity: "low", title: "HSTS con max-age corto", evidence: hsts, why: "Menos de 6 meses: la protección caduca entre visitas.", fix: "max-age=31536000." });
  else findings.pass(C, "HSTS con max-age ≥ 6 meses");

  const tls = await minTls(domain);
  if (tls.tls10 || tls.tls11) findings.add(C, { id: "TLS-OLD", severity: "medium", title: "TLS 1.0/1.1 aceptados", evidence: `TLS1.0: ${tls.tls10} · TLS1.1: ${tls.tls11}`, why: "Protocolos con ataques conocidos; PCI los prohíbe desde 2018.", fix: "Mínimo TLS 1.2 en el borde (Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS)." });
  else findings.pass(C, "TLS mínimo 1.2");
}

function minTls(host) {
  const probe = (v) => new Promise((r) => {
    const s = connect({ host, port: 443, servername: host, minVersion: v, maxVersion: v, rejectUnauthorized: false, timeout: 6000 }, () => { s.destroy(); r(true); });
    s.on("error", () => r(false)); s.on("timeout", () => { s.destroy(); r(false); });
  });
  return Promise.all([probe("TLSv1"), probe("TLSv1.1")]).then(([tls10, tls11]) => ({ tls10, tls11 })).catch(() => ({ tls10: false, tls11: false }));
}
