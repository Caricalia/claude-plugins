// DNS y correo: lo que un atacante mira antes que tu app. Suplantar tu
// dominio en un email es más rentable que cualquier XSS.
import { resolveTxt, resolveCname, resolveMx } from "node:dns/promises";

export async function checkDnsEmail(ctx) {
  const { domain, findings } = ctx; const C = "dns-email";
  const txt = async (name) => { try { return (await resolveTxt(name)).map((r) => r.join("")); } catch { return []; } };

  const spf = (await txt(domain)).find((t) => t.startsWith("v=spf1"));
  const mx = await resolveMx(domain).catch(() => []);
  const isApex = domain.split(".").length <= 2;
  const mailSev = mx.length ? "high" : (isApex ? "medium" : "low");
  if (!spf) {
    findings.add(C, { id: "MAIL-NO-SPF", severity: mailSev, title: "Sin registro SPF",
      evidence: `TXT de ${domain} sin v=spf1${mx.length ? ` (y tiene ${mx.length} MX: recibe correo)` : ""}`,
      why: "Cualquiera puede enviar correo como @" + domain + " y la mayoría de receptores no lo marcarán.",
      fix: mx.length ? "TXT v=spf1 con los remitentes reales (incluye tu proveedor de email transaccional) y -all." : "Si el dominio no envía correo: TXT \"v=spf1 -all\"." });
  } else if (/\+all|\?all/.test(spf)) {
    findings.add(C, { id: "MAIL-SPF-PERMISSIVE", severity: "high", title: "SPF permisivo (+all/?all)", evidence: spf, why: "Equivale a no tener SPF.", fix: "Termina en -all (o ~all mientras validas)." });
  } else if (/\s\+?all$/.test(spf) === false && !/[-~]all/.test(spf)) {
    findings.add(C, { id: "MAIL-SPF-NO-ALL", severity: "low", title: "SPF sin cláusula all", evidence: spf, why: "Sin -all/~all el resto de remitentes quedan en neutral.", fix: "Añade -all al final." });
  } else findings.pass(C, "SPF presente y restrictivo");

  const dmarc = (await txt(`_dmarc.${domain}`)).find((t) => t.startsWith("v=DMARC1"));
  if (!dmarc) {
    findings.add(C, { id: "MAIL-NO-DMARC", severity: mailSev === "low" ? "low" : "medium", title: "Sin DMARC", evidence: `_dmarc.${domain} sin TXT`,
      why: "Sin DMARC, SPF/DKIM no dicen al receptor qué hacer con lo que falla, y no recibes informes de quién suplanta tu dominio.",
      fix: `TXT _dmarc.${domain} "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}" (empieza en p=none una semana para ver informes).` });
  } else if (/p=none/.test(dmarc)) {
    findings.add(C, { id: "MAIL-DMARC-NONE", severity: "low", title: "DMARC en p=none", evidence: dmarc, why: "Solo monitoriza; no protege.", fix: "Sube a p=quarantine y luego p=reject cuando los informes estén limpios." });
  } else findings.pass(C, "DMARC con política activa");

  // Subdominios colgando: CNAME a un servicio donde ya no existe el recurso.
  // Un atacante registra el nombre en ese servicio y sirve contenido como tú.
  const candidates = ["www", "app", "api", "docs", "blog", "status", "test", "staging", "dev", "admin", "mail", "cdn", "assets", "media", "help", "support", "shop"];
  const dangling = [];
  for (const sub of candidates) {
    const name = `${sub}.${domain}`;
    let cn = []; try { cn = await resolveCname(name); } catch { continue; }
    const target = cn[0]; if (!target) continue;
    const fp = TAKEOVER.find(([re]) => re.test(target)); if (!fp) continue;
    const res = await ctx.request(`https://${name}/`, { method: "GET", maxBody: 20000 });
    if (res.ok && fp[1].test(res.body)) dangling.push(`${name} → ${target} (${fp[2]})`);
  }
  ctx.subdomains = candidates;
  if (dangling.length) findings.add(C, { id: "DNS-DANGLING", severity: "high", title: "Subdominio apuntando a un recurso que ya no existe (takeover posible)", evidence: dangling.join("\n"),
    why: "Quien registre ese nombre en el proveedor sirve contenido bajo tu dominio: phishing con tu marca, cookies de tu dominio, y a veces CORS.", fix: "Borra el CNAME o vuelve a reclamar el recurso en el proveedor." });
  else findings.pass(C, "Sin CNAMEs colgando en subdominios habituales");
}

const TAKEOVER = [
  [/\.github\.io$/, /There isn't a GitHub Pages site here/i, "GitHub Pages"],
  [/\.herokuapp\.com|herokudns/, /No such app|herokucdn\.com\/error-pages/i, "Heroku"],
  [/vercel-dns|\.vercel\.app$/, /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i, "Vercel"],
  [/\.netlify\.app$/, /Not Found - Request ID/i, "Netlify"],
  [/\.s3[.-][a-z0-9-]*\.amazonaws\.com$/, /NoSuchBucket/i, "S3"],
  [/\.azurewebsites\.net$/, /404 Web Site not found/i, "Azure"],
  [/\.ghost\.io$/, /The thing you were looking for is no longer here/i, "Ghost"],
  [/\.myshopify\.com$/, /Sorry, this shop is currently unavailable/i, "Shopify"],
  [/\.up\.railway\.app$/, /Application not found/i, "Railway"],
];
