// Lo que tu frontend publica sin querer: claves dentro del bundle JS, source
// maps que regalan el código fuente, scripts de terceros sin SRI y recursos
// por http://. Solo leemos lo que la home ya enlaza; no adivinamos rutas.
import { curl } from "../findings.mjs";

// Solo patrones con prefijo propio del proveedor: poco ruido. Las claves
// públicas por diseño (pk_live_, AIza…, anon de Supabase) no cuentan.
const SECRETS = [
  [/\bAKIA[0-9A-Z]{16}\b/g, "AWS access key", "critical"],
  [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, "clave privada", "critical"],
  [/\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/g, "Stripe secret key", "critical"],
  [/\bsk-ant-[A-Za-z0-9_-]{32,}/g, "Anthropic API key", "high"],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}/g, "OpenAI API key", "high"],
  [/\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}/g, "GitHub token", "high"],
  [/\bxox[baprs]-[0-9A-Za-z-]{10,}/g, "Slack token", "high"],
  [/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, "SendGrid API key", "high"],
];
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const MAX_SCRIPTS = 6;

export async function checkAssets(ctx) {
  const { domain, findings, request, home } = ctx; const C = "assets";
  if (!/text\/html/.test(home.headers.get("content-type") || "")) { findings.skip(C, "Assets del frontend", "la home no es HTML"); return; }
  const base = `https://${domain}/`;
  const tags = [...home.body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)].map((m) => ({ tag: m[0], url: safeUrl(m[1], base) })).filter((s) => s.url);
  const own = (u) => u.hostname === domain || u.hostname.endsWith(`.${domain}`);

  // Contenido mixto: recursos por http:// en una página https.
  const mixed = [...new Set([...home.body.matchAll(/<(?:script|link|iframe|img|source|video|audio)\b[^>]*\b(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]))];
  if (mixed.length) findings.add(C, { id: "MIXED-CONTENT", status: "hardening", priority: /<(?:script|iframe)/i.test(home.body) ? "medium" : "low", title: "Recursos cargados por http:// (contenido mixto)", evidence: mixed.slice(0, 5).join("\n"),
    why: "El navegador bloquea los scripts y deja pasar (o actualiza) las imágenes: o se rompe algo, o se carga en claro algo que un atacante en la red puede cambiar.", fix: "Cambia esas URLs a https:// y añade `upgrade-insecure-requests` a la CSP." });
  else findings.pass(C, "Sin contenido mixto en la home");

  // SRI: un script de terceros sin integrity ejecuta lo que ese tercero sirva hoy.
  const thirdNoSri = tags.filter((s) => !own(s.url) && !/\bintegrity\s*=/i.test(s.tag)).map((s) => s.url.href);
  if (thirdNoSri.length) findings.add(C, { id: "NO-SRI", status: "hardening", priority: "low", title: `${thirdNoSri.length} script(s) de terceros sin Subresource Integrity`, evidence: thirdNoSri.slice(0, 5).join("\n"),
    why: "Si ese CDN o proveedor es comprometido, su código corre en tu página con acceso a la sesión de tus usuarios.", fix: "Para ficheros con versión fija, añade integrity=\"sha384-…\" crossorigin=\"anonymous\". Los que cambian solos (analítica, chat) no admiten SRI: limítalos con la CSP y cárgalos solo donde hagan falta." });
  else if (tags.some((s) => !own(s.url))) findings.pass(C, "Scripts de terceros con SRI");

  // Bundles propios: claves y source maps.
  const ownScripts = tags.filter((s) => own(s.url)).slice(0, MAX_SCRIPTS);
  if (!ownScripts.length) { findings.skip(C, "Bundles JS", "la home no enlaza scripts propios (¿se cargan dinámicamente?)"); return; }
  const leaks = []; const maps = [];
  for (const s of ownScripts) {
    const res = await request(s.url.href, { maxBody: 3_000_000 });
    if (!res.ok || res.status !== 200) continue;
    for (const [re, name, sev] of SECRETS) for (const m of res.body.matchAll(re)) leaks.push({ name, sev, where: s.url.pathname, sample: redact(m[0]) });
    for (const m of res.body.matchAll(JWT)) if (jwtRole(m[0]) === "service_role") leaks.push({ name: "JWT con role service_role (Supabase)", sev: "critical", where: s.url.pathname, sample: redact(m[0]) });
    const mapRef = res.headers.get("sourcemap") || res.headers.get("x-sourcemap") || (res.body.match(/[#@]\s*sourceMappingURL=(\S+)\s*$/) || [])[1];
    if (mapRef && !mapRef.startsWith("data:")) {
      const mapUrl = safeUrl(mapRef, s.url.href);
      const mr = mapUrl && await request(mapUrl.href, { maxBody: 4000 });
      if (mr?.status === 200 && /"sources"\s*:/.test(mr.body)) maps.push(mapUrl.href);
    }
  }
  if (leaks.length) {
    const worst = leaks.some((l) => l.sev === "critical") ? "critical" : "high";
    findings.add(C, { id: "JS-SECRET", severity: worst, title: `Credencial en el JavaScript público: ${[...new Set(leaks.map((l) => l.name))].join(", ")}`,
      evidence: leaks.slice(0, 5).map((l) => `${l.where}: ${l.sample}`).join("\n"), repro: curl(`https://${domain}${leaks[0].where}`, { head: false }) + ` | grep -c '${leaks[0].sample.slice(0, 6)}'`,
      why: "Todo lo que va en el bundle lo descarga cualquier visitante. Una clave secreta ahí es una clave pública: gasto a tu cargo, acceso a tus datos o a tu cuenta del proveedor.",
      fix: "Rota la clave YA (asume que está filtrada) y mueve la llamada al servidor. En Next.js/Vite, solo las variables NEXT_PUBLIC_/VITE_ llegan al cliente: una secreta nunca debe llevar ese prefijo." });
  } else findings.pass(C, `Sin credenciales conocidas en ${ownScripts.length} bundle(s) JS`);

  if (maps.length) findings.add(C, { id: "SOURCE-MAPS", severity: "low", title: "Source maps públicos", evidence: maps.slice(0, 5).join("\n"), repro: curl(maps[0]),
    why: "Cualquiera reconstruye tu código fuente original con comentarios, rutas internas y lógica de negocio: facilita encontrar el siguiente fallo.",
    fix: "No subas los .map a producción (Next.js: productionBrowserSourceMaps: false; Vite: build.sourcemap: false o 'hidden') o súbelos solo a tu herramienta de errores (Sentry)." });
  else findings.pass(C, "Sin source maps públicos en los bundles revisados");
}

function safeUrl(u, base) { try { const x = new URL(u, base); return /^https?:$/.test(x.protocol) ? x : null; } catch { return null; } }
const redact = (s) => s.length > 12 ? `${s.slice(0, 8)}…(${s.length} chars)` : "***";
function jwtRole(t) { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()).role; } catch { return null; } }
