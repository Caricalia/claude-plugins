import { Budget, makeClient } from "./http.mjs";
import { Findings } from "./findings.mjs";
import { checkOrigin } from "./checks/origin.mjs";
import { checkDnsEmail } from "./checks/dns-email.mjs";
import { checkTransport } from "./checks/transport.mjs";
import { checkHeaders } from "./checks/headers.mjs";
import { checkCorsCookies } from "./checks/cors-cookies.mjs";
import { checkPaths } from "./checks/paths.mjs";
import { checkMisc } from "./checks/misc.mjs";
import { checkReflection } from "./checks/reflection.mjs";
import { checkAssets } from "./checks/assets.mjs";

// El tercer campo marca los chequeos que leen respuestas HTTP de la app: si
// un WAF nos sirve un challenge, esos resultados serían de la página del
// challenge y no de tu web, así que no se ejecutan.
const CHECKS = [
  ["origen", checkOrigin], ["dns-email", checkDnsEmail], ["transporte", checkTransport],
  ["cabeceras", checkHeaders, true], ["assets", checkAssets, true], ["cors-cookies", checkCorsCookies, true], ["rutas", checkPaths, true], ["reflexión-xss", checkReflection, true], ["varios", checkMisc, true],
];

// Qué borde tenemos delante, por las cabeceras que él mismo añade.
const EDGES = [["cloudflare", /^cf-ray$/], ["vercel", /^x-vercel-id$/], ["netlify", /^x-nf-request-id$/], ["fastly", /^x-served-by$/], ["cloudfront", /^x-amz-cf-id$/], ["akamai", /^x-akamai/]];
export function detectEdge(headers) {
  const names = [...headers.keys()];
  return (EDGES.find(([, re]) => names.some((n) => re.test(n))) || [null])[0];
}

// Challenge de bots: Cloudflare (cf-mitigated / "Just a moment"), Vercel
// (x-vercel-mitigated), o un 403/429 genérico con página de verificación.
export function detectChallenge(res) {
  const h = res.headers;
  if (/challenge/i.test(h.get("cf-mitigated") || "") || /challenge|deny/i.test(h.get("x-vercel-mitigated") || "")) return true;
  return [403, 429, 503].includes(res.status) && /just a moment|attention required|checking your browser|captcha|challenge-platform/i.test(res.body);
}

export async function run(domain, { max = 250, perSecond = 3, apiBase } = {}) {
  const budget = new Budget({ max, perSecond });
  const request = makeClient(budget);
  const findings = new Findings();
  const home = await request(`https://${domain}/`, { method: "GET" });
  if (!home.ok) throw new Error(`No se pudo conectar a https://${domain}/ (${home.error}). ¿Dominio correcto y accesible?`);
  const ctx = { domain, findings, request, home, apiBase, edge: detectEdge(home.headers), challenged: detectChallenge(home) };
  for (const [name, fn, needsApp] of CHECKS) {
    if (needsApp && ctx.challenged) { findings.skip(name, "no ejecutado", "el WAF respondió con un challenge de bots; ver aviso al inicio del informe"); continue; }
    try { await fn(ctx); }
    catch (e) { findings.skip(name, "chequeo interrumpido", e.message); }
  }
  return { findings, requests: budget.used, edge: ctx.edge, challenged: ctx.challenged };
}
