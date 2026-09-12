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

const CHECKS = [
  ["origen", checkOrigin], ["dns-email", checkDnsEmail], ["transporte", checkTransport],
  ["cabeceras", checkHeaders], ["cors-cookies", checkCorsCookies], ["rutas", checkPaths], ["reflexión-xss", checkReflection], ["varios", checkMisc],
];

export async function run(domain, { max = 250, perSecond = 3, apiBase } = {}) {
  const budget = new Budget({ max, perSecond });
  const request = makeClient(budget);
  const findings = new Findings();
  const home = await request(`https://${domain}/`, { method: "GET" });
  if (!home.ok) throw new Error(`No se pudo conectar a https://${domain}/ (${home.error}). ¿Dominio correcto y accesible?`);
  const ctx = { domain, findings, request, home, apiBase };
  for (const [name, fn] of CHECKS) {
    try { await fn(ctx); }
    catch (e) { findings.skip(name, "chequeo interrumpido", e.message); }
  }
  return { findings, requests: budget.used };
}
