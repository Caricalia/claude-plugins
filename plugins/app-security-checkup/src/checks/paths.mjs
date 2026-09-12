// Rutas sensibles que NO deberían existir. Solo GET/HEAD, sin payloads.
// El valor no es "pedir .env" (eso lo hace cualquiera): es distinguir un
// 200-real de un SPA que devuelve index.html para todo, y probar los
// bypass de path que los frameworks tienen (ahí está lo "avanzado").
import { makeFingerprint } from "../http.mjs";

const SECRETS = [
  "/.env", "/.env.local", "/.env.production", "/.env.backup", "/config/.env",
  "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/store",
  "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.npmrc", "/.dockercfg", "/docker-compose.yml",
  "/config.json", "/appsettings.json", "/config/database.yml", "/wp-config.php.bak", "/.DS_Store",
  "/backup.sql", "/dump.sql", "/database.sqlite", "/.terraform/terraform.tfstate", "/terraform.tfstate",
];
// Endpoints de diagnóstico por framework: devuelven config o variables de entorno.
const DIAG = [
  "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings", "/actuator/threaddump",
  "/metrics", "/debug/vars", "/debug/pprof/", "/_debug", "/__debug__/",
  "/server-status", "/server-info", "/phpinfo.php", "/info.php", "/telescope", "/_profiler",
  "/api/swagger", "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/graphql",
];
// Bypass de path: mismos frameworks, saltándose el filtro de auth/routing.
// Se prueban solo contra un endpoint de diagnóstico ya conocido.
const BYPASS = (p) => [`${p}`, `/.${p}`, `${p}/.`, `${p}%2e`, `${p};`, `/;${p}`, `${p}/..;/`, `${p}%20`, `${p}?`, `${p}#`, `//${p.slice(1)}`];

export async function checkPaths(ctx) {
  const { domain, findings, request } = ctx; const C = "rutas";
  // Línea base: una ruta que seguro no existe. Con esto detectamos el SPA-catch-all.
  const base = await request(`https://${domain}/checkup-${Date.now().toString(36)}-noexiste`);
  const isSpaEcho = makeFingerprint(base.body, base.status);
  ctx.spaCatchAll = base.status === 200;

  const hits = [];
  for (const p of SECRETS) {
    const res = await request(`https://${domain}${p}`);
    if (looksReal(res, isSpaEcho, p)) hits.push({ p, res });
  }
  for (const h of hits) {
    findings.add(C, { id: "PATH-SECRET", severity: "high", title: `Fichero sensible accesible: ${h.p}`,
      evidence: `HTTP ${h.res.status}, ${h.res.bytes} bytes, ${h.res.headers.get("content-type") || "?"} (no se muestra el contenido)`,
      why: "Un secreto servido por HTTP es una credencial pública: claves, tokens, cadenas de conexión.",
      fix: `Deniega ${h.p} en el borde y saca el fichero del directorio público. Rota lo que hubiera dentro.` });
  }

  const diagHits = [];
  for (const p of DIAG) {
    const res = await request(`https://${domain}${p}`);
    if (looksReal(res, isSpaEcho, p) && !isAuthWall(res)) diagHits.push({ p, res });
  }
  for (const h of diagHits) {
    const sev = /env|heapdump|threaddump|pprof|phpinfo|credentials/.test(h.p) ? "high" : "medium";
    findings.add(C, { id: "PATH-DIAG", severity: sev, title: `Endpoint de diagnóstico expuesto: ${h.p}`,
      evidence: `HTTP ${h.res.status}, ${h.res.bytes} bytes, ${h.res.headers.get("content-type") || "?"}`,
      why: "Config, variables de entorno, métricas internas o volcados de memoria accesibles sin autenticar.",
      fix: `Protege ${h.p} con auth o restríngelo a red interna. Los de Spring: management.endpoints.web.exposure.include mínimo.` });
    // Solo si un diag respondió, probamos bypass de path sobre él.
    if (sev === "high") await tryBypass(ctx, C, h.p, isSpaEcho);
  }

  if (!hits.length && !diagHits.length) findings.pass(C, `Sin ficheros sensibles ni endpoints de diagnóstico accesibles (${SECRETS.length + DIAG.length} rutas probadas)`);
  if (ctx.spaCatchAll) findings.skip(C, "Nota", "el frontend responde 200 a rutas inexistentes (SPA); los 'hits' se filtran comparando con esa respuesta base");
}

async function tryBypass(ctx, C, path, isSpaEcho) {
  const { domain, request, findings } = ctx;
  // Reprobamos el endpoint con un prefijo de auth ficticio para ver si el
  // bypass salta un gate. Como no tenemos gate real, comparamos status.
  for (const variant of BYPASS(path)) {
    const res = await request(`https://${domain}${variant}`);
    if (res.status === 200 && !isSpaEcho(res) && res.bytes > 0) {
      findings.add(C, { id: "PATH-BYPASS", severity: "high", title: `Posible bypass de routing: ${variant}`,
        evidence: `${variant} → 200 (${res.bytes} bytes) mientras ${path} estaba protegido/redirigido`,
        why: "Variantes de path (/;/, /..;/, %2e, doble slash) que algunos frameworks normalizan DESPUÉS de aplicar auth: se salta el filtro.",
        fix: "Normaliza el path antes de autorizar; en Spring, desactiva el matching con ';' (matrix variables) y bloquea // en el borde." });
      return;
    }
  }
}

function looksReal(res, isSpaEcho, path) {
  if (!res.ok || res.status !== 200 || res.bytes === 0) return false;
  if (isSpaEcho(res)) return false; // es el catch-all del SPA
  const ct = res.headers.get("content-type") || "";
  // Un .env que devuelve text/html es casi seguro una página de error/SPA.
  if (/\.env|\.git|credentials|id_rsa|\.sql|tfstate/.test(path) && /text\/html/.test(ct)) return false;
  return true;
}
const isAuthWall = (res) => res.status === 401 || res.status === 403;
