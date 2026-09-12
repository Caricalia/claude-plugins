// ¿El origen acepta conexiones que no vienen del CDN? Es el fallo que más
// se pasa por alto: todo el WAF es opcional si el host del hosting responde.
import { resolveCname, resolve4 } from "node:dns/promises";
import { connect } from "node:tls";
import { fixes } from "../findings.mjs";

const HOSTING = [
  [/\.up\.railway\.app$/, "railway"], [/\.vercel\.app$|vercel-dns/, "vercel"], [/\.fly\.dev$/, "fly"],
  [/\.onrender\.com$/, "render"], [/\.herokuapp\.com|herokudns/, "heroku"], [/\.netlify\.app$/, "netlify"],
  [/\.azurewebsites\.net$/, "azure"], [/\.elb\.amazonaws\.com$|\.cloudfront\.net$/, "aws"], [/\.pages\.dev$/, "cloudflare-pages"],
];

const CDN_CNAMES = /cloudflare|cfargotunnel|fastly|akamai|cloudfront|vercel-dns|netlify/i;

export async function checkOrigin(ctx) {
  const { domain, findings, request } = ctx; const C = "origen";
  let cnames = [];
  try { cnames = await resolveCname(domain); } catch {}
  let ips = [];
  try { ips = await resolve4(domain); } catch {}
  ctx.dns = { cnames, ips };

  const behindCdn = cnames.some((c) => CDN_CNAMES.test(c)) || ips.some(isCloudflareIp);
  if (!behindCdn) {
    findings.add(C, { id: "ORIGIN-NO-CDN", severity: "info", title: "El dominio apunta directo al origen (sin CDN/WAF delante)",
      evidence: `CNAME: ${cnames.join(", ") || "-"} · A: ${ips.join(", ") || "-"}`,
      why: "Sin un borde delante no hay WAF, ni rate-limit, ni bloqueo de escáneres: todo lo absorbe tu servidor.",
      fix: "Pon un CDN con WAF (Cloudflare Free ya sirve) y proxía el registro. Luego aplica el resto de este informe en el borde." });
    return;
  }
  findings.pass(C, "Hay un CDN/proxy delante del dominio");

  // El CNAME suele delatar el hosting. Si podemos hablar con su edge con
  // nuestro Host, el CDN es decorativo.
  const target = cnames.find((c) => HOSTING.some(([re]) => re.test(c)));
  if (!target) { findings.skip(C, "Bypass del CDN vía host del hosting", "el CNAME no apunta a un hosting conocido (probablemente túnel o IP propia)"); return; }
  const platform = HOSTING.find(([re]) => re.test(target))[1];
  const direct = await sniProbe(target, domain);
  if (direct.status && direct.status !== 404 && direct.status < 500) {
    findings.add(C, { id: "ORIGIN-BYPASS", severity: "high", title: "El origen responde saltándose el CDN",
      evidence: `TLS a ${target} con SNI/Host ${domain} → HTTP ${direct.status}. Cualquiera puede repetirlo: curl --connect-to ${domain}:443:${target}:443 https://${domain}/`,
      why: "WAF, rate-limit, bloqueo de bots y cabeceras de seguridad del CDN no aplican a quien conecte directamente. Y el host está en tu DNS público.",
      fix: fixes.cdnOnly[platform] || fixes.cdnOnly.generic });
  } else {
    findings.pass(C, `El host del hosting (${target}) no sirve tu dominio sin pasar por el CDN`);
  }
}

// Handshake TLS + una petición mínima al host del hosting con el Host del
// dominio. Una sola conexión, sin cuerpo.
function sniProbe(host, sni) {
  return new Promise((resolve) => {
    const s = connect({ host, port: 443, servername: sni, rejectUnauthorized: false, timeout: 8000 }, () => {
      s.write(`HEAD / HTTP/1.1\r\nHost: ${sni}\r\nUser-Agent: app-security-checkup/0.1\r\nConnection: close\r\n\r\n`);
    });
    let data = "";
    s.on("data", (d) => { data += d; if (data.length > 2000) s.end(); });
    s.on("end", () => resolve({ status: Number((data.match(/^HTTP\/\d\.\d (\d{3})/) || [])[1]) || 0 }));
    s.on("error", (e) => resolve({ status: 0, error: e.code }));
    s.on("timeout", () => { s.destroy(); resolve({ status: 0, error: "timeout" }); });
  });
}

function isCloudflareIp(ip) {
  const [a, b] = ip.split(".").map(Number);
  return (a === 104 && b >= 16 && b <= 31) || (a === 172 && b >= 64 && b <= 71) || (a === 162 && b === 158) || (a === 198 && b === 41) || (a === 188 && b === 114) || (a === 141 && b === 101) || (a === 108 && b === 162) || (a === 173 && b === 245) || (a === 103 && (b === 21 || b === 22 || b === 31)) || (a === 190 && b === 93) || (a === 197 && b === 234) || (a === 131 && b === 0);
}
