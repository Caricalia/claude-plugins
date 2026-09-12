// Un hallazgo = qué, por qué importa, cómo se arregla. Sin el "cómo", el
// informe es una lista de sustos; con él, es una lista de tareas.
export const SEV = { high: 3, medium: 2, low: 1, info: 0 };

export class Findings {
  constructor() { this.items = []; this.checks = []; }
  add(check, { id, severity, title, evidence, why, fix }) {
    this.items.push({ check, id, severity, title, evidence, why, fix });
  }
  pass(check, title) { this.checks.push({ check, title, status: "pass" }); }
  skip(check, title, reason) { this.checks.push({ check, title, status: "skip", reason }); }
  sorted() { return [...this.items].sort((a, b) => SEV[b.severity] - SEV[a.severity]); }
  count(sev) { return this.items.filter((f) => f.severity === sev).length; }
}

// Un "cómo se arregla" por plataforma, para que el fix no sea "configura la CSP".
export const fixes = {
  cdnOnly: {
    cloudflare: "Cloudflare Tunnel (origen sin IP pública) o Authenticated Origin Pulls (mTLS). Como mínimo, allowlist de IPs de Cloudflare en el firewall del origen.",
    vercel: "Vercel ya es el borde: no pongas otro CDN delante, o activa 'Trusted Proxy' y valida x-vercel-* en tu código.",
    railway: "Cloudflare Tunnel con cloudflared como servicio del proyecto (--protocol http2) y borra los dominios *.up.railway.app.",
    generic: "El origen solo debe aceptar conexiones del CDN: túnel, mTLS o allowlist de IPs. Y borra cualquier hostname alternativo que llegue al mismo origen.",
  },
  headers: {
    cloudflare: "Reglas de Transform → Modify Response Header (o Terraform: cloudflare_ruleset fase http_response_headers_transform).",
    vercel: "`headers` en vercel.json o next.config.js.",
    nginx: "`add_header` en el bloque server (con `always`).",
    generic: "Ponlas en el borde (CDN) si tienes varios orígenes; si no, en el reverse proxy. Nunca en dos sitios a la vez.",
  },
};
