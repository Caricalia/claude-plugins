// Un hallazgo = qué, por qué importa, cómo se arregla. Sin el "cómo", el
// informe es una lista de sustos; con él, es una lista de tareas.
//
// Cada hallazgo lleva además un ESTADO, que separa certeza de gravedad:
//   confirmed         — el escáner ha observado el problema; lleva severidad.
//   needs_validation  — hay un indicio, pero el dato decisivo no se ve desde
//                       fuera; sin severidad, con la pregunta exacta a resolver.
//   hardening         — falta una capa de defensa, no hay un fallo explotable
//                       demostrado; sin severidad, con prioridad orientativa.
// La idea de no poner severidad a lo no demostrado y de no vender una capa
// ausente como vulnerabilidad viene de cloudflare/security-audit-skill (MIT).
export const STATUS = ["confirmed", "needs_validation", "hardening"];

// La severidad describe lo que consigue un atacante, no lo que falta:
//   critical — sin autenticar: ejecución de código, acceso a datos o cuentas ajenas.
//   high     — anula un control de seguridad explícito con consecuencias reales.
//   medium   — viola un límite real, con alcance acotado o precondiciones poco comunes.
//   low      — revela información interna no secreta o da poco a mucho esfuerzo.
export const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

// Para hardening: orden de trabajo, no gravedad.
export const PRIORITY = { high: 3, medium: 2, low: 1 };

export class Findings {
  constructor() { this.items = []; this.checks = []; }
  add(check, { id, status = "confirmed", severity, priority, title, evidence, why, fix, repro, unresolved }) {
    if (!STATUS.includes(status)) throw new Error(`Estado inválido en ${id}: ${status}`);
    if (status === "confirmed" && !SEV[severity]) throw new Error(`${id}: un hallazgo confirmado necesita severidad`);
    if (status === "needs_validation" && !unresolved) throw new Error(`${id}: needs_validation necesita 'unresolved'`);
    this.items.push({
      check, id, status, title, evidence, why, fix,
      severity: status === "confirmed" ? severity : null,
      priority: status === "hardening" ? (priority || "low") : null,
      unresolved: status === "needs_validation" ? unresolved : null,
      repro: repro || null,
    });
  }
  pass(check, title) { this.checks.push({ check, title, status: "pass" }); }
  skip(check, title, reason) { this.checks.push({ check, title, status: "skip", reason }); }
  byStatus(status) {
    const rank = status === "confirmed" ? (f) => SEV[f.severity] : status === "hardening" ? (f) => PRIORITY[f.priority] : () => 0;
    return this.items.filter((f) => f.status === status).sort((a, b) => rank(b) - rank(a));
  }
  sorted() { return STATUS.flatMap((s) => this.byStatus(s)); }
  count(sev) { return this.items.filter((f) => f.status === "confirmed" && f.severity === sev).length; }
  countStatus(status) { return this.items.filter((f) => f.status === status).length; }
}

// curl reproducible para que el dueño compruebe el hallazgo sin fiarse del escáner.
export const curl = (url, { method, headers = {}, head = true } = {}) => {
  const parts = ["curl -s", head ? "-o /dev/null -D -" : ""];
  if (method && method !== "GET") parts.push(`-X ${method}`);
  for (const [k, v] of Object.entries(headers)) parts.push(`-H '${k}: ${v}'`);
  parts.push(`'${url}'`);
  return parts.filter(Boolean).join(" ");
};

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
