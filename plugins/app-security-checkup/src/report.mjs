// Informe markdown + JSON. Tres bloques que no se mezclan: lo confirmado
// (con severidad), lo que hay que validar a mano (con la pregunta exacta) y
// el endurecimiento (capas que faltan). Así un "alto" siempre significa algo.
const ICON = { critical: "🟣", high: "🔴", medium: "🟠", low: "🟡" };
const LABEL = { critical: "Crítico", high: "Alto", medium: "Medio", low: "Bajo" };
const PLABEL = { high: "prioridad alta", medium: "prioridad media", low: "prioridad baja" };
const SEVS = ["critical", "high", "medium", "low"];

export const SCHEMA_VERSION = "1";

export function toJson(domain, findings, meta) {
  return {
    schema_version: SCHEMA_VERSION,
    tool: { name: "app-security-checkup", version: meta.version },
    target: domain,
    generated_at: meta.generatedAt,
    requests: meta.requests,
    edge: meta.edge || null,
    waf_challenge: Boolean(meta.challenged),
    summary: {
      confirmed: Object.fromEntries(SEVS.map((s) => [s, findings.count(s)])),
      needs_validation: findings.countStatus("needs_validation"),
      hardening: findings.countStatus("hardening"),
      passed: findings.checks.filter((c) => c.status === "pass").length,
    },
    findings: findings.sorted(),
    checks: findings.checks,
  };
}

export function toMarkdown(domain, findings, meta) {
  const L = [];
  const confirmed = findings.byStatus("confirmed"), pending = findings.byStatus("needs_validation"), hardening = findings.byStatus("hardening");
  L.push(`# Chequeo de seguridad · ${domain}`, "");
  L.push(`_${meta.generatedAt.slice(0, 16).replace("T", " ")} UTC · ${meta.requests} peticiones · solo lectura, sin explotación_`, "");
  const sevCounts = SEVS.filter((s) => s !== "critical" || findings.count(s)).map((s) => `${ICON[s]} ${findings.count(s)} ${LABEL[s].toLowerCase()}`).join(" · ");
  L.push(`**Confirmados:** ${sevCounts}  `);
  L.push(`**Por validar:** ${pending.length} · **Endurecimiento:** ${hardening.length} · ✅ ${findings.checks.filter((c) => c.status === "pass").length} comprobaciones OK`, "");
  if (meta.challenged) L.push("> ⚠️ **Informe parcial.** El WAF respondió al escáner con un challenge de bots, así que solo se han revisado DNS, correo, TLS y el origen. Para el chequeo completo, crea una regla temporal que deje pasar el User-Agent `app-security-checkup` (Cloudflare: WAF → Custom rules → Skip; Vercel: Firewall → regla Bypass por User-Agent), relanza y bórrala después.", "");
  L.push("> **Confirmado** = el escáner lo ha observado. **Por validar** = hay un indicio y falta un dato que no se ve desde fuera; no lleva severidad hasta comprobarlo. **Endurecimiento** = falta una capa de defensa, pero no hay un fallo demostrado.", "");

  if (!findings.items.length) L.push("No se han detectado problemas en las comprobaciones automáticas. Eso no es un certificado: es la lista de lo que este escáner mira.", "");
  let n = 0;
  const section = (title, items, head) => {
    if (!items.length) return;
    L.push(`## ${title}`, "");
    items.forEach((f) => {
      n++;
      L.push(`### ${n}. ${head(f)} ${f.title}`, "");
      L.push(`**Evidencia:** \`${(f.evidence || "").replace(/`/g, "'").replace(/\n/g, " · ")}\`  `, "");
      if (f.unresolved) L.push(`**Qué falta comprobar:** ${f.unresolved}  `, "");
      L.push(`**Por qué importa:** ${f.why}  `, "");
      L.push(`**Cómo se arregla:** ${f.fix}`, "");
      if (f.repro) L.push("**Compruébalo tú:**", "", "```sh", f.repro, "```", "");
    });
  };
  section("Confirmados", confirmed, (f) => `${ICON[f.severity]} ${LABEL[f.severity]} ·`);
  section("Por validar", pending, () => "🔍");
  section("Endurecimiento", hardening, (f) => `🛡️ (${PLABEL[f.priority]}) ·`);

  L.push("---", "");
  L.push("<details><summary>Comprobaciones que pasaron / se omitieron</summary>", "");
  for (const c of findings.checks) L.push(`- ${c.status === "pass" ? "✅" : "⏭️"} **${c.check}** — ${c.title}${c.reason ? ` (${c.reason})` : ""}`);
  L.push("", "</details>", "");
  L.push("> Escaneo pasivo de un dominio propio (verificado por DNS). Ve la web desde fuera: no sustituye una revisión del código ni un pentest. Generado con app-security-checkup.");
  return L.join("\n");
}

export function toText(domain, findings, meta = {}) {
  const L = [`\nChequeo de seguridad · ${domain}`,
    ...(meta.challenged ? ["⚠️  El WAF sirvió un challenge de bots: informe PARCIAL (solo DNS, correo, TLS y origen). Deja pasar el User-Agent app-security-checkup y relanza."] : []),
    `Confirmados: ${SEVS.map((s) => `${ICON[s]} ${findings.count(s)}`).join(" ")} · 🔍 por validar ${findings.countStatus("needs_validation")} · 🛡️ endurecimiento ${findings.countStatus("hardening")}\n`];
  findings.sorted().forEach((f, i) => {
    const tag = f.status === "confirmed" ? LABEL[f.severity].toUpperCase() : f.status === "needs_validation" ? "POR VALIDAR" : `ENDURECER · ${f.priority}`;
    L.push(`${i + 1}. [${tag}] ${f.title}\n   ${(f.evidence || "").replace(/\n/g, " · ")}${f.unresolved ? `\n   ? ${f.unresolved}` : ""}\n   → ${f.fix}\n`);
  });
  if (!findings.items.length) L.push("Sin hallazgos automáticos.\n");
  return L.join("\n");
}
