// Informe markdown. Semáforo arriba, hallazgos ordenados por severidad, y
// cada uno con qué/por qué/cómo. Lo que se comparte en el post.
const ICON = { high: "🔴", medium: "🟠", low: "🟡", info: "🔵" };
const LABEL = { high: "Alto", medium: "Medio", low: "Bajo", info: "Info" };

export function toMarkdown(domain, findings, meta) {
  const items = findings.sorted();
  const L = [];
  L.push(`# Chequeo de seguridad · ${domain}`, "");
  L.push(`_${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC · ${meta.requests} peticiones · solo lectura, sin explotación_`, "");
  const counts = ["high", "medium", "low"].map((s) => `${ICON[s]} ${findings.count(s)} ${LABEL[s].toLowerCase()}`).join("  ·  ");
  L.push(`**Resumen:** ${counts}  ·  ✅ ${findings.checks.filter((c) => c.status === "pass").length} comprobaciones OK`, "");
  if (!items.length) { L.push("No se han detectado problemas en las comprobaciones automáticas. Eso no es un certificado: es la lista de lo que este escáner mira.", ""); }
  else {
    L.push("| # | Sev | Hallazgo |", "|---|---|---|");
    items.forEach((f, i) => L.push(`| ${i + 1} | ${ICON[f.severity]} ${LABEL[f.severity]} | ${f.title} |`));
    L.push("");
    items.forEach((f, i) => {
      L.push(`### ${i + 1}. ${ICON[f.severity]} ${f.title}`, "");
      L.push(`**Evidencia:** \`${(f.evidence || "").replace(/`/g, "'")}\`  `, "");
      L.push(`**Por qué importa:** ${f.why}  `, "");
      L.push(`**Cómo se arregla:** ${f.fix}`, "");
    });
  }
  L.push("---", "");
  L.push("<details><summary>Comprobaciones que pasaron / se omitieron</summary>", "");
  for (const c of findings.checks) L.push(`- ${c.status === "pass" ? "✅" : "⏭️"} **${c.check}** — ${c.title}${c.reason ? ` (${c.reason})` : ""}`);
  L.push("", "</details>", "");
  L.push("> Escaneo pasivo de un dominio propio (verificado por DNS). No sustituye una auditoría ni un pentest. Generado con app-security-checkup.");
  return L.join("\n");
}

export function toText(domain, findings) {
  const items = findings.sorted();
  const L = [`\nChequeo de seguridad · ${domain}`, `${ICON.high} ${findings.count("high")} alto · ${ICON.medium} ${findings.count("medium")} medio · ${ICON.low} ${findings.count("low")} bajo\n`];
  items.forEach((f, i) => L.push(`${i + 1}. [${LABEL[f.severity].toUpperCase()}] ${f.title}\n   ${f.evidence}\n   → ${f.fix}\n`));
  if (!items.length) L.push("Sin hallazgos automáticos.\n");
  return L.join("\n");
}
