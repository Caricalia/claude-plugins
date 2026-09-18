#!/usr/bin/env node
// app-security-checkup — chequeo de seguridad de TU app.
// No lanza NADA contra el objetivo hasta verificar que el dominio es tuyo.
import { verifyOwnership, ownershipHelp, tokenFor, TXT_LABEL } from "../src/ownership.mjs";
import { run } from "../src/run.mjs";
import { toMarkdown, toText, toJson } from "../src/report.mjs";
import { writeFileSync, readFileSync } from "node:fs";

const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url))).version;

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(`--${n}`);
const domain = args.find((a) => !a.startsWith("--") && !isFlagValue(a));
function isFlagValue(a) { const i = args.indexOf(a); return i > 0 && ["--out", "--json", "--api-base", "--max", "--rate", "--token"].includes(args[i - 1]); }

if (!domain || has("help")) {
  console.log(`
app-security-checkup — revisa la seguridad de TU app web (solo lectura, sin exploits).

  npx app-security-checkup <dominio> [opciones]

Opciones:
  --token          Muestra el token de verificación para este dominio y sale.
  --out <fichero>  Guarda el informe markdown (por defecto: <dominio>-checkup.md).
  --json <fichero> Guarda el informe JSON (por defecto: <dominio>-checkup.json).
                   Formato: report-schema.json.
  --api-base <url> Base de tu API si no está en la raíz (p.ej. https://dom/api).
  --max <n>        Máx. de peticiones (defecto 250).
  --rate <n>       Peticiones por segundo (defecto 3).

Primero verifica que el dominio es tuyo (DNS TXT o fichero). Ejecuta con --token
para ver cómo. Sin verificación no se hace ninguna petición al dominio.
`);
  process.exit(domain ? 0 : 1);
}

const token = opt("token") ?? tokenFor(domain);
if (has("token")) {
  console.log(ownershipHelp(domain, token));
  process.exit(0);
}

console.error(`Verificando propiedad de ${domain}…`);
const own = await verifyOwnership(domain, token);
if (!own.verified) {
  console.error("\n❌ No verificado.\n");
  console.error(ownershipHelp(domain, token));
  process.exit(2);
}
console.error(`✅ Propiedad verificada (${own.txt ? "DNS TXT" : "fichero .well-known"}). Escaneando…\n`);

const { findings, requests, edge, challenged } = await run(domain, { max: Number(opt("max", 250)), perSecond: Number(opt("rate", 3)), apiBase: opt("api-base") });
const meta = { requests, edge, challenged, version: VERSION, generatedAt: new Date().toISOString() };
const out = opt("out", `${domain}-checkup.md`);
const jsonOut = opt("json", `${domain}-checkup.json`);
writeFileSync(out, toMarkdown(domain, findings, meta));
writeFileSync(jsonOut, JSON.stringify(toJson(domain, findings, meta), null, 2) + "\n");
console.log(toText(domain, findings, meta));
console.error(`Informe completo: ${out} · JSON: ${jsonOut} · ${requests} peticiones\n`);
// Código de salida para CI: 1 solo si hay un confirmado alto o crítico.
process.exit(findings.count("critical") || findings.count("high") ? 1 : 0);
