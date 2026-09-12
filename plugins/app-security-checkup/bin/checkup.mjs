#!/usr/bin/env node
// app-security-checkup — chequeo de seguridad de TU app.
// No lanza NADA contra el objetivo hasta verificar que el dominio es tuyo.
import { verifyOwnership, ownershipHelp, tokenFor, TXT_LABEL } from "../src/ownership.mjs";
import { run } from "../src/run.mjs";
import { toMarkdown, toText } from "../src/report.mjs";
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(`--${n}`);
const domain = args.find((a) => !a.startsWith("--") && !isFlagValue(a));
function isFlagValue(a) { const i = args.indexOf(a); return i > 0 && ["--out", "--api-base", "--max", "--rate", "--token"].includes(args[i - 1]); }

if (!domain || has("help")) {
  console.log(`
app-security-checkup — revisa la seguridad de TU app web (solo lectura, sin exploits).

  npx app-security-checkup <dominio> [opciones]

Opciones:
  --token          Muestra el token de verificación para este dominio y sale.
  --out <fichero>  Guarda el informe markdown (por defecto: <dominio>-checkup.md).
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

const { findings, requests } = await run(domain, { max: Number(opt("max", 250)), perSecond: Number(opt("rate", 3)), apiBase: opt("api-base") });
const md = toMarkdown(domain, findings, { requests });
const out = opt("out", `${domain}-checkup.md`);
writeFileSync(out, md);
console.log(toText(domain, findings));
console.error(`Informe completo: ${out}  ·  ${requests} peticiones\n`);
process.exit(findings.count("high") ? 1 : 0);
