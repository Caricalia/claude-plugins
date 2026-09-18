// Tests offline: respuestas simuladas, ninguna petición de red.
// npm test  (o: node --test test/checkup.test.mjs)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Findings } from "../src/findings.mjs";
import { checkAssets } from "../src/checks/assets.mjs";
import { detectChallenge, detectEdge } from "../src/run.mjs";
import { toJson, toMarkdown } from "../src/report.mjs";

const res = (status, body = "", headers = {}) => ({ ok: true, status, body, bytes: body.length, headers: new Headers(headers) });
const fakeRequest = (routes) => async (url) => routes[url] || res(404);
const ctxFor = (html, routes = {}) => ({ domain: "ejemplo.test", findings: new Findings(), request: fakeRequest(routes), home: res(200, html, { "content-type": "text/html" }) });
// Construido por partes para que el fichero no contenga un literal con forma de clave.
const fakeStripe = ["sk", "live", "0123456789abcdefghijABCD"].join("_");

test("Findings: un confirmado sin severidad es un error", () => {
  assert.throws(() => new Findings().add("x", { id: "X", title: "t" }), /severidad/);
});

test("Findings: needs_validation exige la pregunta exacta y no lleva severidad", () => {
  const f = new Findings();
  assert.throws(() => f.add("x", { id: "X", status: "needs_validation", severity: "high", title: "t" }), /unresolved/);
  f.add("x", { id: "X", status: "needs_validation", severity: "high", unresolved: "¿…?", title: "t" });
  assert.equal(f.items[0].severity, null);
});

test("Findings: sorted() pone confirmados por severidad, luego por validar, luego endurecimiento", () => {
  const f = new Findings();
  f.add("x", { id: "H", status: "hardening", priority: "high", title: "h" });
  f.add("x", { id: "L", severity: "low", title: "l" });
  f.add("x", { id: "N", status: "needs_validation", unresolved: "?", title: "n" });
  f.add("x", { id: "C", severity: "critical", title: "c" });
  assert.deepEqual(f.sorted().map((i) => i.id), ["C", "L", "N", "H"]);
});

test("assets: detecta una clave secreta en el bundle y la redacta", async () => {
  const ctx = ctxFor(`<script src="/app.js"></script>`, { "https://ejemplo.test/app.js": res(200, `const k="${fakeStripe}";`) });
  await checkAssets(ctx);
  const hit = ctx.findings.items.find((i) => i.id === "JS-SECRET");
  assert.equal(hit.severity, "critical");
  assert.ok(!hit.evidence.includes(fakeStripe), "la evidencia no debe llevar la clave entera");
});

test("assets: ignora claves publicables", async () => {
  const ctx = ctxFor(`<script src="/app.js"></script>`, { "https://ejemplo.test/app.js": res(200, `const k="pk_live_0123456789abcdefghijABCD";`) });
  await checkAssets(ctx);
  assert.ok(!ctx.findings.items.some((i) => i.id === "JS-SECRET"));
});

test("assets: source map público, SRI ausente y contenido mixto", async () => {
  const html = `<script src="/app.js"></script><script src="https://cdn.tercero.test/lib.js"></script><img src="http://img.test/a.png">`;
  const ctx = ctxFor(html, {
    "https://ejemplo.test/app.js": res(200, "console.log(1)\n//# sourceMappingURL=app.js.map"),
    "https://ejemplo.test/app.js.map": res(200, `{"version":3,"sources":["src/a.ts"]}`),
  });
  await checkAssets(ctx);
  const ids = ctx.findings.items.map((i) => i.id);
  assert.ok(ids.includes("SOURCE-MAPS") && ids.includes("NO-SRI") && ids.includes("MIXED-CONTENT"), ids.join());
});

test("detectChallenge: Vercel, Cloudflare y página normal", () => {
  assert.equal(detectChallenge(res(403, "", { "x-vercel-mitigated": "challenge" })), true);
  assert.equal(detectChallenge(res(403, "<title>Just a moment...</title>")), true);
  assert.equal(detectChallenge(res(200, "<h1>hola</h1>")), false);
});

test("detectEdge: por cabeceras de respuesta", () => {
  assert.equal(detectEdge(new Headers({ "x-vercel-id": "cdg1::x" })), "vercel");
  assert.equal(detectEdge(new Headers({ "cf-ray": "abc-MAD" })), "cloudflare");
  assert.equal(detectEdge(new Headers({})), null);
});

test("toJson cumple los campos obligatorios del esquema", () => {
  const schema = JSON.parse(readFileSync(new URL("../report-schema.json", import.meta.url)));
  const f = new Findings();
  f.add("x", { id: "A-B", severity: "high", title: "t", evidence: "e", why: "w", fix: "f" });
  const out = toJson("ejemplo.test", f, { requests: 1, version: "0", generatedAt: new Date().toISOString() });
  for (const k of schema.required) assert.ok(k in out, `falta ${k}`);
  for (const k of schema.$defs.finding.required) assert.ok(k in out.findings[0], `hallazgo sin ${k}`);
  assert.match(toMarkdown("ejemplo.test", f, { requests: 1, generatedAt: out.generated_at }), /## Confirmados/);
});
