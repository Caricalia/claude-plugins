// Cliente HTTP con presupuesto: pocas peticiones, lentas, identificadas.
// Es lo que hace que la herramienta no sirva como arma: sin cuerpo, sin
// wordlists, sin reintentos agresivos, y con un User-Agent que dice quién es.
import { setTimeout as sleep } from "node:timers/promises";

export const USER_AGENT = "app-security-checkup/0.1 (+https://github.com/Caricalia/claude-plugins; solo dominios propios)";

export class Budget {
  constructor({ max = 250, perSecond = 3 } = {}) {
    this.max = max; this.used = 0; this.interval = 1000 / perSecond; this.last = 0;
  }
  async take() {
    if (this.used >= this.max) throw new Error(`Presupuesto agotado (${this.max} peticiones). No se hacen más.`);
    const wait = this.last + this.interval - Date.now();
    if (wait > 0) await sleep(wait);
    this.last = Date.now(); this.used++;
  }
}

// Solo GET/HEAD/OPTIONS. Un método con cuerpo aquí es un bug, no una opción.
const ALLOWED = new Set(["GET", "HEAD", "OPTIONS"]);

export function makeClient(budget, { timeoutMs = 10000 } = {}) {
  return async function request(url, { method = "GET", headers = {}, redirect = "manual", maxBody = 200_000 } = {}) {
    if (!ALLOWED.has(method)) throw new Error(`Método no permitido: ${method}`);
    await budget.take();
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    const started = Date.now();
    try {
      const res = await fetch(url, { method, headers: { "user-agent": USER_AGENT, ...headers }, redirect, signal: ctl.signal });
      let body = "";
      if (method !== "HEAD") {
        const buf = Buffer.from(await res.arrayBuffer());
        body = buf.subarray(0, maxBody).toString("utf8");
        res.truncated = buf.length > maxBody; res.bytes = buf.length;
      }
      return { ok: true, status: res.status, headers: res.headers, body, bytes: res.bytes ?? 0, ms: Date.now() - started, url };
    } catch (e) {
      return { ok: false, status: 0, headers: new Headers(), body: "", bytes: 0, ms: Date.now() - started, url, error: e.name === "AbortError" ? "timeout" : (e.cause?.code || e.message) };
    } finally { clearTimeout(t); }
  };
}

// Distingue "esta ruta existe" de "el SPA devuelve index.html para todo".
// Sin esto, cada .env que pides parece un 200 y el informe es ruido.
export function makeFingerprint(baselineBody, baselineStatus) {
  const b = normalize(baselineBody);
  return (res) => res.status === baselineStatus && normalize(res.body) === b;
}
const normalize = (s) => s.replace(/\s+/g, " ").replace(/nonce-[A-Za-z0-9+/=]+/g, "nonce").trim();
