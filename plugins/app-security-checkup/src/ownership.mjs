// Prueba de propiedad. Sin ella el script no lanza NI UNA petición al
// objetivo. Es la misma idea que Let's Encrypt o Search Console: si puedes
// poner un TXT en el DNS o un fichero en /.well-known, el dominio es tuyo.
import { resolveTxt } from "node:dns/promises";
import { createHash } from "node:crypto";
import { hostname } from "node:os";
import { USER_AGENT } from "./http.mjs";

export const TXT_LABEL = "_security-checkup";
export const WELL_KNOWN = "/.well-known/security-checkup.txt";

// Token estable por máquina+dominio: puedes ponerlo una vez y repetir el
// chequeo cada semana sin cambiar el DNS.
export function tokenFor(domain) {
  return "checkup-" + createHash("sha256").update(`${hostname()}|${domain}`).digest("hex").slice(0, 24);
}

export async function verifyOwnership(domain, token) {
  const results = { txt: false, file: false, errors: [] };
  try {
    const records = await resolveTxt(`${TXT_LABEL}.${domain}`);
    results.txt = records.some((r) => r.join("").trim() === token);
  } catch (e) { results.errors.push(`TXT: ${e.code || e.message}`); }
  if (!results.txt) {
    try {
      const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 8000);
      const res = await fetch(`https://${domain}${WELL_KNOWN}`, { headers: { "user-agent": USER_AGENT }, redirect: "manual", signal: ctl.signal });
      clearTimeout(t);
      results.file = res.status === 200 && (await res.text()).trim() === token;
    } catch (e) { results.errors.push(`fichero: ${e.cause?.code || e.message}`); }
  }
  return { verified: results.txt || results.file, ...results };
}

export function ownershipHelp(domain, token) {
  return [
    `Este dominio no está verificado como tuyo. Elige UNA de estas dos opciones y vuelve a ejecutar:`,
    ``,
    `  1) Registro DNS TXT:`,
    `       ${TXT_LABEL}.${domain}   TXT   "${token}"`,
    ``,
    `  2) Fichero en tu web, con este contenido exacto:`,
    `       https://${domain}${WELL_KNOWN}`,
    `       ${token}`,
    ``,
    `Sin esto el script no hace ninguna petición al dominio. Es a propósito.`,
  ].join("\n");
}
