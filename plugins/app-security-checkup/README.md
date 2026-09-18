# app-security-checkup

Chequeo de seguridad **pasivo** de una web propia. Solo lectura (GET/HEAD), sin
payloads de ataque, a pocas peticiones por segundo. **No lanza nada contra un
dominio hasta verificar que es tuyo** por DNS o por un fichero — es a propósito:
esto revisa tu casa, no la de otros.

## Uso en Claude Code (recomendado)

```
/plugin marketplace add Caricalia/claude-plugins
/plugin install app-security-checkup@caricalia
```

Luego, en cualquier sesión:

```
/app-security-checkup tudominio.com
```

Claude corre el chequeo, te dice qué registro TXT poner para verificar el
dominio y, al relanzar, te da el informe con los hallazgos y su arreglo.

## Uso sin Claude Code (CLI)

Clona el repo y ejecuta el script (Node ≥ 20, sin dependencias):

```bash
git clone https://github.com/Caricalia/claude-plugins
node claude-plugins/plugins/app-security-checkup/bin/checkup.mjs tudominio.com --token   # ver token
node claude-plugins/plugins/app-security-checkup/bin/checkup.mjs tudominio.com           # escanear
```

Genera `tudominio.com-checkup.md` y `tudominio.com-checkup.json` (formato en
[`report-schema.json`](report-schema.json)). Cada hallazgo trae el arreglo
concreto para Cloudflare / Vercel / Railway / nginx y un comando para que lo
compruebes tú. Mira un informe de ejemplo en [`examples/`](examples/).

Sale con código 1 si hay algún hallazgo **confirmado** alto o crítico, así que
sirve como paso de CI.

## Cómo se lee el informe

Los hallazgos van en tres bloques que no se mezclan:

| Bloque | Qué significa | Severidad |
|---|---|---|
| **Confirmados** | El escáner lo ha observado (un `.env` servido, una clave en el JS, un subdominio secuestrable). | Crítico / alto / medio / bajo, según lo que consigue un atacante. |
| **Por validar** | Hay un indicio, pero el dato decisivo no se ve desde fuera (¿esa reflexión llega a ejecutarse?, ¿ese CORS devuelve datos del usuario?). | Ninguna hasta comprobarlo. Trae la pregunta exacta. |
| **Endurecimiento** | Falta una capa de defensa (CSP, HSTS, cabeceras), sin un fallo explotable demostrado. | Ninguna; solo prioridad orientativa. |

Así un "alto" siempre significa algo, y una cabecera que falta no se vende
como una vulnerabilidad.

Si tu WAF (Cloudflare, Vercel…) responde al escáner con un challenge de bots,
lo detecta, avisa de que el informe es parcial y te dice cómo dejarlo pasar un
momento. Sin esto, las cabeceras que revisaría serían las de la página del
challenge, no las de tu web.

## Qué mira

- **Origen alcanzable fuera del CDN** — el fallo que hace opcional todo tu WAF.
- **Subdominios colgando** (takeover), SPF/DMARC, HSTS/TLS/redirección.
- **Cabeceras y CSP** — `unsafe-inline`/`unsafe-eval`/comodín, nosniff, framing, fugas de versión.
- **CORS** reflejado (+ credenciales), **flags de cookies** de sesión.
- **Ficheros sensibles** (`.env`, `.git`, claves, dumps) y **endpoints de diagnóstico** (actuator, metrics, pprof, swagger), con filtro anti-falso-positivo para SPAs.
- **Bypass de routing** (`/;/`, `/..;/`, `%2e`), **open redirect**, **host-header injection**.
- **Reflexión de parámetros sin escapar** (indicador de XSS), sin inyectar scripts.
- **Lo que publica tu frontend sin querer**: claves secretas en el bundle JS (AWS, Stripe, OpenAI, Anthropic, GitHub, Slack, `service_role` de Supabase…), source maps públicos, scripts de terceros sin SRI y contenido mixto.
- **Más cabeceras y DNS**: Permissions-Policy, COOP, CAA, DKIM, `security.txt`, y respuestas con cookie de sesión que el CDN podría cachear.

## Qué NO hace

No hace fuzzing, ni prueba inyecciones, ni fuerza bruta, ni ejecuta exploits.
Es un chequeo de configuración, no un pentest, y no sustituye a uno.

Tampoco lee tu código. Ve la web desde fuera: lo que de verdad sirve tu CDN,
tu DNS y tu hosting. Para revisar el código fuente (autorización, lógica,
aislamiento entre clientes) usa algo como
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill).
Las dos cosas se complementan: esa skill deja como "por validar" justo lo que
no se ve en el código (proxy, cabeceras, despliegue), y eso es lo que mira esta.

## Ética

Solo para dominios que controlas. La verificación de propiedad es obligatoria y
no se puede desactivar por flag. El escaneo se identifica con un User-Agent
propio y respeta un presupuesto bajo de peticiones.

## Créditos

La separación entre confirmado, por validar y endurecimiento, y la regla de que
la severidad depende de lo que consigue un atacante y no de lo que falta, están
inspiradas en [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
(MIT, © Cloudflare, Inc.). No se ha copiado código: esa skill audita código
fuente con agentes y esta escanea una web desde fuera.

## Desarrollo

```bash
npm test   # tests offline con respuestas simuladas, sin red
```

MIT · [@caricalia](https://github.com/Caricalia)
