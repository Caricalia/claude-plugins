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

Genera `tudominio.com-checkup.md` con los hallazgos ordenados por severidad y,
cada uno, el arreglo concreto para Cloudflare / Vercel / Railway / nginx. Mira
un informe de ejemplo en [`examples/`](examples/).

## Qué mira

- **Origen alcanzable fuera del CDN** — el fallo que hace opcional todo tu WAF.
- **Subdominios colgando** (takeover), SPF/DMARC, HSTS/TLS/redirección.
- **Cabeceras y CSP** — `unsafe-inline`/`unsafe-eval`/comodín, nosniff, framing, fugas de versión.
- **CORS** reflejado (+ credenciales), **flags de cookies** de sesión.
- **Ficheros sensibles** (`.env`, `.git`, claves, dumps) y **endpoints de diagnóstico** (actuator, metrics, pprof, swagger), con filtro anti-falso-positivo para SPAs.
- **Bypass de routing** (`/;/`, `/..;/`, `%2e`), **open redirect**, **host-header injection**.
- **Reflexión de parámetros sin escapar** (indicador de XSS), sin inyectar scripts.

## Qué NO hace

No hace fuzzing, ni prueba inyecciones, ni fuerza bruta, ni ejecuta exploits.
Es un chequeo de configuración, no un pentest, y no sustituye a uno.

## Ética

Solo para dominios que controlas. La verificación de propiedad es obligatoria y
no se puede desactivar por flag. El escaneo se identifica con un User-Agent
propio y respeta un presupuesto bajo de peticiones.

MIT · [@caricalia](https://github.com/Caricalia)
