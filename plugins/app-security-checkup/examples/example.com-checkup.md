# Chequeo de seguridad · example.com

_Informe de ejemplo (sintético). Solo lectura, sin explotación._

**Resumen:** 🔴 2 alto  ·  🟠 3 medio  ·  🟡 1 bajo  ·  ✅ 9 comprobaciones OK

| # | Sev | Hallazgo |
|---|---|---|
| 1 | 🔴 Alto | El origen responde saltándose el CDN |
| 2 | 🔴 Alto | Fichero sensible accesible: /.env |
| 3 | 🟠 Medio | CSP con 'unsafe-inline' sin nonce/hash |
| 4 | 🟠 Medio | CORS refleja cualquier Origin |
| 5 | 🟠 Medio | Cookie 'session' sin HttpOnly |
| 6 | 🟡 Bajo | Sin DMARC |

### 1. 🔴 El origen responde saltándose el CDN
**Evidencia:** `TLS al host del hosting con Host example.com → HTTP 200`
**Por qué importa:** WAF, rate-limit y cabeceras del CDN no aplican a quien conecte directamente al origen.
**Cómo se arregla:** Cloudflare Tunnel o Authenticated Origin Pulls; como mínimo, allowlist de IPs del CDN. Y borra los dominios públicos del hosting.

### 2. 🔴 Fichero sensible accesible: /.env
**Evidencia:** `HTTP 200, 412 bytes, text/plain (no se muestra el contenido)`
**Por qué importa:** un `.env` servido por HTTP es una credencial pública.
**Cómo se arregla:** deniega la ruta en el borde, saca el fichero del directorio público y rota lo que hubiera dentro.

### 3. 🟠 CSP con 'unsafe-inline' sin nonce/hash
**Evidencia:** `script-src permite scripts inline sin nonce ni hash`
**Por qué importa:** el vector más común de XSS (inyectar scripts inline) sigue abierto.
**Cómo se arregla:** usa 'nonce-<aleatorio>' por respuesta o hashes; quita 'unsafe-inline' de script-src.

_(Informe recortado para el ejemplo.)_
