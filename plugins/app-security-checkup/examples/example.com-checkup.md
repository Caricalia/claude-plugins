# Chequeo de seguridad · example.com

_Informe de ejemplo (sintético). Solo lectura, sin explotación._

**Confirmados:** 🟣 1 crítico · 🔴 2 alto · 🟠 0 medio · 🟡 1 bajo  
**Por validar:** 1 · **Endurecimiento:** 2 · ✅ 24 comprobaciones OK

> **Confirmado** = el escáner lo ha observado. **Por validar** = hay un indicio y falta un dato que no se ve desde fuera; no lleva severidad hasta comprobarlo. **Endurecimiento** = falta una capa de defensa, pero no hay un fallo demostrado.

## Confirmados

### 1. 🟣 Crítico · Credencial en el JavaScript público: Stripe secret key

**Evidencia:** `/assets/index-3f9a.js: sk_live_…(32 chars)`  
**Por qué importa:** Todo lo que va en el bundle lo descarga cualquier visitante. Una clave secreta ahí es una clave pública.  
**Cómo se arregla:** Rota la clave YA y mueve la llamada al servidor. Solo las variables `NEXT_PUBLIC_`/`VITE_` llegan al cliente: una secreta nunca debe llevar ese prefijo.

### 2. 🔴 Alto · El origen responde saltándose el CDN

**Evidencia:** `TLS a example.up.railway.app con SNI/Host example.com → HTTP 200`  
**Por qué importa:** WAF, rate-limit y cabeceras del CDN no aplican a quien conecte directamente al origen.  
**Cómo se arregla:** Cloudflare Tunnel o Authenticated Origin Pulls; como mínimo, allowlist de IPs del CDN. Y borra los dominios públicos del hosting.

**Compruébalo tú:**

```sh
curl -s -o /dev/null -D - --connect-to example.com:443:example.up.railway.app:443 'https://example.com/'
```

### 3. 🔴 Alto · Fichero sensible accesible: /.env

**Evidencia:** `HTTP 200, 412 bytes, text/plain (no se muestra el contenido)`  
**Por qué importa:** un `.env` servido por HTTP es una credencial pública.  
**Cómo se arregla:** deniega la ruta en el borde, saca el fichero del directorio público y rota lo que hubiera dentro.

### 4. 🟡 Bajo · Source maps públicos

**Evidencia:** `https://example.com/assets/index-3f9a.js.map`  
**Por qué importa:** cualquiera reconstruye tu código fuente original y encuentra antes el siguiente fallo.  
**Cómo se arregla:** `build.sourcemap: false` (Vite) / `productionBrowserSourceMaps: false` (Next.js), o súbelos solo a tu herramienta de errores.

## Por validar

### 5. 🔍 Parámetro reflejado sin escapar en HTML (indicio de XSS): ?q

**Evidencia:** `El marcador con caracteres < > " ' se devolvió crudo en la respuesta HTML (parámetros: q). No se inyectó ningún script.`  
**Qué falta comprobar:** ¿El marcador cae en un contexto donde se ejecuta (HTML, atributo sin comillas, `<script>`) y no lo neutraliza la CSP? Ábrelo en el navegador y mira dónde aparece.  
**Cómo se arregla:** escapa toda salida según su contexto y usa una CSP sin `'unsafe-inline'`.

## Endurecimiento

### 6. 🛡️ (prioridad alta) · Sin Content-Security-Policy

**Evidencia:** `No hay cabecera CSP en la home`  
**Cómo se arregla:** empieza en `Content-Security-Policy-Report-Only` para no romper nada y ve apretando.

### 7. 🛡️ (prioridad baja) · Sin /.well-known/security.txt

**Evidencia:** `HTTP 404`  
**Cómo se arregla:** publica `security.txt` con `Contact:` y `Expires:`.

_(Informe recortado para el ejemplo.)_
