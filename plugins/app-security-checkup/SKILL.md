---
name: app-security-checkup
description: Chequeo de seguridad pasivo de una web PROPIA (verificada por DNS). Detecta origen alcanzable saltándose el CDN, subdominios secuestrables, cabeceras/CSP débiles, CORS reflejado, cookies inseguras, ficheros y endpoints de diagnóstico expuestos, open redirect, host-header injection y reflexión de parámetros (XSS). Solo lectura, sin explotación. Úsalo cuando alguien pida "revisar la seguridad de mi web/app", "auditar mi dominio", "¿está mi sitio bien configurado?".
argument-hint: <dominio>
disable-model-invocation: true
allowed-tools: Bash(node ${CLAUDE_SKILL_DIR}/bin/checkup.mjs *)
---

# app-security-checkup

Revisa la configuración de seguridad de una web **que controlas**. Es pasivo:
solo GET/HEAD, sin payloads de ataque, a pocas peticiones por segundo, y **no
hace nada hasta verificar que el dominio es tuyo** (registro DNS TXT o fichero
en `/.well-known/`).

## Cómo ejecutarlo

El argumento es el dominio (sin `https://`). Ejecuta:

```
node ${CLAUDE_SKILL_DIR}/bin/checkup.mjs $ARGUMENTS
```

- Si el dominio **no está verificado**, el script sale con instrucciones para
  poner un TXT `_security-checkup.<dominio>` o un fichero. Cópiaselas al usuario
  tal cual y dile que vuelva a lanzar cuando lo tenga. No intentes saltarte esto.
- Si **sí** está verificado, escanea (~60-250 peticiones) y escribe un informe
  markdown `<dominio>-checkup.md`. Resume en el chat los hallazgos ordenados por
  severidad y ofrece el informe completo.
- Si la API no está en la raíz, añade `--api-base https://<dominio>/api/`.

Para ver el token de verificación de un dominio sin escanear:
`node ${CLAUDE_SKILL_DIR}/bin/checkup.mjs <dominio> --token`.

## Al presentar los resultados

- Ordena por severidad (🔴 alto → 🟡 bajo). Empieza por lo alto.
- Por cada hallazgo da: qué es, por qué importa, y el arreglo concreto para su
  stack (el informe ya trae fixes para Cloudflare / Vercel / Railway / nginx).
- No inventes hallazgos que el script no reportó. "Sin hallazgos" no es un
  certificado: es la lista de lo que este escáner mira, díselo así.
- No sugieras pasos de explotación ni pruebas ofensivas más allá del escaneo.

## Qué comprueba

Origen alcanzable fuera del CDN · subdominios colgando (takeover) · SPF/DMARC ·
HSTS/TLS/redirección · CSP (unsafe-inline/eval/comodín), X-Content-Type-Options,
framing, Referrer-Policy, fugas de versión · CORS reflejado + credenciales ·
flags de cookies de sesión · ficheros sensibles (.env, .git, claves, dumps) ·
endpoints de diagnóstico (actuator, metrics, pprof, swagger) · bypass de routing
(/;/, /..;/, %2e) · open redirect · host-header injection · reflexión de
parámetros sin escapar (indicador de XSS).
