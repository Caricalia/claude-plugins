# claude-plugins

Marketplace de plugins/skills de [Claude Code](https://claude.com/claude-code)
de [@caricalia](https://github.com/Caricalia).

## Instalar en Claude Code

```
/plugin marketplace add Caricalia/claude-plugins
/plugin install <plugin>@caricalia
```

## Plugins

| Plugin | Qué hace |
|--------|----------|
| [`app-security-checkup`](plugins/app-security-checkup) | Chequeo de seguridad pasivo de tu propia web (verificado por DNS): origen fuera del CDN, subdominios secuestrables, CSP/cabeceras, CORS, cookies, ficheros/endpoints expuestos, open redirect, host-header y reflexión (XSS). Solo lectura, sin exploits. |

## Estructura

```
.claude-plugin/marketplace.json     ← lista de plugins de este marketplace
plugins/<nombre>/                    ← un plugin por carpeta
  ├── .claude-plugin/plugin.json
  ├── SKILL.md
  └── ...
```

Para añadir un plugin: crea `plugins/<nombre>/` con su `SKILL.md` (y
`.claude-plugin/plugin.json`), y añádelo al array `plugins` de
`.claude-plugin/marketplace.json`.
