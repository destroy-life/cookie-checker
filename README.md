# cookie-checker

Validador multi-servicio de sesiones y cookies en tiempo real con exportación limpia para **Cookie-Editor**.

## Servicios soportados

| Servicio | Identificador | Plan / Métricas | Validación Backend |
| :--- | :--- | :--- | :--- |
| **ChatGPT** | `chatgpt` | Free, Go, Plus, Team, Pro, Business, Enterprise | Token Bearer contra `/backend-api` (evita sesiones revocadas) |
| **Spotify** | `spotify` | Free, Premium, Duo, Family, Student | Token Web Player contra `/v1/me` y endpoints de producto |
| **Crunchyroll** | `crunchyroll` | Free, Fan, Mega Fan, Ultimate Fan | Token OAuth `etp_rt` contra `/accounts/v1/me` |
| **Netflix** | `netflix` | Basic, Standard, Standard with Ads, Premium | Scraping de membresía en `/account` (filtra cuentas canceladas) |
| **Claude** | `claude` | Free, Pro, Team, Max | Verificación de identidad en `/api/account` y `/api/organizations` |
| **Grok** | `grok` | Free, XPremium, SuperGrok, SuperGrokHeavy | Sesión SSO y verificación en `/rest/subscriptions` |
| **Cursor** | `cursor` | Free, Pro, Business | JWT WorkOS y verificación de uso en `/api/auth/me` |
| **Twitter / X** | `twitter` / `x` | Free, Premium (Blue) | API `/verify_credentials` + fallback en `/home` con CSRF dinámico |
| **Roblox** | `roblox` | Formato plano | Token `.ROBLOSECURITY` |

---

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Pruebas

```bash
python -m pytest
```

## Uso

```bash
# Revisar todas las cookies presentes
python main.py

# Revisar servicios específicos
python main.py --services chatgpt,spotify
python main.py --services netflix,crunchyroll --clean

# Limpiar solo los resultados de los servicios seleccionados en esta corrida
python main.py --clean
```

> **Nota:** `--services` no admite valores vacíos. `--clean` solo elimina los directorios de salida pertenecientes a los servicios evaluados en esa ejecución, preservando el resto.

---

## Estructura de carpetas

### Entrada (`cookies/`)
Puedes colocar archivos sueltos o en subcarpetas por servicio:

```plaintext
cookies/
  ├── ChatGPT/
  ├── Spotify/
  ├── Crunchyroll/
  ├── Netflix/
  ├── Claude/
  ├── Grok/
  ├── Cursor/
  ├── Twitter/        # o X/
  └── Roblox/
```

**Formatos soportados:**
- JSON de Cookie-Editor (`.json`).
- Formato Netscape (`.txt`, `.cookies`, `.cookie`).
- Cabeceras crudas en formato `nombre=valor; nombre2=valor2;`.

### Salida (`output/`)

```plaintext
output/
  ├── valid/
  │    ├── <Servicio>/
  │    │    └── <Plan>/
  │    │         └── <label>.json
  │    └── Roblox/
  │         └── <usuario>.json       # Roblox se guarda plano sin subcarpeta de plan
  ├── invalid/
  │    └── <Servicio>/
  │         └── <label>.json         # Inválidas agrupadas planas por servicio
  └── reports/
       ├── progress.jsonl            # Registro detallado de cada jar procesado
       └── summary.txt               # Resumen final por conteos y planes
```

Las carpetas vacías (como `unknown/`) no se crean innecesariamente al finalizar la ejecución.

---

## Reglas de etiquetado (`<label>.json`)

- **Email real:** Si el servicio devuelve el correo del usuario, se usa como nombre del archivo (`correo@dominio.com.json`).
- **Handle / Usuario:** Para Twitter y Roblox, se utiliza el `@handle` o nombre de usuario.
- **Contadores atómicos:** Si no hay identidad pública disponible, se asigna `Alive#1`, `Dead#1`, etc.
- **Anti-colisión:** Si un nombre ya existe en la carpeta de destino, se añade automáticamente un sufijo numérico basado en el digest de la cookie para evitar sobreescrituras accidentales.

---

## Comportamiento y protecciones técnicas

- **Flujo en vivo (Live Stream):** Cada cookie se valida, se escribe de forma atómica en disco y se imprime en pantalla inmediatamente, sin esperar a que termine el lote completo.
- **Descarte de duplicados (`skipped_dup`):** Detecta cookies con sesiones idénticas dentro de la misma ejecución mediante un fingerprint hash para no procesar ni escribir duplicados.
- **Formato Cookie-Editor:** Los archivos válidos exportados son listas JSON estructuradas con soporte para división de tokens largos (`__Secure-next-auth.session-token.0`, `.1`, etc.).
- **Tolerancia a WAF y Red:** Respuestas 403 de Cloudflare, rate limits 429 o caídas del servidor no descartan cookies vivas hacia la carpeta de inválidas; se clasifican como dudosas para evitar falsos negativos.
