# Verified by User — Fractia

Estado de verificación por prueba real del usuario vs. smoke test automatizado únicamente.

---

## ✅ Verificado personalmente por el usuario

Funcionalidades que el usuario ha ejecutado en producción/staging y confirmado que funcionan:

### Attack / DAST

- **`form-flood --mode flood`** — probado contra `example.com/contact-sales`
- **`form-flood --mode user-enum`** — probado contra `example.com/contact-sales`
- **`form-flood --mode stuffing`** — probado contra `example.com/contact-sales`
- **`form-flood --mode spam`** — probado contra `example.com/contact-sales`
- **`form-flood --mode inject`** — probado contra `example.com/contact-sales`
- **`form-flood --mode all`** — ejecución secuencial de los 5 modos con reporte consolidado
- **`--form-action` + `--fields`** — bypass de descubrimiento para formularios SPA/React (probado contra `example.com/contact`)
- **Reporte JSON** — guardado en `reports/` con link clickable desde terminal

### General

- **Menú principal** — navegación entre opciones [1][2][3][c][s][p][q]
- **Selector de proyecto** — `selectProject()` funcionando

---

## ⚠️ Solo verificado por smoke test automatizado (no probado por el usuario)

Funcionalidades implementadas y verificadas con tests de Node.js pero que el usuario **no ha ejecutado personalmente en modo interactivo**:

### Attack / DAST

- **`recon`** — reconocimiento pasivo (headers de seguridad, rutas expuestas, CORS, tech stack). Implementado y pasó `--check` pero el usuario no lo ha corrido en real.
- **`spike-test`** — ráfaga concurrente de requests. Mismo estado que recon.

### Mobile Audit — Flutter/Dart Security Engine (Pilar D)

Todos los módulos han corrido en un proyecto Flutter sintético de prueba (`/tmp/fake_flutter3`) y produjeron findings correctos, pero **el usuario no ha ejecutado el motor contra un proyecto Flutter real**:

| Módulo | Estado |
|---|---|
| `auth` — Auth & Token Storage | ⚠️ Solo smoke test |
| `network` — Network & SSL Pinning | ⚠️ Solo smoke test |
| `storage` — Secure Storage | ⚠️ Solo smoke test |
| `deeplinks` — Deep Links & Navigation | ⚠️ Solo smoke test |
| `crypto` — Cryptography | ⚠️ Solo smoke test |
| `platform` — Platform Config (Android/iOS) | ⚠️ Solo smoke test |
| `deps` — Dependencies (pubspec) | ⚠️ Solo smoke test |
| `obfuscation` — Obfuscation & Build Security | ⚠️ Solo smoke test |
| `logging` — Logging & Debug Leaks | ⚠️ Solo smoke test |
| `state` — State Management Security | ⚠️ Solo smoke test |
| **`mobileAuditFlow()`** — flujo interactivo en menú `[4]` | ⚠️ Nunca ejecutado en modo interactivo |

**Para verificar:** correr `node fractia.js`, seleccionar `[4] Mobile Audit`, apuntar a un proyecto Flutter real y confirmar que el output, la barra de riesgo y el JSON report se generan correctamente.
