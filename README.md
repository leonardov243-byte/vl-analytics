<img width="800" height="450" alt="ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/66c03165-3b62-4b03-b29e-db75109d963a" />
# 📊 VL Analytics — Panel de Analíticas en Tiempo Real

Panel de analíticas propio para monitorear tráfico web en tiempo real. Recibe datos de proyectos externos conectados, analiza cada visita, detecta bots y amenazas, y genera alertas automáticas.

**Demo en vivo:** http://3.91.15.132

---

## Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| Backend | Python 3 + Flask |
| Base de datos | SQLite |
| Servidor web | Nginx (reverse proxy) |
| Proceso | Gunicorn (2 workers) |
| Sistema | systemd (arranque automático) |
| Infraestructura | AWS EC2 t2.micro (Free Tier) |
| Seguridad IPs | AbuseIPDB API |
| Almacenamiento | AWS S3 (backup automático) |
| Monitoreo | AWS CloudWatch |
| Alertas | Gmail (notificaciones automáticas) |

---

## Panel — 7 Cards en tiempo real

| Card | Descripción |
|------|-------------|
| 🌐 Total visitas | Contador global de todas las requests recibidas |
| 🔢 IPs únicas | Direcciones IP distintas detectadas |
| 📁 Proyectos | Fuentes de tráfico externas conectadas |
| 👤 Humanos | Visitas clasificadas como tráfico real |
| 🤖 Bots | Tráfico automatizado detectado |
| ⚠️ Sospechosos | IPs con comportamiento anómalo |
| 🚨 Maliciosas | IPs confirmadas en blacklists |

---

## Funcionalidades

- 🔍 Detección automática bot/humano por análisis de comportamiento
- 🛡️ Integración con AbuseIPDB para verificación de reputación de IPs
- 📧 Alertas automáticas por Gmail ante amenazas detectadas
- 💾 Backup automático de la base de datos a AWS S3
- 📈 AWS CloudWatch configurado para monitoreo de la instancia
- 🔄 Gunicorn + systemd para servicio estable en producción

---

## Proyectos externos conectados

- [CorpVL](https://github.com/leonardov243-byte/corporaciones-vl) — Sistema de autenticación empresarial que alimenta el panel con datos de cada sesión

---

## Autor

**Leonardo Vieira** — Desarrollado y desplegado integramente en AWS EC2.
---

## Arquitectura
