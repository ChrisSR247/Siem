# Operación Huella Digital — Recursos técnicos

## Escenario
AndesLogística S.A. es una organización ficticia. El equipo de seguridad detectó actividad anómala durante la mañana del 15 de octubre de 2026 y recopiló evidencias entre las 08:00 y las 14:00.

Las evidencias contienen actividad legítima y potencialmente relacionada con el incidente. No se garantiza que todos los eventos anómalos pertenezcan al mismo incidente. Las conclusiones deben sustentarse en evidencia.

## Infraestructura relevante

| Host | IP | Función |
|---|---|---|
| FIN-PC03 | 10.20.10.43 | Estación de Finanzas |
| FIN-PC07 | 10.20.10.47 | Estación de Finanzas |
| FIN-PC11 | 10.20.10.51 | Estación de Finanzas |
| IT-PC02 | 10.20.10.102 | Estación de administración TI |
| DC01 | 10.20.20.10 | Directorio y DNS |
| FS01 | 10.20.20.15 | Servidor de archivos corporativos |
| ERP01 | 10.20.20.25 | ERP interno |
| PROXY01 | 10.20.20.30 | Proxy web |

Red de usuarios: `10.20.10.0/24`. Red de servidores: `10.20.20.0/24`. El personal de Finanzas utiliza legítimamente `FS01` para acceder a recursos departamentales.

## Evidencias

- `authentication.csv`: autenticaciones y fallos de autenticación.
- `dns.csv`: consultas DNS observadas.
- `firewall.csv`: conexiones permitidas y denegadas, incluyendo volúmenes de tráfico.
- `proxy.csv`: navegación web observada por el proxy.
- `endpoint.csv`: eventos seleccionados de estaciones de trabajo, procesos y archivos.
- `suspicious-traffic.pcap`: captura parcial de tráfico de red.

Todos los timestamps utilizan el formato `YYYY-MM-DDTHH:MM:SS` y corresponden al mismo reloj de referencia.

## Alcance
Todos los datos son simulados. El reto no autoriza pruebas contra infraestructura real, servicios externos, infraestructura UIDE ni equipos de otros participantes.
