## 1. Información General

**Empresa/Partner:** Seguridad Digital EC
**Responsable del Reto:** Ola Bini
**Correo Electrónico:** ola@seguridaddigital.ec
**Cargo:** Principal Security Consultant
**Nombre del Reto:** Operación Huella Digital: Investigación y Detección de un Incidente Corporativo

**Categoría (marque con una X):**

* [x] Universitarios
* [ ] Profesionales

**Enfoque (marque con una X):**

* [x] Blue Team
* [ ] Red Team
* [ ] SOC Operations
* [x] Incident Response

---

## 2. Contexto Empresarial

AndesLogística S.A. es una empresa ficticia de aproximadamente 150 colaboradores que utiliza infraestructura tecnológica para gestionar sus operaciones administrativas, financieras y logísticas.

El área de tecnología ha recibido una alerta relacionada con un volumen inusual de tráfico saliente originado desde una estación de trabajo perteneciente al área financiera. Debido a las características de la actividad detectada, existe preocupación sobre un posible incidente de seguridad que podría involucrar el compromiso de una cuenta corporativa, acceso no autorizado a recursos internos y posible exposición de información empresarial.

La organización dispone de registros provenientes de diferentes componentes de su infraestructura, pero actualmente el análisis de esta información se realiza principalmente de forma manual y cada fuente de información es revisada de manera independiente.

La empresa requiere determinar qué ocurrió, establecer el posible alcance del incidente e identificar mecanismos que permitan detectar y analizar de manera más eficiente incidentes similares en el futuro.

---

## 3. Contexto Técnico

La infraestructura de AndesLogística S.A. incluye estaciones de trabajo Windows, servicios de autenticación centralizada, servidores internos, servicios DNS, firewall y proxy corporativo.

Luego de detectar tráfico saliente inusual desde una estación de trabajo, el equipo de seguridad recopiló diferentes fuentes de evidencia correspondientes al período en el cual habría ocurrido el incidente.

Entre las evidencias disponibles se encuentran registros de autenticación, resolución DNS, conexiones de red, navegación web, eventos generados por estaciones de trabajo y una captura parcial de tráfico de red.

Las fuentes contienen tanto actividad legítima de usuarios y sistemas como eventos potencialmente relacionados con el incidente. Los registros deberán ser analizados y correlacionados para establecer una secuencia coherente de acontecimientos.

La organización no dispone actualmente de una solución que permita correlacionar automáticamente estas fuentes para identificar patrones de actividad potencialmente maliciosa.

---

## 4. Problema

La organización ha identificado actividad anómala asociada con uno de sus equipos, pero desconoce el origen, desarrollo, alcance e impacto potencial del incidente.

Los equipos participantes deberán analizar las evidencias proporcionadas, identificar los eventos relevantes y reconstruir, en la medida permitida por la evidencia disponible, la secuencia del incidente.

Además del análisis, deberán diseñar e implementar una solución técnica que permita a la organización identificar, correlacionar o analizar de manera más eficiente comportamientos similares en futuras investigaciones.

La solución deberá demostrar capacidad para trabajar con las fuentes de información suministradas y aportar valor al proceso de detección o respuesta frente a incidentes de seguridad.

Los participantes deberán diferenciar claramente entre hechos demostrados por la evidencia, hipótesis razonables y aspectos que no puedan determinarse con la información disponible.

---

## 5. Objetivo Empresarial del Reto

Fortalecer las capacidades de detección y respuesta frente a incidentes de ciberseguridad mediante el análisis y correlación de diferentes fuentes de evidencia, permitiendo comprender el alcance de un incidente y desarrollar una solución que facilite la identificación y análisis de comportamientos similares en el futuro.

---

## 6. Recursos Entregados

Cada equipo recibirá un conjunto de evidencias digitales generadas para un escenario empresarial simulado.

Los recursos incluirán:

* Registros de autenticación en formato CSV.
* Registros de consultas y resoluciones DNS en formato CSV.
* Registros de conexiones de firewall en formato CSV.
* Registros de navegación mediante proxy en formato CSV.
* Registros de eventos provenientes de estaciones de trabajo en formato CSV.
* Captura parcial de tráfico de red en formato PCAP.
* Documento con información general sobre la infraestructura tecnológica simulada.
* Descripción de los formatos y campos principales de las fuentes proporcionadas.

Los registros contendrán actividad legítima y actividad potencialmente relacionada con el incidente. Será responsabilidad de los equipos identificar, correlacionar y justificar los eventos considerados relevantes.

---

## 7. Entregables Esperados (marque con una X)

* [x] Pitch con una duración de tres minutos.
* [x] Ficha técnica en formato PDF.
* [x] Código fuente.
* [x] Prototipo.
* [x] Evidencia de pruebas.
* [ ] Otros.

La ficha técnica deberá incluir la descripción de los principales resultados de la investigación, las evidencias que los sustentan, una línea de tiempo del incidente y una descripción de la solución desarrollada.

El código fuente o prototipo deberá permitir demostrar el funcionamiento de la solución propuesta utilizando las evidencias proporcionadas.

---

## 8. Tiempo Sugerido (marque con una X)

* [ ] 6 horas
* [ ] 12 horas
* [x] 24 horas

---

## 9. Nivel de Dificultad (marque con una X)

* [ ] Básico
* [x] Intermedio
* [ ] Avanzado

---

## 10. Criterios de Evaluación

| Criterio                 | Puntaje |
| ------------------------ | ------: |
| Comprensión del problema |      10 |
| Innovación               |      20 |
| Viabilidad técnica       |      20 |
| Impacto empresarial      |      15 |
| Seguridad de la solución |      15 |
| Escalabilidad            |      10 |
| Calidad del pitch        |      10 |
| **Total**                | **100** |

---

## 11. Requisito Técnicos

**Hardware:**

* Computador portátil.
* Se recomienda un mínimo de 8 GB de memoria RAM.
* Espacio disponible para almacenar y procesar las evidencias proporcionadas.

**Software:**

* Sistema operativo Windows, GNU/Linux o macOS.
* Navegador web.
* Herramientas para análisis de archivos CSV.
* Herramientas para análisis de capturas PCAP.
* Lenguaje de programación, scripting o plataforma de desarrollo seleccionada por el equipo.
* Herramientas adicionales que el equipo considere necesarias para desarrollar su solución.

**Otros:**

* Acceso a Internet.
* Navegador Web.

Los equipos podrán utilizar herramientas Open Source, frameworks, librerías, plataformas de análisis, contenedores y herramientas de Inteligencia Artificial conforme al Reglamento Oficial del Hackathon.

---

## 12. Restricciones

Los participantes deberán trabajar exclusivamente con las evidencias y recursos proporcionados para el reto.

No se requiere ni se autoriza realizar pruebas sobre infraestructura real de Seguridad Digital EC, UIDE, AndesLogística S.A. o cualquier otra organización.

No está permitido escanear o atacar redes externas, la infraestructura del evento, equipos de otros participantes o servicios disponibles en Internet.

Para efectos del reto, las evidencias, registros, capturas de tráfico y demás recursos proporcionados deberán ser tratados como información confidencial de la organización. Estos materiales no podrán ser cargados, copiados, transmitidos ni compartidos con servicios externos, incluyendo herramientas de Inteligencia Artificial generativa, chatbots, plataformas de análisis en línea u otros servicios de terceros.

La captura PCAP y los registros proporcionados constituyen información simulada específicamente preparada para el Hackathon.

Los participantes podrán utilizar herramientas y servicios disponibles en Internet para desarrollar y documentar su solución, siempre que su utilización sea compatible con el Reglamento Oficial y el Código de Conducta del Hackathon.

La evaluación se centrará en el análisis realizado, la justificación técnica de las conclusiones y el valor aportado por la solución desarrollada.

---

## 13. Observaciones

No existe una tecnología o arquitectura obligatoria para resolver el reto. Los equipos podrán seleccionar las herramientas, metodologías y tecnologías que consideren apropiadas.

La utilización de Inteligencia Artificial no constituye por sí misma un elemento de innovación ni proporciona puntaje adicional. Toda solución presentada deberá ser comprendida, validada y justificada técnicamente por sus integrantes.

Las conclusiones relacionadas con el incidente deberán estar respaldadas por evidencia. Cuando la información disponible no permita establecer un hecho con certeza, el equipo deberá indicarlo expresamente y podrá presentar hipótesis debidamente fundamentadas.

Se valorarán especialmente las soluciones capaces de correlacionar información procedente de diferentes fuentes, reducir el trabajo manual requerido durante una investigación y presentar resultados de manera comprensible y útil para un equipo de seguridad.
