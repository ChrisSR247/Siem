import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from config import DB_PATH
from utils import log_coloreado


def _conectar():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def inicializar_db():
    conn = _conectar()
    cursor = conn.cursor()

    # Tabla de Eventos Normalizados
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            timestamp_original TEXT,
            fuente TEXT NOT NULL,
            host TEXT,
            usuario TEXT,
            ataque TEXT,
            riesgo TEXT,
            ip_origen TEXT,
            ip_destino TEXT,
            mitre TEXT,
            detalles TEXT,
            respuesta_ia TEXT,
            modelo TEXT,
            estado TEXT DEFAULT 'pendiente',
            raw_evento TEXT
        )
    """)

    # Tabla de Incidentes Correlacionados
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incidente_id TEXT UNIQUE NOT NULL,
            titulo TEXT NOT NULL,
            empresa TEXT NOT NULL,
            fecha_incidente TEXT,
            score_riesgo INTEGER,
            severidad_global TEXT,
            host_comprometido TEXT,
            ip_host TEXT,
            usuario_comprometido TEXT,
            departamento TEXT,
            vector_inicial TEXT,
            c2_servidor TEXT,
            volumen_exfiltrado_mb REAL,
            archivos_comprometidos_total INTEGER,
            resumen_ia TEXT,
            datos_json TEXT,
            creado_en TEXT
        )
    """)

    # Tabla de Línea de Tiempo del Incidente
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS linea_tiempo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incidente_id TEXT,
            timestamp TEXT NOT NULL,
            fase TEXT NOT NULL,
            fuente TEXT NOT NULL,
            host TEXT,
            usuario TEXT,
            evento TEXT NOT NULL,
            mitre TEXT
        )
    """)

    # Tabla de Indicadores de Compromiso (IoCs)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incidente_id TEXT,
            tipo TEXT NOT NULL,
            valor TEXT NOT NULL,
            descripcion TEXT,
            mitre TEXT
        )
    """)

    # Tabla de Falsos Positivos / Distractores Suprimidos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS falsos_positivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incidente_id TEXT,
            distractor_id TEXT,
            categoria TEXT NOT NULL,
            host TEXT,
            justificacion TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def guardar_evento(
    evento_normalizado: dict,
    resultado_reglas: dict,
    resultado_ia: dict,
) -> int:
    conn = _conectar()
    try:
        cursor = conn.execute(
            """
            INSERT INTO eventos (fecha, timestamp_original, fuente, host, usuario, ataque, riesgo,
                                 ip_origen, ip_destino, mitre, detalles, respuesta_ia, modelo, estado, raw_evento)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                evento_normalizado.get("timestamp", ""),
                evento_normalizado.get("fuente", ""),
                evento_normalizado.get("host", ""),
                evento_normalizado.get("usuario", ""),
                resultado_reglas.get("ataque", ""),
                resultado_reglas.get("riesgo", ""),
                evento_normalizado.get("ip_origen", ""),
                evento_normalizado.get("ip_destino", ""),
                resultado_reglas.get("mitre", ""),
                evento_normalizado.get("detalles", ""),
                json.dumps(resultado_ia, ensure_ascii=False),
                resultado_ia.get("modelo", ""),
                resultado_ia.get("severidad", "pendiente"),
                json.dumps(evento_normalizado, ensure_ascii=False),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def guardar_lote_eventos(eventos: List[dict], batch_size: int = 1000) -> int:
    """Inserta de manera masiva y eficiente una lista de eventos normalizados en SQLite."""
    conn = _conectar()
    cursor = conn.cursor()
    total = 0
    now = datetime.now(timezone.utc).isoformat()

    try:
        for i in range(0, len(eventos), batch_size):
            batch = eventos[i : i + batch_size]
            filas = [
                (
                    now,
                    ev.get("timestamp", ""),
                    ev.get("fuente", ""),
                    ev.get("host", ""),
                    ev.get("usuario", ""),
                    ev.get("ataque", ev.get("descripcion", "")[:80]),
                    ev.get("riesgo", "BAJO"),
                    ev.get("ip_origen", ""),
                    ev.get("ip_destino", ""),
                    ev.get("mitre", ""),
                    ev.get("detalles", ""),
                    "",
                    "INGESTA_BATCH",
                    "procesado",
                    json.dumps(ev, ensure_ascii=False),
                )
                for ev in batch
            ]
            cursor.executemany(
                """
                INSERT INTO eventos (fecha, timestamp_original, fuente, host, usuario, ataque, riesgo,
                                     ip_origen, ip_destino, mitre, detalles, respuesta_ia, modelo, estado, raw_evento)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                filas,
            )
            total += len(batch)
        conn.commit()
        return total
    finally:
        conn.close()


def guardar_incidente_correlacionado(incidente: dict, resumen_ia: str = "") -> int:
    """Guarda en SQLite el caso maestro de incidente con todas sus relaciones forenses."""
    conn = _conectar()
    inc_id = incidente.get("incidente_id", "INC-001")
    now = datetime.now(timezone.utc).isoformat()

    try:
        # Reemplazar si ya existe para re-análisis limpios
        conn.execute("DELETE FROM incidentes WHERE incidente_id = ?", (inc_id,))
        conn.execute("DELETE FROM linea_tiempo WHERE incidente_id = ?", (inc_id,))
        conn.execute("DELETE FROM iocs WHERE incidente_id = ?", (inc_id,))
        conn.execute("DELETE FROM falsos_positivos WHERE incidente_id = ?", (inc_id,))

        cursor = conn.execute(
            """
            INSERT INTO incidentes (
                incidente_id, titulo, empresa, fecha_incidente, score_riesgo,
                severidad_global, host_comprometido, ip_host, usuario_comprometido,
                departamento, vector_inicial, c2_servidor, volumen_exfiltrado_mb,
                archivos_comprometidos_total, resumen_ia, datos_json, creado_en
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inc_id,
                incidente.get("titulo", ""),
                incidente.get("empresa", ""),
                incidente.get("fecha_incidente", ""),
                incidente.get("score_riesgo", 90),
                incidente.get("severidad_global", "CRITICO"),
                incidente.get("host_comprometido", ""),
                incidente.get("ip_host", ""),
                incidente.get("usuario_comprometido", ""),
                incidente.get("departamento", ""),
                incidente.get("vector_inicial", ""),
                incidente.get("c2_servidor", ""),
                incidente.get("volumen_exfiltrado_mb", 0.0),
                incidente.get("archivos_comprometidos_total", 0),
                resumen_ia or incidente.get("resumen_ia", ""),
                json.dumps(incidente, ensure_ascii=False),
                now,
            ),
        )

        # Guardar Línea de Tiempo
        for item in incidente.get("linea_tiempo", []):
            conn.execute(
                """
                INSERT INTO linea_tiempo (incidente_id, timestamp, fase, fuente, host, usuario, evento, mitre)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inc_id,
                    item.get("timestamp", ""),
                    item.get("fase", ""),
                    item.get("fuente", ""),
                    item.get("host", ""),
                    item.get("usuario", ""),
                    item.get("evento", ""),
                    item.get("mitre", ""),
                ),
            )

        # Guardar IoCs
        for ioc in incidente.get("iocs", []):
            conn.execute(
                """
                INSERT INTO iocs (incidente_id, tipo, valor, descripcion, mitre)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    inc_id,
                    ioc.get("tipo", ""),
                    ioc.get("valor", ""),
                    ioc.get("descripcion", ""),
                    ioc.get("mitre", ""),
                ),
            )

        # Guardar Falsos Positivos Suprimidos
        for fp in incidente.get("falsos_positivos", []):
            conn.execute(
                """
                INSERT INTO falsos_positivos (incidente_id, distractor_id, categoria, host, justificacion)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    inc_id,
                    fp.get("distractor_id", ""),
                    fp.get("categoria", ""),
                    fp.get("host", ""),
                    fp.get("justificacion", ""),
                ),
            )

        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def obtener_ultimo_incidente() -> Optional[dict]:
    """Recupera el último incidente correlacionado registrado en la base de datos."""
    conn = _conectar()
    try:
        row = conn.execute("SELECT * FROM incidentes ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        res = dict(row)
        if res.get("datos_json"):
            try:
                res["datos"] = json.loads(res["datos_json"])
            except Exception:
                res["datos"] = {}
        return res
    finally:
        conn.close()


def obtener_estadisticas(horas: int = 24) -> dict:
    conn = _conectar()
    try:
        total = conn.execute("SELECT COUNT(*) FROM eventos").fetchone()[0]
        criticos = conn.execute("SELECT COUNT(*) FROM eventos WHERE riesgo = 'CRITICO'").fetchone()[0]
        altos = conn.execute("SELECT COUNT(*) FROM eventos WHERE riesgo = 'ALTO'").fetchone()[0]
        medios = conn.execute("SELECT COUNT(*) FROM eventos WHERE riesgo = 'MEDIO'").fetchone()[0]

        top_ips = conn.execute(
            """
            SELECT ip_origen, COUNT(*) as cnt
            FROM eventos
            WHERE ip_origen != ''
            GROUP BY ip_origen
            ORDER BY cnt DESC
            LIMIT 5
            """
        ).fetchall()

        top_ataques = conn.execute(
            """
            SELECT ataque, COUNT(*) as cnt
            FROM eventos
            WHERE ataque != ''
            GROUP BY ataque
            ORDER BY cnt DESC
            LIMIT 5
            """
        ).fetchall()

        return {
            "total": total,
            "criticos": criticos,
            "altos": altos,
            "medios": medios,
            "bajos": total - criticos - altos - medios,
            "top_ips": [(row["ip_origen"], row["cnt"]) for row in top_ips],
            "top_ataques": [(row["ataque"], row["cnt"]) for row in top_ataques],
            "modelos_usados": [],
        }
    finally:
        conn.close()


def obtener_todos_eventos(limite: int = 100) -> list:
    conn = _conectar()
    try:
        rows = conn.execute(
            "SELECT * FROM eventos ORDER BY id DESC LIMIT ?",
            (limite,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
