import sqlite3
import json
from datetime import datetime, timezone

from config import DB_PATH


def _conectar():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def inicializar_db():
    conn = _conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            fuente TEXT NOT NULL,
            ataque TEXT,
            riesgo TEXT,
            ip_origen TEXT,
            ip_destino TEXT,
            mitre TEXT,
            respuesta_ia TEXT,
            modelo TEXT,
            estado TEXT DEFAULT 'pendiente',
            raw_evento TEXT
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
            INSERT INTO eventos (fecha, fuente, ataque, riesgo, ip_origen, ip_destino,
                                 mitre, respuesta_ia, modelo, estado, raw_evento)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                evento_normalizado.get("fuente", ""),
                resultado_reglas.get("ataque", ""),
                resultado_reglas.get("riesgo", ""),
                evento_normalizado.get("ip_origen", evento_normalizado.get("raw_log", "")),
                evento_normalizado.get("ip_destino", ""),
                resultado_reglas.get("mitre", ""),
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


def obtener_estadisticas(horas: int = 24) -> dict:
    conn = _conectar()
    try:
        desde = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        total = conn.execute("SELECT COUNT(*) FROM eventos WHERE fecha >= ?", (desde,)).fetchone()[0]
        criticos = conn.execute(
            "SELECT COUNT(*) FROM eventos WHERE fecha >= ? AND riesgo = 'CRITICO'",
            (desde,),
        ).fetchone()[0]
        altos = conn.execute(
            "SELECT COUNT(*) FROM eventos WHERE fecha >= ? AND riesgo = 'ALTO'",
            (desde,),
        ).fetchone()[0]
        medios = conn.execute(
            "SELECT COUNT(*) FROM eventos WHERE fecha >= ? AND riesgo = 'MEDIO'",
            (desde,),
        ).fetchone()[0]

        top_ips = conn.execute(
            """
            SELECT ip_origen, COUNT(*) as cnt
            FROM eventos
            WHERE fecha >= ? AND ip_origen != ''
            GROUP BY ip_origen
            ORDER BY cnt DESC
            LIMIT 5
            """,
            (desde,),
        ).fetchall()

        top_ataques = conn.execute(
            """
            SELECT ataque, COUNT(*) as cnt
            FROM eventos
            WHERE fecha >= ?
            GROUP BY ataque
            ORDER BY cnt DESC
            LIMIT 5
            """,
            (desde,),
        ).fetchall()

        modelos_usados = conn.execute(
            """
            SELECT modelo, COUNT(*) as cnt
            FROM eventos
            WHERE fecha >= ? AND modelo != ''
            GROUP BY modelo
            ORDER BY cnt DESC
            """,
            (desde,),
        ).fetchall()

        return {
            "total": total,
            "criticos": criticos,
            "altos": altos,
            "medios": medios,
            "bajos": total - criticos - altos - medios,
            "top_ips": [(row["ip_origen"], row["cnt"]) for row in top_ips],
            "top_ataques": [(row["ataque"], row["cnt"]) for row in top_ataques],
            "modelos_usados": [(row["modelo"], row["cnt"]) for row in modelos_usados],
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