import sqlite3
from datetime import datetime
from pathlib import Path

from config import Config


def get_database_path():
    """
    Return the absolute path of the SQLite database.

    The database location comes from the application configuration.
    """

    database_path = Path(Config.DATABASE_PATH)

    if not database_path.is_absolute():
        database_path = Path.cwd() / database_path

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    return database_path


def get_connection():
    """
    Create and return a SQLite database connection.
    """

    connection = sqlite3.connect(
        get_database_path()
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create all required database tables.

    This function is safe to run every time the application starts
    because CREATE TABLE IF NOT EXISTS is used.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            prompt TEXT NOT NULL,

            rule_score REAL NOT NULL DEFAULT 0,

            llm_confidence REAL NOT NULL DEFAULT 0,

            threat_weight REAL NOT NULL DEFAULT 0,

            security_score REAL NOT NULL DEFAULT 0,

            risk_category TEXT NOT NULL,

            threat_type TEXT NOT NULL,

            rule_findings TEXT,

            llm_explanation TEXT,

            explanation TEXT,

            optimized_prompt TEXT,

            optimization_applied INTEGER NOT NULL DEFAULT 0,

            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            pattern TEXT NOT NULL UNIQUE,

            threat_type TEXT NOT NULL,

            severity REAL NOT NULL,

            description TEXT,

            enabled INTEGER NOT NULL DEFAULT 1,

            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            action TEXT NOT NULL,

            endpoint TEXT,

            ip_address TEXT,

            details TEXT,

            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()

    connection.close()


def save_scan(scan_data):
    """
    Save a completed security scan into the database.

    Returns the generated scan ID.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO scans (
            prompt,
            rule_score,
            llm_confidence,
            threat_weight,
            security_score,
            risk_category,
            threat_type,
            rule_findings,
            llm_explanation,
            explanation,
            optimized_prompt,
            optimization_applied,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_data.get("prompt", ""),
            scan_data.get("rule_score", 0),
            scan_data.get("llm_confidence", 0),
            scan_data.get("threat_weight", 0),
            scan_data.get("security_score", 0),
            scan_data.get("risk_category", "Safe"),
            scan_data.get("threat_type", "Benign"),
            scan_data.get("rule_findings", ""),
            scan_data.get("llm_explanation", ""),
            scan_data.get("explanation", ""),
            scan_data.get("optimized_prompt"),
            1 if scan_data.get("optimization_applied") else 0,
            datetime.utcnow().isoformat()
        )
    )

    scan_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return scan_id


def get_scan_history(limit=50):
    """
    Return the latest scan records.

    The default limit prevents the API from returning an
    unnecessarily large amount of data.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            prompt,
            rule_score,
            llm_confidence,
            threat_weight,
            security_score,
            risk_category,
            threat_type,
            explanation,
            optimized_prompt,
            optimization_applied,
            created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    """
    Return one scan by its database ID.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


def save_audit_log(
    action,
    endpoint=None,
    ip_address=None,
    details=None
):
    """
    Store a lightweight application audit event.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO audit_logs (
            action,
            endpoint,
            ip_address,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            action,
            endpoint,
            ip_address,
            details,
            datetime.utcnow().isoformat()
        )
    )

    connection.commit()

    connection.close()


def get_database_stats():
    """
    Return basic statistics used by the dashboard.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) AS total FROM scans"
    )

    total_scans = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE risk_category IN ('High Risk', 'Critical')
        """
    )

    high_risk_scans = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE risk_category = 'Safe'
        """
    )

    safe_scans = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT AVG(security_score) AS average_score
        FROM scans
        """
    )

    average_result = cursor.fetchone()["average_score"]

    connection.close()

    return {
        "total_scans": total_scans,
        "high_risk_scans": high_risk_scans,
        "safe_scans": safe_scans,
        "average_score": round(
            average_result or 0,
            2
        )
    }