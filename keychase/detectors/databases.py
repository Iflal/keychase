"""Database connection string and credential detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── MongoDB ───────────────────────────────────────────────────
    Detector(
        id="mongodb-connection-string",
        name="MongoDB Connection String",
        pattern=_compile(r"mongodb(?:\+srv)?://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+"),
        severity=Severity.CRITICAL,
        description="MongoDB connection URI with embedded credentials.",
        keywords=("mongodb://", "mongodb+srv://"),
    ),

    # ── PostgreSQL ────────────────────────────────────────────────
    Detector(
        id="postgresql-connection-string",
        name="PostgreSQL Connection String",
        pattern=_compile(r"postgres(?:ql)?://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+"),
        severity=Severity.CRITICAL,
        description="PostgreSQL connection URI with embedded credentials.",
        keywords=("postgres://", "postgresql://"),
    ),

    # ── MySQL ─────────────────────────────────────────────────────
    Detector(
        id="mysql-connection-string",
        name="MySQL Connection String",
        pattern=_compile(r"mysql://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+"),
        severity=Severity.CRITICAL,
        description="MySQL connection URI with embedded credentials.",
        keywords=("mysql://",),
    ),

    # ── Redis ─────────────────────────────────────────────────────
    Detector(
        id="redis-connection-string",
        name="Redis Connection String",
        pattern=_compile(r"redis(?:s)?://[^\s'\"<>]*:[^\s'\"<>]+@[^\s'\"<>]+"),
        severity=Severity.HIGH,
        description="Redis connection URI with embedded password.",
        keywords=("redis://", "rediss://"),
    ),

    # ── JDBC ──────────────────────────────────────────────────────
    Detector(
        id="jdbc-connection-string",
        name="JDBC Connection String with Password",
        pattern=_compile(
            r"""(?i)jdbc:[a-z]+://[^\s'\"]+(?:password|pwd)\s*=\s*[^\s&;'\"]+"""
        ),
        severity=Severity.CRITICAL,
        description="JDBC database connection string with inline password.",
        keywords=("jdbc:",),
    ),

    # ── DSN-style password ────────────────────────────────────────
    Detector(
        id="database-password-assignment",
        name="Database Password Assignment",
        pattern=_compile(
            r"""(?i)(?:db|database|mysql|postgres|pg|mongo|redis)[_\-]?pass(?:word)?\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        severity=Severity.HIGH,
        description="Hardcoded database password in a configuration variable.",
        keywords=("db_pass", "database_pass", "db_password", "pg_pass", "mysql_pass", "mongo_pass"),
    ),
]
