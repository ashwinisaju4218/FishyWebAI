import sqlite3

def create_database():

    conn = sqlite3.connect("fishywebai.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        url TEXT,

        result TEXT,

        confidence REAL,

        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

def save_scan(url, result, confidence):

    conn = sqlite3.connect("fishywebai.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans
        (url, result, confidence)
        VALUES (?, ?, ?)
        """,
        (url, result, confidence)
    )

    conn.commit()
    conn.close()

def get_scans():

    conn = sqlite3.connect("fishywebai.db")

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scans
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_scans():

    conn = sqlite3.connect("fishywebai.db")

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scans
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_dashboard_stats():

    conn = sqlite3.connect("fishywebai.db")

    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM scans
    WHERE result LIKE '%PHISHING%'
    """)
    phishing_count = cursor.fetchone()[0]

    safe_count = total_scans - phishing_count

    conn.close()

    return {
        "total": total_scans,
        "phishing": phishing_count,
        "safe": safe_count
    }