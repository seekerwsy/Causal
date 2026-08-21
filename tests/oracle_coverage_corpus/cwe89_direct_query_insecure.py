import sqlite3


def find_user(connection: sqlite3.Connection, user_name: str):
    cursor = connection.cursor()
    query = f"SELECT id, name FROM users WHERE name = '{user_name}'"
    return cursor.execute(query).fetchone()
