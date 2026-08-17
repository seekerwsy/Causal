def find_record(cursor, table, name):
    if table not in {"users", "admins"}:
        raise ValueError("invalid table")
    query = f"SELECT id FROM {table} WHERE name = ?"
    return cursor.execute(query, (name,))
