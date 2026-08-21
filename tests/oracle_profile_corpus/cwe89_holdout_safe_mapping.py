def find_record(cursor, entity, name):
    tables = {"user": "users", "admin": "admins"}
    table = tables[entity]
    query = f"SELECT id FROM {table} WHERE name = ?"
    return cursor.execute(query, (name,))
