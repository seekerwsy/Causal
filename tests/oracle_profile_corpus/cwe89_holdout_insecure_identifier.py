def find_record(cursor, table, name):
    query = f"SELECT id FROM {table} WHERE name = ?"
    return cursor.execute(query, (name,))
