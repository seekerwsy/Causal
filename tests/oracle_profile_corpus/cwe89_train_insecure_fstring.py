def find_user(cursor, name):
    return cursor.execute(f"SELECT id FROM users WHERE name = '{name}'")
