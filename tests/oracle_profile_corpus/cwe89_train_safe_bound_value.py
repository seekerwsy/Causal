def find_user(cursor, name):
    return cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
