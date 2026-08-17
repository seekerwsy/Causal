def find_user(cursor, name):
    query = "SELECT id FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)
