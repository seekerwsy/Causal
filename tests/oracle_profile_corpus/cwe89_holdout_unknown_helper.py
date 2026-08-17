def build_query(name):
    return "SELECT id FROM users WHERE name = ?", (name,)


def find_user(cursor, name):
    query, parameters = build_query(name)
    return cursor.execute(query, parameters)
