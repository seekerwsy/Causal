def migrate(cursor, script):
    return cursor.executescript(script)
