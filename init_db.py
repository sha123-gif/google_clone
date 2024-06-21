import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

# Create users table
c.execute('''CREATE TABLE IF NOT EXISTS users (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             email TEXT UNIQUE NOT NULL,
             password TEXT NOT NULL
             )''')

conn.commit()
conn.close()
