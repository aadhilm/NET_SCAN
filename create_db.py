import sqlite3

# Connect to SQLite (creates 'users.db' if it doesn't exist)
conn = sqlite3.connect("users.db")

# Close the connection
conn.close()

