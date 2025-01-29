import sqlite3

# Connect to SQLite
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Insert a user
try:
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "password123"))
    conn.commit()
    print("User added successfully!")
except sqlite3.IntegrityError:
    print("Username already exists!")

# Close the connection
conn.close()
