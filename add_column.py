import sqlite3

# Connect to your database
conn = sqlite3.connect('products.db')  # Make sure this is your correct .db file

# Create a cursor
cursor = conn.cursor()

# Try to add the profile_pic column
try:
    cursor.execute("ALTER TABLE user ADD COLUMN profile_pic TEXT")
    print("✅ 'profile_pic' column added successfully.")
except sqlite3.OperationalError as e:
    print(f"⚠️ Error: {e}")

# Commit and close
conn.commit()
conn.close()
