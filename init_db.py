# init_db.py
from app import app, db  # change `your_app_file` to your actual app file name (without .py)

with app.app_context():
    db.create_all()
    print("Database initialized.")
