import os
import secrets
from werkzeug.security import generate_password_hash
from app import app
from extensions import db
from models import User

def create_admin_user():
    # Fetch admin credentials from environment variables (with defaults)
    username = os.getenv("ADMIN_USERNAME", "admin")
    email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    mobile = os.getenv("ADMIN_MOBILE", "9876543210")
    initial_password = os.getenv("ADMIN_PASSWORD")

    # Generate a random secure password if none provided
    if not initial_password:
        initial_password = secrets.token_urlsafe(16)
        print(f"[SECURITY NOTICE] Generated admin password: {initial_password}")

    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username=username).first()
        if admin:
            print(f"⚠️ Admin user '{username}' already exists.")
            return

        # Create admin user
        admin = User(
            username=username,
            email=email,
            mobile=mobile,
            gender='male',
            is_admin=True,
            role='superadmin'
        )

        # Set hashed password using model method
        admin.set_password(initial_password)

        # Add to DB
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin user '{username}' created successfully.")

# Run the function
if __name__ == "__main__":
    create_admin_user()
