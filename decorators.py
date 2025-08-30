# decorators.py (Corrected)

from functools import wraps
from flask import redirect, url_for, flash, abort
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first.", "danger")
            return redirect(url_for('auth.login'))

        # CORRECTED LOGIC: Check if the role is not 'user'.
        # This allows both 'admin' and 'superadmin' to pass.
        if current_user.role == 'user':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home'))

        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator