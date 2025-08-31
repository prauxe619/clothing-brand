from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, abort, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, Product, ProductImage, Size, Color, Cart, CartItem, Wishlist, Order, OrderItem, Banner, Review, Address, ProductSize
import razorpay
import os
from dotenv import load_dotenv
import json
from datetime import datetime, timedelta, timezone
from flask_mail import Mail, Message
from forms import ProductForm, AddressForm, AddToCartForm
from models import db, Product, User, Order, OrderItem, Size, Cart, Wishlist, CartItem, Review, Address, ProductImage, WhatsAppCart, UserActivity, Banner, UserActivityLog, ActivityLog, SiteSettings, GPTUsage, NewsletterSubscriber
from flask_migrate import Migrate
from admin_routes import admin_bp
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf, ValidationError, CSRFError 
import io
from xhtml2pdf import pisa
from werkzeug.utils import secure_filename, safe_join
from werkzeug.security import generate_password_hash
import uuid
from admin_routes import admin_bp
import sys
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy.orm import joinedload 
import logging # Import logging
import requests
import smtplib
from email.mime.text import MIMEText
from flask_wtf.csrf import CSRFProtect
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import shutil
import tempfile
from extensions import db, cache
from openai import OpenAI
from flask_cors import CORS
import time
from utils.nlp_parser import parse_query
from sqlalchemy import or_, and_, func
import re
import secrets # For generating secure tokens/OTPs
from urllib.parse import urlparse, urljoin
import openai  # Ensure openai-python package is installed
from markupsafe import escape
from sqlalchemy.exc import SQLAlchemyError
import cloudinary
import cloudinary.uploader



load_dotenv()
client = OpenAI()

app = Flask(__name__)
CORS(app)

# --- 3. Configuration ---
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your_strong_fallback_secret_key_here") # Use a strong fallback for dev
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads' # Original upload folder for product images
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SESSION_COOKIE_SECURE'] = True   # Only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Not accessible via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Helps prevent CSRF

# Razorpay credentials
app.config['RAZORPAY_KEY_ID'] = os.environ.get("RAZORPAY_KEY_ID", "") # Use .get with default empty string
app.config['RAZORPAY_KEY_SECRET'] = os.environ.get("RAZORPAY_KEY_SECRET", "") # Use .get with default empty string
DELHIVERY_API_TOKEN = os.environ.get('DELHIVERY_API_TOKEN')
DELHIVERY_API_BASE_URL = "https://track.delhivery.com/c/api/pin-codes/json/"
ULTRAMSG_INSTANCE_ID = os.environ.get('ULTRAMSG_INSTANCE_ID')
ULTRAMSG_TOKEN = os.environ.get('ULTRAMSG_TOKEN')
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Mailtrap SMTP configuration
app.config['MAIL_SERVER'] = "email-smtp.ap-south-1.amazonaws.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'connect@prauxe.com'


db.init_app(app)
cache.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app) # Initialize CSRFProtect with app instance
mail = Mail(app)
cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache'})


print("✅ Using database:", app.config["SQLALCHEMY_DATABASE_URI"])
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)


CSP_POLICY = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "https://checkout.razorpay.com",
        "https://cdn.tailwindcss.com",
        "https://cdn.jsdelivr.net",         # For Swiper or JS libraries
        "https://www.googletagmanager.com", # Google Analytics
        "https://www.clarity.ms",           # Microsoft Clarity
        "https://scripts.clarity.ms",
        "'unsafe-inline'"
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com"
    ],
    'style-src-elem': [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com",
        "'unsafe-inline'"
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com",
        "data:"  # For data:application/font-woff fonts
    ],
    'img-src': [
        "'self'",
        "data:",
        "https://placehold.co",
        "https://cdn.razorpay.com",
        "https://res.cloudinary.com"  # <-- Added Cloudinary
    ],
    'connect-src': [
        "'self'",
        "https://api.razorpay.com",
        "https://api.razorpay.com/v1/checkout"
    ],
    'frame-src': [
        "'self'",
        "https://api.razorpay.com",
        "https://checkout.razorpay.com"
    ]
}


# Minimum password length
SECURITY_PASSWORD_LENGTH_MIN = 8

# Optional: require a mix of uppercase, lowercase, digits, and special chars
SECURITY_PASSWORD_COMPLEXITY_CHECKER = 'zxcvbn'  # optional
SECURITY_PASSWORD_COMPLEXITY = {
    'UPPERCASE': 1,   # at least 1 uppercase letter
    'LOWERCASE': 1,   # at least 1 lowercase letter
    'DIGITS': 1,      # at least 1 digit
    'SPECIAL': 1      # at least 1 special character
}

# Minimum password length
SECURITY_PASSWORD_LENGTH_MIN = 8

# Optional: require a mix of uppercase, lowercase, digits, and special chars
SECURITY_PASSWORD_COMPLEXITY_CHECKER = 'zxcvbn'  # optional
SECURITY_PASSWORD_COMPLEXITY = {
    'UPPERCASE': 1,   # at least 1 uppercase letter
    'LOWERCASE': 1,   # at least 1 lowercase letter
    'DIGITS': 1,      # at least 1 digit
    'SPECIAL': 1      # at least 1 special character
}

Talisman(app, content_security_policy=CSP_POLICY)

# Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    app=app # Pass the app instance here
)

# --- 5. Logging Setup ---
app.logger.setLevel(logging.DEBUG)
# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- 7. Razorpay Client Initialization (using app.config) ---
try:
    if not app.config['RAZORPAY_KEY_ID'] or not app.config['RAZORPAY_KEY_SECRET']:
        print("WARNING: Razorpay keys are missing or empty in app.config. Razorpay client will not be initialized.")
        client = None
    else:
        client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))
        # Removed set_app_details to avoid potential argument mismatch error
        # client.set_app_details("PRAUXE_Store", "1.0") 
        print("DEBUG: Razorpay client initialized successfully.")
except Exception as e:
    print(f"ERROR: An unexpected error occurred during Razorpay client initialization: {e}")
    client = None

# --- 8. Global Constants ---
MAX_RECENTLY_VIEWED = 8
ALL_POSSIBLE_SIZES = ['XS', 'S', 'M', 'L', 'XL', 'XXL']
ALL_SIZES = [
    {'name': 'XS'},
    {'name': 'S'},
    {'name': 'M'},
    {'name': 'L'},
    {'name': 'XL'},
    {'name': 'XXL'},
]
ALL_COLORS = [
    {'name': 'Black', 'hex_code': '#000000'},
    {'name': 'White', 'hex_code': '#FFFFFF'},
    {'name': 'Red', 'hex_code': '#FF0000'},
    {'name': 'Blue', 'hex_code': '#0000FF'},
    {'name': 'Green', 'hex_code': '#008000'},
    {'name': 'Yellow', 'hex_code': '#FFFF00'},
    {'name': 'Pink', 'hex_code': '#FFC0CB'},
    {'name': 'Grey', 'hex_code': '#808080'},
    {'name': 'Navy', 'hex_code': '#000080'},
    {'name': 'Rose Gold', 'hex_code': '#B76E79'},
    {'name': 'Space Gray', 'hex_code': '#717378'},
    {'name': 'Silver', 'hex_code': '#C0C0C0'},
    {'name': 'Midnight Blue', 'hex_code': '#191970'},
    {'name': 'Graphite', 'hex_code': '#383838'},
    {'name': 'Pearl White', 'hex_code': '#F8F8F8'},
]
# Example in-memory data structure, replace with DB model
user_addresses = {
    # user_id: [list_of_addresses]
}

app.register_blueprint(admin_bp)

# --- 10. Flask-Login Setup (user_loader) ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- 11. Context Processors ---

@app.context_processor
def inject_theme():
    from extensions import cache
    theme = cache.get('theme_settings')

    if not theme:
        settings = SiteSettings.get()
        theme = {
            'primary_color': settings.primary_color or '#e91e63',
            'background_color': settings.background_color or '#ffffff',
            'font_family': settings.font_family or "'Inter', sans-serif"
        }
        cache.set('theme_settings', theme, timeout=3600)

    return theme


@app.context_processor
def inject_currency_utils():
    def format_price(inr_price):
        currency = session.get('currency', 'INR')
        if currency == 'USD':
            usd_rate = 86  # Ideally fetched from API or config
            return f"${inr_price / usd_rate:.2f}"
        return f"₹{inr_price:.2f}"
    return dict(format_price=format_price)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_user_data():
    """
    Provide user-related data to templates:
      - user (current_user if authenticated)
      - user_wishlist_ids (set of product ids either from DB or normalized session)
    Make this tolerant of different guest_wishlist storage shapes.
    """
    user = current_user if current_user.is_authenticated else None

    # Wishlist IDs (as a set of ints) ------------------------------------------------
    if user:
        # logged-in user's wishlist from DB
        try:
            wishlist_items = Wishlist.query.filter_by(user_id=user.id).all()
            user_wishlist_ids = {int(w.product_id) for w in wishlist_items}
        except Exception:
            # fallback safe default
            user_wishlist_ids = set()
    else:
        # guest user — normalize session data to a list of ints
        try:
            guest_ids = normalize_guest_wishlist()  # returns list of ints and writes back to session
            user_wishlist_ids = set(guest_ids)
        except Exception:
            user_wishlist_ids = set()
    context = {
        'current_user': current_user,
        'user_wishlist_ids': user_wishlist_ids,
        # keep any existing keys you were injecting:
        # 'symbol': app.config.get('CURRENCY_SYMBOL'),
        # 'rate': some_rate,
        # 'bag_item_count': calc_count...
    }

    # If you had more keys currently being returned, extend 'context' with them.
    return context

@app.context_processor
def utility_processor():
    
    return dict(convert_price=convert_price)

@app.context_processor
def inject_global_settings():
    settings = SiteSettings.query.first()
    return dict(settings=settings)


# --- 12. BEFORE REQUEST HOOKS ---
@app.before_request
def track_recently_viewed():
    if request.endpoint == 'product_detail' and request.method == 'GET':
        product_id = request.view_args.get('product_id')
        if product_id:
            recently_viewed_products = session.get('recently_viewed', [])
            recently_viewed_products = [int(p) for p in recently_viewed_products if isinstance(p, (int, str)) and str(p).isdigit()]
            if product_id in recently_viewed_products:
                recently_viewed_products.remove(product_id)
            recently_viewed_products.insert(0, product_id)
            session['recently_viewed'] = recently_viewed_products[:MAX_RECENTLY_VIEWED]

# --- 13. Database Initialization and Seeding (within app context) ---
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = (
        "script-src 'self' https://checkout.razorpay.com https://cdn.tailwindcss.com 'unsafe-inline';"
    )
    return response



# --- 14. HELPER FUNCTIONS (Non-route specific) ---

def generate_order_number():
    # PRX-YYMMDD-XXXX (daily sequence 0001, 0002, ...)
    today_str = datetime.utcnow().strftime("%y%m%d")
    prefix = f"PRX-{today_str}-"

    start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)

    # Count today's existing orders that already have today's prefix
    count_today = db.session.query(func.count(Order.id))\
        .filter(Order.created_at >= start, Order.created_at < end)\
        .scalar() or 0

    # Try a few candidates to avoid race
    for i in range(1, 6):
        candidate = f"{prefix}{str(count_today + i).zfill(4)}"
        exists = db.session.query(Order.id).filter_by(order_number=candidate).first()
        if not exists:
            return candidate

    # Fallback random suffix
    from random import randint
    return f"{prefix}{randint(1000, 9999)}"


def migrate_main_images_to_cloudinary():
    products = Product.query.all()
    for product in products:
        main_img = next((img for img in product.images if img.is_main), None)
        if not main_img:
            print(f"No main image for product {product.id} ({product.name})")
            continue

        # Skip if already a Cloudinary URL
        if main_img.image_url.startswith("http://") or main_img.image_url.startswith("https://"):
            print(f"Skipping already uploaded main image: {main_img.image_url}")
            continue

        local_path = os.path.join("static", "uploads", main_img.image_url)
        if not os.path.exists(local_path):
            print(f"Local file not found: {local_path}")
            continue

        try:
            upload_result = cloudinary.uploader.upload(local_path)
            main_img.image_url = upload_result['secure_url']  # update DB
            db.session.commit()
            print(f"Uploaded main image for product {product.id}: {main_img.image_url}")
        except Exception as e:
            print(f"Error uploading {local_path}: {e}")



def normalize_guest_wishlist():
    """
    Normalize session['guest_wishlist'] into a list of integers (product IDs).
    Accepts many historical shapes:
      - list of ints: [1, 2, 3]
      - list of strings: ['1','2']
      - list of dicts: [{'product_id': 1}, {'id': 2}, {'product': {'id': 3}}]
      - dict mapping ids -> truthy : { "1": True, "2": True }
      - single int or single string
    Stores normalized list back to session['guest_wishlist'] (as ints).
    Returns normalized list.
    """
    raw = session.get('guest_wishlist', [])
    normalized = []

    # If it's a dict mapping ids -> something, use keys
    if isinstance(raw, dict):
        for k in raw.keys():
            try:
                normalized.append(int(k))
            except (ValueError, TypeError):
                continue

    # If it's a list, inspect each element
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, int):
                normalized.append(entry)
                continue
            if isinstance(entry, str):
                # numeric string?
                try:
                    normalized.append(int(entry))
                    continue
                except ValueError:
                    # maybe it's JSON-like; skip
                    continue
            if isinstance(entry, dict):
                # try common shapes
                pid = None
                if 'product_id' in entry:
                    pid = entry.get('product_id')
                elif 'id' in entry:
                    pid = entry.get('id')
                elif 'product' in entry and isinstance(entry.get('product'), dict):
                    pid = entry['product'].get('id')
                # try converting
                try:
                    if pid is not None:
                        normalized.append(int(pid))
                except (ValueError, TypeError):
                    continue
            # else ignore unknown types

    else:
        # single value (int or numeric string)
        try:
            normalized.append(int(raw))
        except (ValueError, TypeError):
            normalized = []

    # Deduplicate and keep order (optional)
    seen = set()
    result = []
    for x in normalized:
        if x not in seen:
            seen.add(x)
            result.append(x)

    # Save cleaned version back to session as list of ints
    session['guest_wishlist'] = result
    session.modified = True
    return result

def is_safe_url(target):
    """
    Ensures the target is a safe local URL (same host).
    """
    host_url = request.host_url
    test_url = urljoin(host_url, target or '')  # normalize relative/absolute
    ref_url = urlparse(host_url)
    parsed = urlparse(test_url)

    return (
        parsed.scheme in ('http', 'https') and
        ref_url.netloc == parsed.netloc
    )


# Allowed internal redirect paths
ALLOWED_PATHS = {
    "/": "home",
    "/dashboard": "dashboard",
    "/profile": "profile",
}

def safe_redirect(target, fallback="home"):
    """
    Redirect only to whitelisted internal routes.
    """
    if target in ALLOWED_PATHS:
        return redirect(url_for(ALLOWED_PATHS[target]))
    return redirect(url_for(fallback))



def is_suspicious_payment(payment_data):
    try:
        amount = int(payment_data.get('amount', 0)) / 100
        email = payment_data.get('email', '')
        method = payment_data.get('method', '')
        currency = payment_data.get('currency', '')

        if amount > 50000:
            return True
        if currency != "INR":
            return True
        if "test" in email:
            return True
        if method not in ['card', 'upi', 'netbanking']:
            return True
        return False
    except Exception as e:
        print("Fraud detection error:", e)
        return False

def notify_admin(message):
    print("[ADMIN ALERT]", message)
    # Later: send email, Slack, Telegram etc.



def get_dynamic_price(product, user=None):
    price = product.price
    now = datetime.now()

    for rule in product.price_rules:
        if not rule.active:
            continue

        try:
            # We no longer use eval() here.
            # Instead, we will parse the condition based on the rule type.
            condition_data = json.loads(rule.condition)
        except json.JSONDecodeError:
            # Skip any rule with invalid JSON data
            continue

        if rule.rule_type == 'time':
            # Safely get the time range from the parsed JSON data
            time_range = condition_data.get('time_range')
            if time_range and time_range[0] <= now.strftime('%H:%M') <= time_range[1]:
                price *= (1 - rule.discount_percent / 100)

        elif rule.rule_type == 'inventory':
            # Safely get the threshold from the parsed JSON data
            threshold = condition_data.get('stock_below', 0)
            if product.stock <= threshold:
                price *= (1 - rule.discount_percent / 100)

        elif rule.rule_type == 'user_behavior' and user:
            # Safely get the minimum views from the parsed JSON data
            min_views = condition_data.get('min_views', 0)
            
            recent_views = UserActivity.query.filter_by(
                user_id=user.id, product_id=product.id, activity_type='view'
            ).filter(UserActivity.timestamp > datetime.utcnow() - timedelta(days=7)).count()

            if recent_views >= min_views:
                price *= (1 - rule.discount_percent / 100)

    return round(price, 2)



def get_cached_theme_settings():
    settings = cache.get('theme_settings')
    if settings is None:
        settings = SiteSettings.get()
        cache.set('theme_settings', settings, timeout=60 * 60)  # cache for 1 hour
    return settings


def load_theme_from_name(name):
    themes = {
        'default': {
            'primary_color': '#e91e63',
            'background_color': '#ffffff',
            'font_family': "'Inter', sans-serif"
        },
        'dark': {
            'primary_color': '#f59e0b',
            'background_color': '#1a1a1a',
            'font_family': "'Playfair Display', serif"
        }
    }
    return themes.get(name, themes['default'])

def log_activity(admin_id, action):
    log = ActivityLog(admin_id=admin_id, action=action)
    db.session.add(log)
    db.session.commit()


def log_user_activity(user_id, action):
    log = UserActivityLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

@app.before_request
def detect_country():
    if 'currency' not in session:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        country = get_user_country(ip)

        # Set currency based on country
        if country == 'India':
            session['currency'] = 'INR'
        elif country == 'United States':
            session['currency'] = 'USD'
        elif country == 'United Kingdom':
            session['currency'] = 'GBP'
        elif country == 'Germany':
            session['currency'] = 'EUR'
        else:
            session['currency'] = 'USD'  # default fallback

        session['region_set'] = False  # show region popup later


# ... your imports and app setup ...

def send_otp_via_authkey(mobile_number, otp_code):
    """
    Sends an OTP to a mobile number using the AuthKey API.
    
    Returns True on success, False on failure.
    """
    # Replace these with your actual AuthKey credentials
    # It's best practice to store sensitive keys in environment variables
    api_key = os.environ.get("AUTHKEY_API_KEY") 
    sender_id = os.environ.get("AUTHKEY_SENDER_ID") 

    url = "https://control.authkey.io/api/verify_sender_id_and_api_key.php"
    
    payload = {
        'mobile': mobile_number,
        'otp': otp_code,
        'sender_id': sender_id,
        'api_key': api_key,
    }

    try:
        response = requests.post(url, data=payload)
        response_data = response.json()
        
        # Check for success status from the API response
        if response.status_code == 200 and response_data.get('status') == 'success':
            return True
        else:
            # Log the API error response for debugging
            print(f"AuthKey API Error: {response_data.get('message', 'Unknown Error')}")
            return False
            
    except requests.exceptions.RequestException as e:
        # Log network or connection errors
        print(f"Network error while calling AuthKey API: {e}")
        return False

def is_spam_message(text):
    try:
        response = openai.Moderation.create(input=text)
        flagged = response['results'][0]['flagged']
        return flagged
    except Exception as e:
        print(f"Spam detection failed: {e}")
        return False


def seed_initial_data():
    """
    Seeds initial data for the application, including sizes, colors,
    an admin user, and sample products with images.
    """
    db.create_all()
    
    # ... (Your existing seeding logic for Sizes, Colors, and Admin User goes here)
    # ... I've omitted it for brevity, but keep your original code.
    
    # Seed sample products if the table is empty
    if Product.query.count() == 0:
        print("Seeding sample products with images...")
        
        # Create product instances without an image argument
        product1 = Product(name='Black T-Shirt', price=499, category='men')
        product2 = Product(name='Blue Jeans', price=799, category='men')
        product3 = Product(name='White Hoodie', price=899, category='women')
        product4 = Product(name='Red Dress', price=1199, category='women')
        
        db.session.add_all([product1, product2, product3, product4])
        
        # Create a main image for each product and link it
        image1 = ProductImage(image_url='https://via.placeholder.com/150/000000/FFFFFF?text=Black+T-Shirt', product=product1, is_main=True)
        image2 = ProductImage(image_url='https://via.placeholder.com/150/0000FF/FFFFFF?text=Blue+Jeans', product=product2, is_main=True)
        image3 = ProductImage(image_url='https://via.placeholder.com/150/FFFFFF/000000?text=White+Hoodie', product=product3, is_main=True)
        image4 = ProductImage(image_url='https://via.placeholder.com/150/FF0000/FFFFFF?text=Red+Dress', product=product4, is_main=True)
        
        db.session.add_all([image1, image2, image3, image4])
        
        # Finally, commit everything to the database
        db.session.commit()
        print("Sample products and their images seeded.")


def get_user_country(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        return response.get("country_name", "India")
    except:
        return "India"

# utils.py
def convert_price(amount_in_inr, currency):
    # You can later replace this with a live API
    rates = {
        'INR': 1,
        'USD': 0.012,
        'EUR': 0.011,
        'GBP': 0.0105
    }
    rate = rates.get(currency, 1)
    return round(amount_in_inr * rate, 2)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message("Password Reset Request",
                  sender="noreply@yourdomain.com",
                  recipients=[user.email])
    msg.body = f"""To reset your password, click the link below:
{url_for('reset_password', token=token, _external=True)}

If you didn’t request this, ignore this email.
"""
    mail.send(msg)




def send_email_notification(order, user):
    if not order.email:
        current_app.logger.error("send_email_notification: No recipient email on order.")
        return

    try:
        msg = Message(
            subject=f"Order Confirmation – {order.order_id}",   # shows your friendly id if you mirror it
            recipients=[order.email],
            sender=current_app.config.get("MAIL_DEFAULT_SENDER", "connect@prauxe.com"),
            reply_to=current_app.config.get("MAIL_DEFAULT_SENDER", "connect@prauxe.com"),
        )

        # Plain-text fallback
        text_lines = [
            f"Hi {order.order_name or 'there'},",
            "",
            f"Thanks for your order with Prauxe!",
            f"Order ID: {order.order_id}",
            f"Amount: ₹{order.amount:.2f}",
            f"Payment Method: {order.payment_method or 'ONLINE'}",
            f"Ship To: {order.delivery_address}",
            "",
            "We’ll notify you when it ships.",
            "— Team Prauxe"
        ]
        msg.body = "\n".join(text_lines)

        # HTML body (make sure the template exists)
        msg.html = render_template(
            "email/order_confirmation.html",
            order=order,
            current_year=datetime.utcnow().year
        )

        mail.send(msg)
        current_app.logger.info(f"✅ Order email sent to {order.email} for {order.order_id}")
    except Exception as e:
        current_app.logger.exception(f"❌ Failed to send order email for {order.order_id}: {e}")

    
def send_whatsapp_message(to, message):
    instance_id = os.getenv("ULTRAMSG_INSTANCE_ID")
    token = os.getenv("ULTRAMSG_TOKEN")

    to = to.lstrip("+")  # remove plus if present
    print(f"Sending WhatsApp message to: {to}")
    print(f"Message: {message}")

    url = f"https://api.ultramsg.com/{instance_id}/messages/chat"
    payload = {
        "token": token,
        "to": to,
        "body": message
    }
    try:
        response = requests.post(url, data=payload)
        print("✅ WhatsApp reply sent:", response.json())
    except Exception as e:
        print(f"❌ Error sending WhatsApp message: {e}") 

def send_whatsapp_notification(order, user):
   
    instance_id = os.getenv("ULTRAMSG_INSTANCE_ID")  # Store in .env
    token = os.getenv("ULTRAMSG_TOKEN")              # Store in .env

    url = f"https://api.ultramsg.com/{instance_id}/messages/chat"

    order_summary = ""
    for item in order.items:
      order_summary += f"• {item.name} | Size: {item.size_name or '-'}, Color: {item.color_name or '-'}, Qty: {item.quantity}, ₹{item.price_at_purchase}\n"


    message = f"""
✅ Order Confirmed!

Hi {order.order_name}, thank you for shopping with *Prauxe*!

🧾 Order ID: {order.order_id}
🚚 Shipping: {order.shipping_method}
📦 Items:
{order_summary}
🏠 To: {order.delivery_address}

You'll be notified when it's shipped.
"""

    payload = {
        "token": token,
        "to": f"+91{order.order_mobile}",
        "body": message
    }

    try:
        response = requests.post(url, data=payload)
        print("DEBUG: WhatsApp sent:", response.json())
    except Exception as e:
        print(f"ERROR sending WhatsApp: {e}")

def send_whatsapp_image(to, image_url, caption=""):
    instance_id = os.getenv("ULTRAMSG_INSTANCE_ID")
    token = os.getenv("ULTRAMSG_TOKEN")

    url = f"https://api.ultramsg.com/{instance_id}/messages/image"
    payload = {
        "token": token,
        "to": to,
        "image": image_url,
        "caption": caption
    }

    try:
        response = requests.post(url, data=payload)
        print("📸 Image sent:", response.json())
    except Exception as e:
        print(f"❌ Error sending image: {e}")


def send_product_catalog(to, products):
    instance_id = os.getenv("ULTRAMSG_INSTANCE_ID")
    token = os.getenv("ULTRAMSG_TOKEN")
    url = f"https://api.ultramsg.com/{instance_id}/messages/template"

    for product_dict in products: # Renamed 'product' to 'product_dict' for clarity
        # The image_url is already available in the product_dict
        image_url = product_dict['image_url']

        payload = {
            "token": token,
            "to": to,
            "template": {
                "name": "product_catalog_template",
                "language": {"policy": "deterministic", "code": "en"},
                "components": [
                    {
                        "type": "header",
                        "parameters": [
                            {"type": "image", "image": {"link": image_url}} # Use image_url from dict
                        ]
                    },
                    {
                        "type": "body",
                        "parameters": [
                            {"type": "text", "text": product_dict['name']},
                            {"type": "text", "text": f"₹{product_dict['price']}"}
                        ]
                    },
                    {
                        "type": "button",
                        "sub_type": "url",
                        "index": "0",
                        "parameters": [
                            {"type": "text", "text": product_dict['url']}
                        ]
                    }
                ]
            }
        }
        response = requests.post(url, json=payload)
        print("Send product response:", response.json())


def generate_invoice_pdf(order):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Prauxe - Order Invoice")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Order ID: {order.order_id}")
    c.drawString(50, height - 100, f"Customer Name: {order.order_name or 'N/A'}")
    c.drawString(50, height - 120, f"Mobile: {order.order_mobile or 'N/A'}")
    c.drawString(50, height - 140, f"Date: {order.created_at.strftime('%Y-%m-%d %H:%M:%S')}")

    c.drawString(50, height - 170, "Items:")

    y = height - 190
    for item in order.items:
        line = f"{item.name} x {item.quantity} @ ₹{item.price_at_purchase} = ₹{item.price_at_purchase * item.quantity}"
        c.drawString(60, y, line)
        y -= 20

    c.drawString(50, y - 10, f"Total Amount: ₹{order.amount}")

    c.showPage()
    c.save()
    buffer.seek(0)

    return buffer


def save_pdf_to_static(buffer, filename):
    sanitized_filename = secure_filename(filename)
    static_dir = os.path.join(os.getcwd(), "static", "invoices")
    os.makedirs(static_dir, exist_ok=True)
    file_path = os.path.join(static_dir, sanitized_filename)
    with open(file_path, "wb") as f:
        f.write(buffer.read())
    public_url = f"https://yourdomain.com/static/invoices/{sanitized_filename}"
    
    return public_url

def send_whatsapp_invoice(order):
    pdf_buffer = generate_invoice_pdf(order)
    filename = f"invoice_{order.order_id}.pdf"
    pdf_url = save_pdf_to_static(pdf_buffer, filename)

    url = f"https://api.ultramsg.com/{ULTRAMSG_INSTANCE_ID}/messages/document"
    payload = {
        "token": ULTRAMSG_TOKEN,
        "to": f"+91{order.order_mobile}",
        "body": pdf_url,
        "filename": filename,
        "caption": f"Invoice for your order {order.order_id}"
    }
    response = requests.post(url, data=payload)
    print("DEBUG: Invoice sent:", response.json())


def send_whatsapp_invoice(order):
    pdf_buffer = generate_invoice_pdf(order)
    filename = f"invoice_{order.order_id}.pdf"

    # Save temp locally
    filepath = f"/tmp/{filename}"
    with open(filepath, "wb") as f:
        f.write(pdf_buffer.read())

    # Upload PDF somewhere accessible publicly and get the URL (implement upload logic)
    pdf_url = upload_pdf_and_get_url(filepath)

    if pdf_url:
        # Send WhatsApp message with document type
        url = f"https://api.ultramsg.com/{ULTRAMSG_INSTANCE_ID}/messages/document"
        payload = {
            "token": ULTRAMSG_TOKEN,
            "to": f"+91{order.order_mobile}",
            "body": pdf_url,
            "filename": filename,
            "caption": f"Invoice for your order {order.order_id}"
        }
        response = requests.post(url, data=payload)
        print("DEBUG: Invoice sent:", response.json())
    else:
        print("ERROR: Could not upload PDF invoice")

# Modify your order confirmation flow to call this function after placing order:
# send_whatsapp_invoice(order)

def upload_pdf_and_get_url(filepath):
    filename = os.path.basename(filepath)
    dest_path = os.path.join("static", "invoices", filename)
    shutil.copy(filepath, dest_path)
    # Assuming your domain is https://yourdomain.com
    public_url = f"https://yourdomain.com/{dest_path}"
    return public_url


def get_user_wishlist(user_id):
    # This function is a placeholder, ensure it queries your actual Wishlist model
    # For now, returning an empty list to prevent errors.
    # You already have inject_user_data context processor, so this might not be needed.
    return [] 

def admin_required(func):
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__ # Preserve original function name for Flask
    return wrapper

# --- 15. JINJA2 FILTERS ---
@app.template_filter('fromjson')
def fromjson_filter(s):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {} # Return empty dict on decode error for robustness


# ---------------- ROUTES ----------------

from flask import send_from_directory

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.png', mimetype='image/png')


@app.route("/")
@app.route("/home")
def home():
        conversion_rates = {
        'INR': 1,
        'USD': 0.013,  # example rate, adjust as per actual
        'EUR': 0.012,
        'GBP': 0.011,
    }
        banners = Banner.query.filter_by(is_active=True).order_by(Banner.created_at.asc()).all()

        # Function to get products with average rating
        def get_products_with_ratings(query_obj, limit=None, specific_ids=None):
            base_query = db.session.query(
                Product,
                db.func.avg(Review.rating).label('average_rating'),
                db.func.count(Review.id).label('review_count')
            ).outerjoin(Review)
            
            if specific_ids:
                base_query = base_query.filter(Product.id.in_(specific_ids))

            products_with_ratings_query = base_query.group_by(Product.id).order_by(query_obj)
            
            if limit and not specific_ids:
                products_with_ratings_query = products_with_ratings_query.limit(limit)
            
            results = []
            for product_obj, avg_rating, review_count in products_with_ratings_query.all():
                results.append({
                    'id': product_obj.id,
                    'name': product_obj.name,
                    'price': product_obj.price,
                    'image': product_obj.main_image_url,
                    'category': product_obj.category,
                    'average_rating': round(avg_rating, 1) if avg_rating is not None else 0,
                    'review_count': review_count if review_count is not None else 0
                })
                
            return results

        # Fetch recently viewed product IDs from session
        recently_viewed_ids = session.get('recently_viewed', [])
        recently_viewed_products_unordered = get_products_with_ratings(Product.id.desc(), specific_ids=recently_viewed_ids)
        
        recently_viewed_map = {p['id']: p for p in recently_viewed_products_unordered}
        ordered_recently_viewed_products = [
            recently_viewed_map[p_id] for p_id in recently_viewed_ids if p_id in recently_viewed_map
        ]

        # Fetch suggested products (e.g., top 5 popular products)
        suggested_products = get_products_with_ratings(Product.popularity.desc(), limit=5)

        products = get_products_with_ratings(Product.id.desc(), limit=12)
        
        user_wishlist_ids = []
        if current_user.is_authenticated:
            user_wishlist_ids = [item.product_id for item in current_user.wishlist_items]

        categories = [
            {"name": "Men", "url": url_for('men_collection'), "image": "images/cat-men.jpg"},
            {"name": "Women", "url": url_for('women_collection'), "image": "images/cat-women.jpg"},
            {"name": "Kids", "url": url_for('category', category_name='kids'), "image": "images/cat-kids.jpg"},
            {"name": "Ethnic", "url": url_for('category', category_name='ethnic'), "image": "images/cat-ethnic.jpg"},
            {"name": "Western", "url": url_for('category', category_name='western'), "image": "images/cat-western.jpg"},
            {"name": "Accessories", "url": url_for('category', category_name='accessories'), "image": "images/cat-accessories.jpg"}
        ]
        
        best_sellers = get_products_with_ratings(Product.popularity.desc(), limit=4)
        new_arrivals = get_products_with_ratings(Product.created_at.desc(), limit=4)
        bestsellers = get_products_with_ratings(
         func.coalesce(func.avg(Review.rating), 0).desc(),  # pass as first argument
          limit=4
         )


        return render_template('home.html',     
                               products=products, 
                               user_wishlist_ids=user_wishlist_ids,
                               categories=categories,
                               best_sellers=best_sellers,
                               new_arrivals=new_arrivals,
                               bestsellers=bestsellers,
                               recently_viewed_products=ordered_recently_viewed_products,
                               suggested_products=suggested_products, conversion_rates=conversion_rates, banners=banners)



@app.route("/new-arrivals")
def new_arrivals_page():
    """
    Displays a page with the latest products (new arrivals), with optional sorting.
    """
    sort = request.args.get('sort', 'default')

    # Base query
    query = Product.query

    # Apply sorting
    if sort == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        query = query.order_by(Product.price.desc())
    elif sort == 'newest':
        query = query.order_by(Product.created_at.desc())
    elif sort == 'popularity':
        # Assuming a popularity field exists. You can define your logic here
        query = query.order_by(Product.popularity.desc())
    else:
        query = query.order_by(Product.created_at.desc())  # Default

    latest_products = query.limit(20).all()

    # Prepare product data
    products_data = []
    for product in latest_products:
        review_count = len(product.reviews) if hasattr(product, 'reviews') and product.reviews else 0
        avg_rating = getattr(product, 'average_rating', 0)

        products_data.append({
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'image': product.main_image_url,
            'average_rating': avg_rating,
            'review_count': review_count
        })

    # Get user's wishlist
    user_wishlist_ids = []
    if current_user.is_authenticated:
        user_wishlist_ids = [item.product_id for item in current_user.wishlist_items]

    return render_template(
        'new_arrivals.html',
        new_arrivals=products_data,
        user_wishlist_ids=user_wishlist_ids,
        page_title="New Arrivals",
        sort=sort  # Pass current sort to template
    )



@app.route('/men')
def men_collection():
    sort = request.args.get('sort', 'default')

    products_query = db.session.query(
        Product,
        db.func.avg(Review.rating).label('average_rating'),
        db.func.count(Review.id).label('review_count')
    ).outerjoin(Review).filter(Product.category=='men').group_by(Product.id)

    if sort == 'price_asc':
        products_query = products_query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        products_query = products_query.order_by(Product.price.desc())
    elif sort == 'newest':
        products_query = products_query.order_by(Product.created_at.desc()) 
    elif sort == 'popularity':
        products_query = products_query.order_by(Product.popularity.desc())
    else:
        products_query = products_query.order_by(
        func.coalesce(func.avg(Review.rating), 0).desc(),
         Product.popularity.desc()
          )

    men_products_with_ratings = products_query.all()

    product_ids_in_wishlist = set() 
    cart_quantities = {}

    if current_user.is_authenticated:
        wishlist_entries = Wishlist.query.filter_by(user_id=current_user.id).all()
        for item in wishlist_entries:
            product_ids_in_wishlist.add(item.product_id)

        user_cart = Cart.query.filter_by(user_id=current_user.id).first()
        if user_cart:
            for cart_item in user_cart.items.all():
                cart_quantities[cart_item.product_id] = cart_item.quantity
    else:
        guest_wishlist_data = session.get('guest_wishlist', [])
        for item in guest_wishlist_data:
            if isinstance(item, dict) and 'product_id' in item:
                try:
                    product_ids_in_wishlist.add(int(item['product_id']))
                except (ValueError, TypeError):
                    pass

        # ✅ Define cart_session_data only in else block
        cart_session_data = session.get('cart', {})
        for pid_str, qty in cart_session_data.items():
            try:
                cart_quantities[int(pid_str)] = qty
            except ValueError:
                pass

    products_for_template = []
    for product_obj, avg_rating, review_count in men_products_with_ratings:
        product_data = {
            'id': product_obj.id,
            'name': product_obj.name,
            'price': product_obj.price,
            'image': product_obj.main_image_url,
            'category': product_obj.category,
            'in_wishlist': product_obj.id in product_ids_in_wishlist,
            'quantity_in_cart': cart_quantities.get(product_obj.id, 0),
            'average_rating': round(avg_rating, 1) if avg_rating is not None else 0,
            'review_count': review_count if review_count is not None else 0
        }
        products_for_template.append(product_data)

    return render_template('men.html', products=products_for_template, sort=sort)


@app.route('/women')
def women_collection():
        sort = request.args.get('sort', 'default')
        
        products_query = db.session.query(
            Product,
            db.func.avg(Review.rating).label('average_rating'),
            db.func.count(Review.id).label('review_count')
        ).outerjoin(Review).filter(Product.category=='women').group_by(Product.id)

        if sort == 'price_asc':
            products_query = products_query.order_by(Product.price.asc())
        elif sort == 'price_desc':
            products_query = products_query.order_by(Product.price.desc())
        elif sort == 'newest':
            products_query = products_query.order_by(Product.created_at.desc()) 
        elif sort == 'popularity':
            products_query = products_query.order_by(Product.popularity.desc())
        else:
            products_query = products_query.order_by(
            func.coalesce(func.avg(Review.rating), 0).desc(), 
            Product.popularity.desc()
             )
        women_products_with_ratings = products_query.all()

        product_ids_in_wishlist = set() 
        cart_quantities = {}

        if current_user.is_authenticated:
            wishlist_entries = Wishlist.query.filter_by(user_id=current_user.id).all()
            for item in wishlist_entries:
                product_ids_in_wishlist.add(item.product_id)
            
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if user_cart:
                for cart_item in user_cart.items.all():
                    cart_quantities[cart_item.product_id] = cart_item.quantity
        else:
            guest_wishlist_data = session.get('guest_wishlist', [])
            for item in guest_wishlist_data:
                if isinstance(item, dict) and 'product_id' in item:
                    try:  
                       product_ids_in_wishlist.add(int(item['product_id']))
                    except (ValueError, TypeError):
                       pass

            
            cart_session_data = session.get('cart', {})
            for pid_str, qty in cart_session_data.items():
                try:
                    cart_quantities[int(pid_str)] = qty
                except ValueError:
                    pass

        products_for_template = []
        for product_obj, avg_rating, review_count in women_products_with_ratings:
            product_data = {
                'id': product_obj.id,
                'name': product_obj.name,
                'price': product_obj.price,
                'image': product_obj.main_image_url,
                'category': product_obj.category,
                'in_wishlist': product_obj.id in product_ids_in_wishlist,
                'quantity_in_cart': cart_quantities.get(product_obj.id, 0),
                'average_rating': round(avg_rating, 1) if avg_rating is not None else 0,
                'review_count': review_count if review_count is not None else 0
            }
            products_for_template.append(product_data)

        return render_template('women.html', products=products_for_template, sort=sort)

@app.route('/sale')
def sale():
      return render_template("sale.html")      

@app.route('/category/<category_name>')
def category(category_name):
    # You can filter products based on the category_name
    products = Product.query.filter_by(category=category_name).all()
    return render_template("category.html", products=products, category_name=category_name)

# In your Flask route file
@limiter.limit("5 per minute")
@app.route('/cart')
def cart():
    cart_items_for_template = []
    total = 0
    conversion_rates = { 
        'INR': 1,
        'USD': 0.013,
        'EUR': 0.012,
        'GBP': 0.011,
    }
    currency_symbols = {
        'INR': '₹',
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
    }

    current_currency = session.get('currency', 'INR') 
    rate = conversion_rates.get(current_currency, 1)
    symbol = currency_symbols.get(current_currency, '₹')
    
    if current_user.is_authenticated:
        user_cart = Cart.query.filter_by(user_id=current_user.id).first()
        if user_cart:
            for cart_item_obj in user_cart.items: # Iterate over CartItem objects
                product = Product.query.get(cart_item_obj.product_id)
                if product:
                    item_total = cart_item_obj.quantity * product.price
                    total += item_total
                    color_name = cart_item_obj.color_name
                    color_hex = None
                    if color_name:
                         color_obj = Color.query.filter_by(name=color_name).first()
                         if color_obj:
                              color_hex = color_obj.hex_code
                    cart_items_for_template.append({
                        'product_id': cart_item_obj.product_id,
                        'quantity': cart_item_obj.quantity,
                        'size_name': cart_item_obj.size_name,
                        'color_name': cart_item_obj.color_name,
                        'color_hex': color_hex,
                        'total': item_total,
                        'product': { # Embed product details as a dictionary
                            'name': product.name,
                            'image': product.main_image_url,
                            'price': product.price,
                            'stock': product.stock # Useful for quantity checks
                        }
                    })
    else:
        # Guest user cart from session
        guest_cart = session.get('cart', {})
        current_app.logger.debug(f"Guest cart session data: {guest_cart}")
        for item_key, quantity in guest_cart.items():
            # item_key format: "product_id-size-color"
            parts = item_key.split('-')
            try:
                # --- START OF FIX ---
                # This correctly splits the key into its three parts
                product_id = int(parts[0])
                size_name = parts[1] if len(parts) > 1 and parts[1] != 'None' else None
                color_name = parts[2] if len(parts) > 2 and parts[2] != 'None' else None
                # --- END OF FIX ---
                
                product = Product.query.get(product_id)
                if product:
                    item_total = quantity * product.price
                    total += item_total
                    color_hex = None
                    if color_name:
                        color_obj = Color.query.filter_by(name=color_name).first()
                        color_hex = color_obj.hex_code if color_obj else None
                    cart_items_for_template.append({
                        'product_id': product_id,
                        'quantity': quantity,
                        'size_name': size_name,
                        'color_name': color_name,
                        'color_hex': color_hex,
                        'total': item_total,
                        'product': { # Embed product details as a dictionary
                            'name': product.name,
                            'image': product.main_image_url,
                            'price': product.price,
                            'stock': product.stock
                        }
                    })
                else:
                    current_app.logger.warning(f"Product ID {product_id} not found for guest cart item.")
                    # Optionally remove invalid item from session cart here
                    # del session['cart'][item_key]
                    # session.modified = True
            except (ValueError, IndexError):
                current_app.logger.error(f"Invalid cart item key format: {item_key}")
                # Optionally remove invalid item from session cart here
                # del session['cart'][item_key]
                # session.modified = True


    # Prepare wishlist products for template (assuming wishlist_section.html uses this)
    wishlist_products_for_template = []
    if current_user.is_authenticated:
        user_wishlist_items = Wishlist.query.filter_by(user_id=current_user.id).all()
        for wish_item in user_wishlist_items:
            product = Product.query.get(wish_item.product_id)
            if product:
                wishlist_products_for_template.append({
                    'id': product.id,
                    'name': product.name,
                    'image': product.main_image_url,
                    'price': product.price,
                    'size_name': wish_item.size_name,
                    'color_name': wish_item.color_name
                })
    else:
        guest_wishlist = session.get('guest_wishlist', [])
        for wish_data in guest_wishlist:
            product_id = None
            size_name = None
            color_name = None

            # --- ADDED TYPE CHECK HERE ---
            if isinstance(wish_data, dict):
                product_id = wish_data.get('product_id')
                size_name = wish_data.get('size')
                color_name = wish_data.get('color')
            else:
                # Assume wish_data is a simple product ID (string or int)
                product_id = wish_data
            # --- END ADDED TYPE CHECK ---

            if product_id is not None:
                try:
                    product_id_int = int(product_id) # Convert to int for query
                    product = Product.query.get(product_id_int)
                    if product:
                        wishlist_products_for_template.append({
                            'id': product.id,
                            'name': product.name,
                            'image': product.main_image_url,
                            'price': product.price,
                            'size_name': size_name,
                            'color_name': color_name
                        })
                except (ValueError, TypeError):
                    current_app.logger.error(f"Invalid product ID in guest wishlist: {product_id}")
                    # Optionally remove invalid item from session here
                    # session['guest_wishlist'].remove(wish_data)
                    # session.modified = True

    return render_template('cart.html', 
                            cart_items=cart_items_for_template, 
                            total=total, 
                            wishlist_products=wishlist_products_for_template, conversion_rates=conversion_rates, current_currency=session.get('currency', 'INR'), rate=rate, symbol=symbol, )



@limiter.limit("5 per minute")
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    try:
        data = request.get_json()
        received_csrf_token = request.headers.get('X-CSRFToken')

        # CSRF validation
        if not received_csrf_token:
            current_app.logger.warning("CSRF token missing from add to cart request.")
            return jsonify(success=False, message="CSRF token missing."), 400
        try:
            validate_csrf(received_csrf_token)
        except ValidationError:
            current_app.logger.warning("Invalid CSRF token received for add to cart.")
            return jsonify(success=False, message="Invalid CSRF token."), 400

        # Extract product and variant info
        product_id = data.get('product_id')
        if not product_id:
            return jsonify(success=False, message="Missing product ID."), 400

        quantity = int(data.get('quantity', 1))
        size_name = data.get('size')
        color_name = data.get('color')
        actual_size_name = size_name if size_name and size_name != 'N/A' else None
        actual_color_name = color_name if color_name and color_name != 'N/A' else None

        current_app.logger.debug(f"[ADD TO CART] Product ID={product_id}, User={getattr(current_user, 'id', None)}, Qty={quantity}, Size={actual_size_name}, Color={actual_color_name}")

        # Fetch product
        product = db.session.get(Product, product_id)
        if not product:
            return jsonify(success=False, message="Product not found."), 404
        if quantity <= 0:
            return jsonify(success=False, message="Quantity must be at least 1."), 400
        if quantity > product.stock:
            return jsonify(success=False, message=f"Not enough stock. Only {product.stock} available."), 400

        # --- Logged-in user cart logic ---
        if current_user.is_authenticated:
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if not user_cart:
                user_cart = Cart(user_id=current_user.id)
                db.session.add(user_cart)
                db.session.commit()  # Commit to get cart ID

            cart_item = CartItem.query.filter_by(
                cart_id=user_cart.id,
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if cart_item:
                if cart_item.quantity + quantity > product.stock:
                    return jsonify(
                        success=False,
                        message=f"Adding {quantity} would exceed stock. Current in cart: {cart_item.quantity}, Available: {product.stock - cart_item.quantity}"
                    ), 400
                cart_item.quantity += quantity
                flash_message = f"Added {quantity} more of '{product.name}' to your cart."
            else:
                cart_item = CartItem(
                    cart_id=user_cart.id,
                    product_id=product_id,
                    quantity=quantity,
                    size_name=actual_size_name,
                    color_name=actual_color_name
                )
                db.session.add(cart_item)
                flash_message = f"'{product.name}' added to your cart!"

            db.session.commit()
            current_app.logger.info(flash_message)

            # --- Remove from wishlist ---
            wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()
            if wishlist_item:
                db.session.delete(wishlist_item)
                db.session.commit()
                current_app.logger.info(f"Removed product {product_id} from wishlist for user {current_user.id}")

        # --- Guest user cart logic ---
        else:
            guest_cart = session.get('cart', {})
            item_key = f"{int(product_id)}-{actual_size_name or 'None'}-{actual_color_name or 'None'}"
            current_quantity = guest_cart.get(item_key, 0)
            if current_quantity + quantity > product.stock:
                return jsonify(
                    success=False,
                    message=f"Adding {quantity} would exceed stock. Current in cart: {current_quantity}, Available: {product.stock - current_quantity}"
                ), 400
            guest_cart[item_key] = current_quantity + quantity
            session['cart'] = guest_cart
            session.modified = True

            flash_message = f"'{product.name}' added to your guest cart!"
            current_app.logger.info(flash_message)
            current_app.logger.debug(f"Guest cart after add: {session.get('cart')}")

        return jsonify(success=True, message=flash_message)

    except SQLAlchemyError as db_err:
        db.session.rollback()
        current_app.logger.error(f"Database error on add_to_cart: {db_err}", exc_info=True)
        return jsonify(success=False, message="A database error occurred."), 500
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error on add_to_cart: {e}", exc_info=True)
        return jsonify(success=False, message=f"An unexpected error occurred: {str(e)}"), 500



@app.route('/update_cart', methods=['POST'])
def update_cart():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        action = data.get('action')  # 'increase' or 'decrease'
        size_name = data.get('size')
        color_name = data.get('color')

        if not product_id or not action:
            return jsonify(success=False, message="Missing product ID or action."), 400

        actual_size_name = size_name if size_name and size_name != 'N/A' else None
        actual_color_name = color_name if color_name and color_name != 'N/A' else None

        product = Product.query.get(product_id)
        if not product:
            return jsonify(success=False, message="Product not found."), 404

        # Get stock for the specific variant
        variant_stock = 0
        if actual_size_name:
            for ps in product.product_sizes:
                if ps.size.name == actual_size_name:
                    variant_stock = ps.quantity
                    break
        else:
            variant_stock = product.stock  # fallback if no size

        # If you have color stock as well, you can further filter here
        # e.g., variant_stock = get_stock_for_size_and_color(product, actual_size_name, actual_color_name)

        quantity = 0
        item_total = 0

        if current_user.is_authenticated:
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if not user_cart:
                return jsonify(success=False, message="Cart not found."), 404

            cart_item = CartItem.query.filter_by(
                cart_id=user_cart.id,
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if not cart_item:
                return jsonify(success=False, message="Item not found in cart."), 404

            if action == 'increase':
                if cart_item.quantity < variant_stock:
                    cart_item.quantity += 1
                else:
                    return jsonify(success=False, message=f"Maximum stock ({variant_stock}) reached for this variant."), 400
            elif action == 'decrease':
                cart_item.quantity -= 1
                if cart_item.quantity < 0:
                    cart_item.quantity = 0
            else:
                return jsonify(success=False, message="Invalid action."), 400

            db.session.commit()
            quantity = cart_item.quantity
            item_total = quantity * product.price

        else:
            # Guest cart
            guest_cart = session.get('cart', {})
            item_key = f"{product_id}-{actual_size_name if actual_size_name else 'None'}-{actual_color_name if actual_color_name else 'None'}"
            current_quantity = guest_cart.get(item_key, 0)

            if action == 'increase':
                if current_quantity < variant_stock:
                    current_quantity += 1
                else:
                    return jsonify(success=False, message=f"Maximum stock ({variant_stock}) reached for this variant."), 400
            elif action == 'decrease':
                current_quantity -= 1
                if current_quantity < 0:
                    current_quantity = 0
            else:
                return jsonify(success=False, message="Invalid action."), 400

            if current_quantity == 0:
                guest_cart.pop(item_key, None)
            else:
                guest_cart[item_key] = current_quantity

            session['cart'] = guest_cart
            session.modified = True
            quantity = current_quantity
            item_total = quantity * product.price

        # Recalculate total cart amount
        total_cart_amount = 0
        if current_user.is_authenticated:
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if user_cart and user_cart.items:
                total_cart_amount = sum(item.product.price * item.quantity for item in user_cart.items)
        else:
            guest_cart = session.get('cart', {})
            for key, qty in guest_cart.items():
                parts = key.split('-', 2)
                try:
                    p_id = int(parts[0])
                except (ValueError, IndexError):
                    continue
                prod = Product.query.get(p_id)
                if prod:
                    total_cart_amount += qty * prod.price

        return jsonify(
            success=True,
            quantity=quantity,
            item_total=item_total,
            total_cart_amount=total_cart_amount
        )

    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"An unexpected error occurred: {str(e)}"), 500


@app.route('/product/<string:product_id>', methods=['GET', 'POST'])
def product_details(product_id):
    try:
        product_id_int = int(product_id)
        product = Product.query.options(
            joinedload(Product.sizes),
            joinedload(Product.images),
            joinedload(Product.colors)
        ).get_or_404(product_id_int)
    except ValueError:
        product = Product.query.options(
            joinedload(Product.sizes),
            joinedload(Product.images),
            joinedload(Product.colors)
        ).filter_by(id=product_id).first_or_404()

    # Recently viewed logic
    recently_viewed = session.get('recently_viewed', [])
    if product.id in recently_viewed:
        recently_viewed.remove(product.id)
    recently_viewed.insert(0, product.id)
    session['recently_viewed'] = recently_viewed[:8]

    # Log user view activity
    if current_user.is_authenticated:
        view = UserActivity(user_id=current_user.id, product_id=product.id, activity_type='view')
        db.session.add(view)
        db.session.commit()

    # Initialize the Add to Cart form
    form = AddToCartForm()
    form.size.choices = [(s.name, s.name) for s in product.sizes] or [('N/A', 'N/A')]
    form.color.choices = [(c.name, c.name) for c in product.colors] or [('N/A', 'N/A')]

    # Wishlist logic
    is_in_wishlist = False
    if current_user.is_authenticated:
        is_in_wishlist = Wishlist.query.filter_by(user_id=current_user.id, product_id=product.id).first() is not None
    else:
        guest_wishlist = session.get('guest_wishlist', [])
        # Simplified check for wishlist items
        is_in_wishlist = any(item.get('product_id') == product.id if isinstance(item, dict) else str(item) == str(product.id) for item in guest_wishlist)

    # --- Handle Add to Cart Form Submission ---
    if form.validate_on_submit():
        quantity = form.quantity.data
        selected_size = request.json.get('size_name') if request.is_json else form.size.data
        selected_color = request.json.get('color_name') if request.is_json else form.color.data

        # Enforce color selection if colors exist
        if product.colors and selected_color == 'N/A':
            flash('Please select a color.', 'error')
            return redirect(url_for('product_details', product_id=product_id))

        # --- Your add-to-cart logic (for both authenticated and guest users) goes here ---

        flash_message = f'Added {quantity} x {product.name}'
        if selected_color != 'N/A':
            flash_message += f' ({selected_color})'
        if selected_size != 'N/A':
            flash_message += f' (Size: {selected_size})'
        flash_message += ' to your cart!'

        flash(flash_message, 'success')
        return redirect(url_for('product_details', product_id=product_id))

    # --- Fetch similar and recently viewed products ---
    similar_products = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id
    ).limit(8).all()

    recent_products = []
    if recently_viewed:
        recent_products = Product.query.filter(Product.id.in_(recently_viewed)).limit(6).all()

    # Dynamic price
    user = current_user if current_user.is_authenticated else None
    final_price = get_dynamic_price(product, user)

    # Render the template
    return render_template(
        'product_detail.html',
        product=product,
        final_price=final_price,
        form=form,
        is_in_wishlist=is_in_wishlist,
        similar_products=similar_products,
        recent_products=recent_products,
        colors=product.colors
    )




@limiter.limit("5 per minute")
@app.route('/checkout', methods=['GET']) # Only GET here now, for initial page load
@login_required
def checkout():
    cart_items_for_template = []
    total_cart_amount = 0

    # ... (cart calculation logic remains the same) ...

    if not cart_items_for_template:
        flash("Your cart is empty! Cannot proceed to checkout.", "warning")
        return redirect(url_for('cart'))

    # On initial GET, we still need the total for display
    amount_in_paise = int(total_cart_amount * 100)

    # We DON'T create a Razorpay order here on GET.
    # The order_id and amount for Razorpay will come *after* 'create_order'
     # --- ADD THESE LINES TEMPORARILY ---
    test_csrf_value = generate_csrf()
    print(f"DEBUG: CSRF token generated for checkout GET: {test_csrf_value}")
    if not test_csrf_value:
        print("WARNING: generate_csrf() returned an empty or None value!")
    # --- END ADDED LINES ---

    return render_template("checkout.html",
                           cart_items=cart_items_for_template,
                           total=total_cart_amount,
                           amount=amount_in_paise, # This amount is for display in forms
                           order_id=None, # No Razorpay order_id on initial load
                           key_id=app.config['RAZORPAY_KEY_ID'],
                           user=current_user)


@app.route("/create_order", methods=["GET", "POST"])
@login_required
def create_order():
    user_cart = Cart.query.filter_by(user_id=current_user.id).first()
    cart_items_for_template = []
    total_cart_amount = 0

    if user_cart:
        for cart_item in user_cart.items:
            product = db.session.get(Product, cart_item.product_id)
            if product:
                subtotal = product.price * cart_item.quantity
                total_cart_amount += subtotal
                cart_items_for_template.append({
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'quantity': cart_item.quantity,
                    'total': subtotal,
                    'size_name': cart_item.size_name,
                    'color_name': cart_item.color_name
                })

    if not cart_items_for_template:
        flash("Your cart is empty!", "warning")
        return redirect(url_for('cart'))

    amount_for_razorpay_paise = int(total_cart_amount * 100)

    if request.method == "POST":
        # ... read form fields (same as your code) ...
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        house_no = request.form.get("house_no")
        road = request.form.get("road")
        area = request.form.get("area")
        city = request.form.get("city")
        state = request.form.get("state")
        pincode = request.form.get("pincode")
        shipping_method = request.form.get("shipping_method")
        save_to_profile = request.form.get("save_to_profile") == "on"

        # validations (same)
        if not all([name, email, phone, house_no, city, state, pincode, shipping_method]):
            flash("Please fill in all required fields.", "danger")
            return render_template("checkout.html", cart_items=cart_items_for_template, total=total_cart_amount,
                                   amount=amount_for_razorpay_paise, order_id=None,
                                   key_id=app.config['RAZORPAY_KEY_ID'], user=current_user, name=name, email=email,
                                   phone=phone, house_no=house_no, road=road, area=area, city=city,
                                   state=state, pincode=pincode, shipping_method=shipping_method,
                                   save_to_profile=save_to_profile)

        amount_rupees_from_form = float(request.form.get("amount", 0))
        if abs(total_cart_amount - amount_rupees_from_form) > 0.01:
            flash("Cart total mismatch. Please refresh the page.", "danger")
            return redirect(url_for('cart'))

        if save_to_profile:
            try:
                current_user.name = name
                current_user.mobile = phone
                current_user.pincode = pincode
                current_user.state = state
                current_user.city = city
                current_user.house_no = house_no
                current_user.road = road
                current_user.area = area
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"WARNING: Failed to save profile changes: {e}")

        full_address = ", ".join(filter(None, [house_no, road, area, city, state, pincode]))

        # ✅ NEW: COD BRANCH — no Razorpay call, create order and go to Thank You
        if shipping_method == "COD":
            try:
                friendly = generate_order_number()
                new_order = Order(
                    order_number=friendly,
                    order_id=friendly,                 # CHANGED: keep legacy col in sync
                    razorpay_order_id=None,            # no Razorpay
                    payment_method="COD",
                    user_id=current_user.id,
                    amount=total_cart_amount,
                    status="cod_placed",
                    order_name=name,
                    order_mobile=phone,
                    order_pincode=pincode,
                    order_state=state,
                    order_city=city,
                    order_house_no=house_no,
                    order_road=road,
                    order_area=area,
                    delivery_address=full_address,
                    email=email,
                    shipping_method=shipping_method
                )
                db.session.add(new_order)

                for cart_item in user_cart.items.all():
                    product = db.session.get(Product, cart_item.product_id)
                    if product:
                        db.session.add(OrderItem(
                            order=new_order,
                            product_id=product.id,
                            name=product.name,
                            quantity=cart_item.quantity,
                            price_at_purchase=product.price,
                            size_name=cart_item.size_name,
                            color_name=cart_item.color_name
                        ))

                # Clear cart for COD too
                for item in user_cart.items.all():
                    db.session.delete(item)
                db.session.delete(user_cart)
                session.pop('cart', None)

                db.session.commit()

                # Optional notifications
                try:
                    send_email_notification(new_order, current_user)
                    send_whatsapp_notification(new_order, current_user)
                except Exception as e:
                    print(f"Notification error (COD): {e}")

                return redirect(url_for("thank_you", order_id=new_order.id))
            except Exception as e:
                db.session.rollback()
                print(f"ERROR: COD order creation failed: {e}")
                flash("Could not place your COD order. Please try again.", "danger")
                return redirect(url_for('cart'))

        # 💳 ONLINE BRANCH — create Razorpay order, then render checkout so JS opens the popup
        try:
            razorpay_order = client.order.create({
                "amount": amount_for_razorpay_paise,
                "currency": "INR",
                "payment_capture": 0,
                "receipt": f"receipt_{current_user.id}_{datetime.now().timestamp()}"
            })
            rp_id = razorpay_order["id"]
        except Exception as e:
            print(f"ERROR: Razorpay order creation failed: {e}")
            flash("Failed to initiate payment. Please try again.", "danger")
            return redirect(url_for("cart"))

        friendly = generate_order_number()
        new_order = Order(
            order_number=friendly,
            order_id=friendly,                # CHANGED: keep legacy col in sync
            razorpay_order_id=rp_id,          # NEW: store Razorpay id here
            payment_method="ONLINE",
            user_id=current_user.id,
            amount=total_cart_amount,
            status="pending_payment",
            order_name=name,
            order_mobile=phone,
            order_pincode=pincode,
            order_state=state,
            order_city=city,
            order_house_no=house_no,
            order_road=road,
            order_area=area,
            delivery_address=full_address,
            email=email,
            shipping_method=shipping_method
        )
        db.session.add(new_order)

        for cart_item in user_cart.items.all():
            product = db.session.get(Product, cart_item.product_id)
            if product:
                db.session.add(OrderItem(
                    order=new_order,
                    product_id=product.id,
                    name=product.name,
                    quantity=cart_item.quantity,
                    price_at_purchase=product.price,
                    size_name=cart_item.size_name,
                    color_name=cart_item.color_name
                ))

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("Could not save your order. Please try again.", "danger")
            return render_template("checkout.html", cart_items=cart_items_for_template, total=total_cart_amount,
                                   amount=amount_for_razorpay_paise, order_id=None,
                                   key_id=app.config['RAZORPAY_KEY_ID'], user=current_user)

        # Render template so frontend opens Razorpay (note: pass rp_id, not friendly)
        return render_template("checkout.html", cart_items=cart_items_for_template, total=total_cart_amount,
                               amount=amount_for_razorpay_paise, order_id=rp_id,
                               key_id=app.config['RAZORPAY_KEY_ID'], user=current_user)

    # GET (unchanged)
    return render_template("checkout.html", cart_items=cart_items_for_template, total=total_cart_amount,
                           amount=amount_for_razorpay_paise, order_id=None,
                           key_id=app.config['RAZORPAY_KEY_ID'], user=current_user,
                           name=current_user.name or '', email=current_user.email or '',
                           phone=current_user.mobile or '', house_no=current_user.house_no or '',
                           road=current_user.road or '', area=current_user.area or '',
                           city=current_user.city or '', state=current_user.state or '',
                           pincode=current_user.pincode or '',
                           shipping_method=getattr(current_user, 'shipping_method', 'Standard Shipping'),
                           save_to_profile=False)


@app.route("/payment_success", methods=["POST"])
@login_required
def payment_success():
    if client is None:
        return jsonify({"success": False, "message": "Payment service unavailable."}), 500

    try:
        razorpay_order_id = request.form.get("razorpay_order_id")
        payment_id = request.form.get("razorpay_payment_id")
        signature = request.form.get("razorpay_signature")

        if not all([razorpay_order_id, payment_id, signature]):
            return jsonify({'success': False, 'message': 'Missing payment details'}), 400

        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }

        try:
           client.utility.verify_payment_signature(params_dict)
        except Exception:
            return jsonify({"success": False, "message": "Payment verification failed"}), 400

# ✅ Fraud detection here
        try:
           payment_data = client.payment.fetch(payment_id)
           if is_suspicious_payment(payment_data):
               ip = request.remote_addr
               notify_admin(f"⚠️ Suspicious payment detected\nUser: {current_user.id}\nIP: {ip}\nAmount: ₹{int(payment_data['amount']) / 100}\nMethod: {payment_data.get('method')}")
        except Exception as e:
            print(f"WARNING: Failed to fetch payment data for fraud detection: {e}")

            
        except Exception:
            return jsonify({"success": False, "message": "Payment verification failed"}), 400

        order = Order.query.filter_by(razorpay_order_id=razorpay_order_id).first()
        if not order:
            return jsonify({"success": False, "message": "Order not found"}), 404

        # Update status
        order.status = "paid"
        order.payment_id = payment_id
        order.signature = signature

        # Save updated address details from frontend
        for field in ['name', 'email', 'phone', 'house_no', 'road', 'area', 'city', 'state', 'pincode', 'shipping_method']:
            setattr(order, f"order_{field}" if field not in ['email', 'shipping_method'] else field, request.form.get(field))

        order.delivery_address = ", ".join(filter(None, [
            request.form.get('house_no'), request.form.get('road'), request.form.get('area'),
            request.form.get('city'), request.form.get('state'), request.form.get('pincode')
        ])).strip()

        if request.form.get("save_to_profile") == 'true':
            try:
                current_user.name = request.form.get("name")
                current_user.mobile = request.form.get("phone")
                current_user.pincode = request.form.get("pincode")
                current_user.state = request.form.get("state")
                current_user.city = request.form.get("city")
                current_user.house_no = request.form.get("house_no")
                current_user.road = request.form.get("road")
                current_user.area = request.form.get("area")
            except Exception as e:
                print(f"WARNING: Profile update failed: {e}")

        # Clear cart
        user_cart = Cart.query.filter_by(user_id=current_user.id).first()
        if user_cart:
            for item in user_cart.items.all():
                db.session.delete(item)
            db.session.delete(user_cart)
        session.pop('cart', None)

        db.session.commit()

        # Optional notifications
        send_email_notification(order, current_user)
        send_whatsapp_notification(order, current_user)

        return jsonify({"success": True, "url": url_for("thank_you", order_id=order.id)})

    except Exception as e:
        db.session.rollback()
        print(f"ERROR in payment_success: {e}")
        return jsonify({"success": False, "message": "Server error."}), 500


@app.route("/payment_failed")
def payment_failed():
    """
    Handles payment failure scenarios.
    Displays a message to the user that the payment could not be processed.
    """
    flash("Your payment could not be processed. Please try again or contact support.", "danger")
    return render_template("payment_failed.html")


from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta

@app.route('/thank_you')
@login_required
def thank_you():
    latest_order = (
        db.session.query(Order)
        .options(
            selectinload(Order.items)                # Order -> items
            .selectinload(OrderItem.product)         # items -> product
            .selectinload(Product.images)            # product -> images (for main_image_url)
        )
        .filter_by(user_id=current_user.id)
        .order_by(Order.id.desc())
        .first()
    )

    estimated_delivery = (datetime.utcnow() + timedelta(days=5)).strftime('%B %d, %Y')

    # Clear cart
    session.pop('cart', None)

    # Normalize items and attach a display_image_url + unit_price field the template can use
    items = []
    if latest_order:
        raw_items = latest_order.items or []
        for it in raw_items:
            # Pick product main image (works for Cloudinary full URL or your static fallback)
            img = None
            if getattr(it, "product", None):
                # Uses Product.main_image_url from your model
                img = it.product.main_image_url

            # Attach transient helpers for template
            setattr(it, "display_image_url", img)
            setattr(it, "unit_price", it.price_at_purchase)  # clearer alias
            items.append(it)

    return render_template(
        "thank_you.html",
        order=latest_order,
        estimated_delivery=estimated_delivery,
        items=items
    )



@limiter.limit("5 per minute")
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        mobile = request.form.get('mobile')
        gender = request.form.get('gender')

        # Dictionary to pass existing form data back to template in case of error
        form_data = {
            'email': email,
            'mobile': mobile,
            'gender': gender
        }

        # Validate that all required fields are filled
        if not email or not password or not mobile:
            flash('All required fields (Email, Password, Mobile Number) must be filled.', 'error')
            return render_template('signup.html', **form_data)

        # Server-side Password Validation
        password_pattern = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$")
        if not password_pattern.match(password):
            flash('Password must contain at least one capital letter, one number, and one symbol (@$!%*#?&), and be at least 8 characters long.', 'error')
            return render_template('signup.html', **form_data)
        
        # Mobile number format validation
        if not (mobile.isdigit() and len(mobile) == 10):
            flash('Please enter a valid 10-digit mobile number.', 'error')
            return render_template('signup.html', **form_data)

        # Check for existing email and mobile
        if User.query.filter_by(email=email).first():
            flash('Email address is already registered. Please login instead.', 'error')
            return render_template('signup.html', **form_data)

        if User.query.filter_by(mobile=mobile).first():
            flash('Mobile number is already registered. Please login or use a different number.', 'error')
            return render_template('signup.html', **form_data)

        # Create new user instance with the user's email as their username
        # This assumes your User model can handle 'email' as the username field
        user = User(username=email, email=email, mobile=mobile, gender=gender if gender else None)

        try:
          user.set_password(password)
        except ValueError as e:
          flash(f"Error setting password: {e}", 'error')
          return render_template('signup.html', **form_data)

        db.session.add(user)
        db.session.commit()

        login_user(user, remember=True)
        flash('Account created successfully! You are now logged in.', 'success')
        return redirect(url_for('home'))

    # For GET request, render the empty signup form
    return render_template('signup.html', email='', mobile='', gender='')


@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        # Redirect if already logged in
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')

        if not identifier or not password:
            flash('Please enter your username, email, or mobile number and password.', 'error')
            return render_template('login.html')

        user = None
        # Try to find user by username, email, or mobile number
        user = User.query.filter_by(username=identifier).first()
        if not user:
            user = User.query.filter_by(email=identifier).first()
        if not user and identifier.isdigit() and len(identifier) >= 10:
            user = User.query.filter_by(mobile=identifier).first()

        # Check if user was found and password is correct
        if user and user.check_password(password):
            login_user(user, remember=True)
            log_user_activity(user.id, "User logged in")
            flash('Logged in successfully!', 'success')

            # --- CORRECTED Cart Merge Logic ---
            guest_cart_data = session.get('cart', {})
            if guest_cart_data:
                user_db_cart = Cart.query.filter_by(user_id=user.id).first()
                if not user_db_cart:
                    user_db_cart = Cart(user_id=user.id)
                    db.session.add(user_db_cart)
                    db.session.commit()

                # Iterate through keys like '10-S'
                for item_key, quantity in guest_cart_data.items():
                    try:
                        # Split the key to get the product_id and size
                        parts = item_key.split('-')
                        product_id_str = parts[0]
                        size_name = parts[1] if len(parts) > 1 and parts[1] != 'None' else None

                        # Correctly convert only the product_id part to an integer
                        product_id = int(product_id_str)

                        existing_item = CartItem.query.filter_by(
                            cart_id=user_db_cart.id,
                            product_id=product_id,
                            size_name=size_name
                        ).first()

                        if existing_item:
                            existing_item.quantity += quantity
                        else:
                            new_item = CartItem(
                                cart_id=user_db_cart.id,
                                product_id=product_id,
                                quantity=quantity,
                                size_name=size_name
                            )
                            db.session.add(new_item)
                    except (ValueError, IndexError) as e:
                        current_app.logger.error(f"Error merging guest cart item '{item_key}': {e}")
                        continue

                db.session.commit()
                session.pop('cart', None) # Clear the guest cart from the session

            # --- Unified and Corrected Wishlist Merge Logic ---
            guest_wishlist_items = session.get('guest_wishlist', [])
            if guest_wishlist_items:
                for item in guest_wishlist_items:
                    product_id = item.get('product_id')

                    if not product_id:
                        continue
                    
                    # Find existing wishlist item for this user, product, and size
                    existing_wish_item = Wishlist.query.filter_by(
                        user_id=user.id, 
                        product_id=product_id,
                    ).first()

                    if not existing_wish_item:
                        # Only add if the item doesn't already exist in the user's database wishlist
                        new_wish_item = Wishlist(user_id=user.id, product_id=product_id)
                        db.session.add(new_wish_item)
                
                db.session.commit()
                session.pop('guest_wishlist', None)

            # Redirect to the page they were trying to access, or home
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
        # The URL is relative and therefore safe.
                return safe_redirect(next_page, fallback='home')
            else:
        # The URL is external or not provided. Redirect to the home page.
                return redirect(url_for('home'))
        else:
            flash('Invalid username, email, mobile number, or password.', 'error')
            return render_template('login.html')
    return render_template('login.html')



@app.route('/logout')
# @login_required # Optional, but good practice
def logout():
    logout_user()
    session.pop('cart', None) # Clear guest cart from session
    session.pop('guest_wishlist', None) # Clear guest wishlist from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('home')) # Redirect to home or login page   


@limiter.limit("5 per minute")
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        user = None
        
        if not identifier:
            flash('Please enter your email address or mobile number.', 'error')
            return render_template('forgot_password.html')

        email_pattern = re.compile(r'[^@]+@[^@]+\.[^@]+')
        
        if email_pattern.match(identifier):
            user = User.query.filter_by(email=identifier).first()
            action_type = "email"
        elif identifier.isdigit() and len(identifier) == 10:
            user = User.query.filter_by(mobile=identifier).first()
            action_type = "mobile"
        else:
            flash('Please enter a valid email or 10-digit mobile number.', 'error')
            return render_template('forgot_password.html', identifier=identifier)

        if user:
            if action_type == "mobile":
                otp_code = ''.join(secrets.choice('0123456789') for _ in range(6))
                otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
                user.otp_code = otp_code
                user.otp_expiry = otp_expiry
                db.session.commit()

                # --- NEW: Call the AuthKey function here ---
                if send_otp_via_authkey(user.mobile, otp_code):
                    flash(f"A verification code has been sent to your mobile number.", 'success')
                    return redirect(url_for('verify_otp', mobile=user.mobile))
                else:
                    # If the API call fails, inform the user
                    flash('Failed to send the OTP. Please try again later.', 'error')
                    return render_template('forgot_password.html', identifier=identifier)
            else:
                # Your email-based reset logic
                token = user.get_reset_token()
                # send_reset_email(user.email, token)
                flash(f"An email with instructions to reset your password has been sent.", 'success')
                return redirect(url_for('login'))

        flash('If the identifier you entered is registered, a password reset link or code has been sent.', 'info')
        return render_template('forgot_password.html', identifier=identifier)

    return render_template('forgot_password.html')


@limiter.limit("5 per minute")
@limiter.limit("5 per minute")
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    mobile = request.args.get('mobile')
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        mobile_from_form = request.form.get('mobile')

        if not entered_otp or not mobile_from_form:
            flash('Please enter the OTP and your mobile number.', 'error')
            return render_template('verify_otp.html', mobile=mobile_from_form)

        user = User.query.filter_by(mobile=mobile_from_form).first()

        # Correct usage of datetime.now() with timezone.utc for comparison
        if user and user.otp_code == entered_otp and user.otp_expiry > datetime.now(timezone.utc):
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()

            reset_token = user.get_reset_token()
            flash('OTP verified successfully! You can now reset your password.', 'success')
            return redirect(url_for('reset_password', token=reset_token))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
            return render_template('verify_otp.html', mobile=mobile_from_form)

    return render_template('verify_otp.html', mobile=mobile)


@limiter.limit("5 per minute")
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        try:
            # ✅ Flask-Security handles policy validation here
            hashed_pw = generate_password_hash(new_password)
            user.password = hashed_pw
            db.session.commit()
            flash("Your password has been updated!", "success")
            return redirect(url_for("login"))
        except ValueError as e:
            # Raised if password does not meet policy
            flash(f"Invalid password: {e}", "error")
            return render_template("reset_password.html", token=token)

    return render_template("reset_password.html", token=token)

@limiter.limit("5 per minute")
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # Ensure it's a POST request for sensitive operation
    if request.method == 'POST':
        # Get the actual User object from the database
        # current_user.id gives you the ID of the logged-in user
        user_to_delete = User.query.get(current_user.id)

        if user_to_delete: # Check if the user object was found (it should be)
            # Log out the user before deleting to invalidate the session
            logout_user()

            # Perform the deletion
            db.session.delete(user_to_delete)
            db.session.commit()

            flash('Your account has been successfully deleted.', 'success')
            return redirect(url_for('home'))
        else:
            # This case should ideally not happen if login_required is working
            flash('Error: User not found for deletion.', 'error')
            return redirect(url_for('dashboard')) # Redirect to dashboard or home

    # If it's not a POST request (e.g., trying to access directly via GET)
    flash('Invalid request method for account deletion.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/dashboard', endpoint='user_dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return render_template("admin/admin_dashboard.html", user=current_user)
    
    # For normal user: fetch last 5 orders
    last_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(3).all()

    
    return render_template("user_dashboard.html", user=current_user, last_orders=last_orders)



@app.route('/profile')
@login_required
def profile():
    recent_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(3).all()
    return render_template('profile.html', user=current_user, recent_orders=recent_orders)



@app.route('/orders')
@login_required
def orders():
    # Get filter parameters from the request
    status_filter = request.args.get('status', 'all')
    timeframe_filter = request.args.get('timeframe', 'all')

    # Start with the base query
    base_query = Order.query.filter_by(user_id=current_user.id)

    # Apply status filter
    if status_filter != 'all':
        if status_filter == 'on_the_way':
            # This is a placeholder for your actual 'on the way' status
            base_query = base_query.filter(Order.status.in_(['Shipped', 'Out for Delivery']))
        else:
            base_query = base_query.filter_by(status=status_filter.capitalize())

    # Apply timeframe filter
    if timeframe_filter != 'all':
        today = datetime.now()
        if timeframe_filter == '30_days':
            date_ago = today - timedelta(days=30)
            base_query = base_query.filter(Order.created_at >= date_ago)
        elif timeframe_filter == '6_months':
            date_ago = today - timedelta(days=180) # Approximately 6 months
            base_query = base_query.filter(Order.created_at >= date_ago)
        elif timeframe_filter == 'past_years':
            date_ago = today.replace(year=today.year - 1)
            base_query = base_query.filter(Order.created_at < date_ago)

    # Fetch the orders with the applied filters
    user_orders = base_query.options(db.joinedload(Order.items).joinedload(OrderItem.product))\
                            .order_by(Order.created_at.desc())\
                            .all()

    # Pass the current filter values back to the template to keep the radio buttons checked
    return render_template('orders.html', 
                           orders=user_orders,
                           current_status=status_filter,
                           current_timeframe=timeframe_filter)



@app.route('/remove_from_cart', methods=['POST'])
# @login_required # Removed for guest cart functionality
def remove_from_cart():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        size_name = data.get('size')
        color_name = data.get('color')

        current_app.logger.debug(f"Remove from cart request: Product ID={product_id}, Size='{size_name}', Color='{color_name}'")

        if not product_id:
            current_app.logger.warning("Missing product ID in remove from cart request.")
            return jsonify(success=False, message="Missing product ID."), 400

        actual_size_name = size_name if size_name and size_name != 'N/A' else None
        actual_color_name = color_name if color_name and color_name != 'N/A' else None

        current_app.logger.debug(f"Normalized for DB query: Product ID={product_id}, Size={actual_size_name}, Color={actual_color_name}")

        action = '' # To store 'removed'

        if current_user.is_authenticated:
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if not user_cart:
                current_app.logger.warning(f"Cart not found for user {current_user.id} during removal.")
                return jsonify(success=False, message="Cart not found."), 404

            cart_item = CartItem.query.filter_by(
                cart_id=user_cart.id,
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if cart_item:
                db.session.delete(cart_item)
                db.session.commit()
                action = 'removed'
                flash_message = "Item removed from cart!"
                current_app.logger.info(flash_message)
            else:
                current_app.logger.warning(f"Cart item not found in DB with: Product ID={product_id}, Size={actual_size_name}, Color={actual_color_name}")
                return jsonify(success=False, message="Item not found in cart."), 404
        else:
    # Guest user cart from session
           guest_cart = session.get('cart', {})

# use a 3-part key: productId-size-color (match your add_to_cart format!)
           item_key = f"{int(product_id)}-{(actual_size_name or 'None')}-{(actual_color_name or 'None')}"

           if item_key in guest_cart:
              del guest_cart[item_key]
              session['cart'] = guest_cart
              session.modified = True
              action = 'removed'
              flash_message = "Item removed from guest cart!"
           else:
             current_app.logger.warning(f"Guest cart item not found in session with key: {item_key}")
             return jsonify(success=False, message="Item not found in guest cart."), 404


        # Recalculate total after removal (for both logged-in and guest)
        total_cart_amount = 0
        if current_user.is_authenticated:
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if user_cart and user_cart.items:
                total_cart_amount = sum(item.product.price * item.quantity for item in user_cart.items)
        else:
            guest_cart = session.get('cart', {})
            for item_key, quantity in guest_cart.items():
                parts = item_key.split('-')
                p_id = int(parts[0])
                product = Product.query.get(p_id)
                if product:
                    total_cart_amount += quantity * product.price

        return jsonify(success=True, action=action, message=flash_message, total_cart_amount=total_cart_amount)

    except Exception as e:
        db.session.rollback() # Only applies if a session transaction was started
        current_app.logger.error(f"ERROR: Failed to remove from cart for product ID {data.get('product_id', 'N/A')}: {e}", exc_info=True)
        return jsonify(success=False, message=f"An unexpected error occurred: {str(e)}"), 500


@app.route('/update_quantity/<int:product_id>', methods=['POST'])
def update_quantity(product_id):
    action = request.form.get('action')
    cart = session.get('cart', {})

    print("Before update:", cart)  # Debug

    pid = str(product_id)

    if pid in cart:
        if action == 'increase':
            cart[pid] += 1
        elif action == 'decrease':
            cart[pid] -= 1
            if cart[pid] <= 0:
                del cart[pid]

        session['cart'] = cart
        print("After update:", session['cart'])  # Debug
    else:
        print("Product not in cart!")

    return redirect(url_for('cart'))


@app.route('/order/<int:order_id>') # Changed from /orders/<int:order_id> to match your template
@login_required
def order_detail(order_id):
    # Fetch the order, ensuring it belongs to the current user or user is admin
    order = Order.query.filter_by(id=order_id).first_or_404()

    # Security check: Ensure user can only view their own orders or if they are admin
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this order.', 'danger')
        return redirect(url_for('user_dashboard'))

   
    products_in_order_for_template = []
    try:
        for order_item in order.items: # Loop through related OrderItem objects
            product = Product.query.get(order_item.product_id)
            if product:
                products_in_order_for_template.append({
                    'product': product,
                    'quantity': order_item.quantity,
                    'size': order_item.size, # Assuming OrderItem has size/color
                    'color': order_item.color, # Assuming OrderItem has size/color
                    'subtotal': order_item.price * order_item.quantity # Use item.price if stored on OrderItem
                })
        
      
    except Exception as e:
        print(f"Error loading order items: {e}")
        products_in_order_for_template = [] # Ensure it's empty on error

    # --- Construct the Shipping Address String ---
    shipping_address_display = ""
    parts = []

    # Add Name and Mobile
    if order.order_name:
        parts.append(f"To: {order.order_name}")
    if order.order_mobile:
        parts.append(f"Mobile: {order.order_mobile}")

    # Add Address Lines
    address_lines = []
    if order.order_house_no:
        address_lines.append(order.order_house_no)
    if order.order_road:
        address_lines.append(order.order_road)
    if order.order_area:
        address_lines.append(order.order_area)
    
    if address_lines:
        parts.append(", ".join(filter(None, address_lines))) # Join address lines with comma

    # Add City, State, Pincode
    city_state_pincode_parts = []
    if order.order_city:
        city_state_pincode_parts.append(order.order_city)
    if order.order_state:
        city_state_pincode_parts.append(order.order_state)
    if order.order_pincode:
        city_state_pincode_parts.append(f"- {order.order_pincode}") # Pincode with a hyphen

    if city_state_pincode_parts:
        parts.append(" ".join(filter(None, city_state_pincode_parts)).strip()) # Join with space, strip leading/trailing space

    shipping_address_display = "\n".join(filter(None, parts)) # Join all parts with newlines

 

    return render_template(
        'order_detail.html', # Ensure this matches your template file name
        order=order,
        product=products_in_order_for_template, # Pass the list of product dictionaries
        shipping_address_display=shipping_address_display # Pass the formatted address
    )

@app.route('/api/product_sizes/<int:product_id>', methods=['GET'])
def get_product_sizes(product_id):
    """
    Returns a JSON list of available sizes for a given product.
    """
    product = Product.query.options(joinedload(Product.sizes)).get_or_404(product_id)
    sizes = [{'name': s.name} for s in product.sizes]
    
    if not sizes:
        # If a product has no defined sizes, you might want a default 'One Size' or similar
        return jsonify(sizes=[{'name': 'N/A'}]), 200
        
    return jsonify(sizes=sizes), 200

@app.route('/api/product_colors/<int:product_id>', methods=['GET'])
def get_product_colors(product_id):
    """
    Returns a JSON list of available colors for a given product.
    """
    product = Product.query.options(joinedload(Product.colors)).get_or_404(product_id)
    colors = [{'name': c.name} for c in product.colors]
    
    if not colors:
        # If a product has no colors, return a default
        return jsonify(colors=[{'name': 'N/A'}]), 200
        
    return jsonify(colors=colors), 200



@app.route('/wishlist')
def wishlist():
    if current_user.is_authenticated:
        # 1. Fetch the user's wishlist items
        wishlist_items = Wishlist.query.filter_by(user_id=current_user.id).all()
        
        # 2. Eagerly load sizes and colors for each item
        for item in wishlist_items:
            if item.product:
                item.product.sizes
                item.product.colors
                
    else:
        # Handle guest wishlist from session
        guest_wishlist = session.get('guest_wishlist', [])
        wishlist_items = []
        for item in guest_wishlist:
            # Check the data type to prevent TypeError
            if isinstance(item, dict):
                product_id = item.get('product_id')
                size_name = item.get('size')
                color_name = item.get('color')
            else:
                product_id = item
                size_name = None
                color_name = None

            product = Product.query.get(product_id)
            if product:
                item_with_product = {
                    'product_id': product.id,
                    'product': product,
                    'size_name': size_name,
                    'color_name': color_name
                }
                wishlist_items.append(item_with_product)
        
    return render_template(
        'wishlist_items.html', 
        wishlist_items=wishlist_items, 
        Product=Product  # Pass the Product model to the template
    )

@limiter.limit("5 per minute")
@app.route('/add_to_wishlist', methods=['POST'])
def add_to_wishlist():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        size_name = data.get('size')
        color_name = data.get('color')

        current_app.logger.debug(f"Received wishlist toggle request: Product ID={product_id}, Size={size_name}, Color={color_name}")

        if not product_id:
            current_app.logger.warning("Missing product ID in wishlist toggle request.")
            return jsonify(success=False, message="Missing product ID."), 400

        product = Product.query.get(product_id)
        if not product:
            current_app.logger.warning(f"Product with ID {product_id} not found for wishlist operation.")
            return jsonify(success=False, message="Product not found."), 404

        # Normalize size_name and color_name to None if they are 'N/A'
        actual_size_name = size_name if size_name and size_name != 'N/A' else None
        actual_color_name = color_name if color_name and color_name != 'N/A' else None

        action = '' # To store 'added' or 'removed'

        if current_user.is_authenticated:
            # --- Logged-in User Logic (Database) ---
            wishlist_item = Wishlist.query.filter_by(
                user_id=current_user.id,
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if wishlist_item:
                db.session.delete(wishlist_item)
                db.session.commit()
                action = 'removed'
                flash_message = f"'{product.name}' removed from your wishlist."
            else:
                new_wishlist_item = Wishlist(
                    user_id=current_user.id,
                    product_id=product_id,
                    size_name=actual_size_name,
                    color_name=actual_color_name
                )
                db.session.add(new_wishlist_item)
                db.session.commit()
                action = 'added'
                flash_message = f"'{product.name}' added to your wishlist!"
            current_app.logger.info(flash_message)

        else:
            # --- Guest User Logic (Session) ---
            guest_wishlist = session.get('guest_wishlist', [])
            
            # Create a unique identifier for the item including its variant
            item_identifier = {
                'product_id': product_id,
                'size': actual_size_name,
                'color': actual_color_name
            }

            # Check if the item (with variant) is already in the guest wishlist
            found_index = -1
            for i, item in enumerate(guest_wishlist):
                if isinstance(item, dict) and \
                   item.get('product_id') == product_id and \
                   item.get('size') == actual_size_name and \
                   item.get('color') == actual_color_name:
                    found_index = i
                    break

            if found_index != -1:
                # Item found, remove it
                guest_wishlist.pop(found_index)
                action = 'removed'
                flash_message = f"'{product.name}' removed from your guest wishlist."
            else:
                # Item not found, add it
                guest_wishlist.append(item_identifier)
                action = 'added'
                flash_message = f"'{product.name}' added to your guest wishlist!"
            
            session['guest_wishlist'] = guest_wishlist
            session.modified = True 
            current_app.logger.info(flash_message)
            current_app.logger.debug(f"Guest wishlist after toggle: {session.get('guest_wishlist')}")

        return jsonify(success=True, action=action, message=flash_message)

    except Exception as e:
        db.session.rollback() 
        current_app.logger.error(f"ERROR: Failed to toggle wishlist for product ID {data.get('product_id', 'N/A')}: {e}", exc_info=True)
        return jsonify(success=False, message=f"An unexpected error occurred: {str(e)}"), 500



@app.route('/move_cart_item_to_wishlist', methods=['POST'])
def move_cart_item_to_wishlist():
    try:
        data = request.get_json()
        received_csrf_token = request.headers.get('X-CSRFToken')

        # Added: CSRF Protection
        if not received_csrf_token:
            return jsonify(success=False, message="CSRF token missing."), 400
        try:
            validate_csrf(received_csrf_token)
        except ValidationError:
            return jsonify(success=False, message="Invalid CSRF token."), 400
        
        product_id = data.get('product_id')
        size_name = data.get('size')
        color_name = data.get('color')

        current_app.logger.debug(f"Move cart item to wishlist request: Product ID={product_id}, Size={size_name}, Color={color_name}")

        if not product_id:
            current_app.logger.warning("Missing product ID in move to wishlist request.")
            return jsonify(success=False, message="Missing product ID."), 400

        product = Product.query.get(product_id)
        if not product:
            current_app.logger.warning(f"Product with ID {product_id} not found for move to wishlist operation.")
            return jsonify(success=False, message="Product not found."), 404

        # Normalize variant names
        actual_size_name = size_name if size_name and size_name.upper() != 'NONE' and size_name.upper() != 'N/A' else None
        actual_color_name = color_name if color_name and color_name.upper() != 'NONE' and color_name.upper() != 'N/A' else None

        if current_user.is_authenticated:
            # --- Logged-in user: Move item in database ---
            
            # 1. Find the user's cart. This is the fix for the traceback error.
            user_cart = Cart.query.filter_by(user_id=current_user.id).first()
            if not user_cart:
                current_app.logger.warning(f"No cart found for authenticated user {current_user.id}.")
                flash("Your cart is empty!", 'warning')
                return jsonify(success=False, message="No cart found.")

            # 2. Find and remove the item from CartItem, filtering by cart_id.
            cart_item_to_remove = CartItem.query.filter_by(
                cart_id=user_cart.id,  # Correct: Use cart_id, not user_id
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if cart_item_to_remove:
                db.session.delete(cart_item_to_remove)
                current_app.logger.info(f"Removed item {product_id} (size: {actual_size_name}, color: {actual_color_name}) from authenticated cart.")
            else:
                current_app.logger.warning(f"Item {product_id} not found in authenticated user's cart for removal (size: {actual_size_name}, color: {actual_color_name}).")
                # Even if not found, we still proceed to add to wishlist as the user intended.

            # 3. Add to Wishlist, including all variants
            existing_wishlist_item = Wishlist.query.filter_by(
                user_id=current_user.id,
                product_id=product_id,
                size_name=actual_size_name,
                color_name=actual_color_name
            ).first()

            if not existing_wishlist_item:
                new_wishlist_item = Wishlist(
                    user_id=current_user.id,
                    product_id=product_id,
                    size_name=actual_size_name,
                    color_name=actual_color_name
                )
                db.session.add(new_wishlist_item)
                current_app.logger.info(f"Added item {product_id} to authenticated wishlist (variant: {actual_size_name}/{actual_color_name}).")
            else:
                current_app.logger.info(f"Item {product_id} (variant: {actual_size_name}/{actual_color_name}) already exists in authenticated user's wishlist.")

            db.session.commit()
            flash(f"'{product.name}' moved to your wishlist!", 'success')
            return jsonify(success=True, message="Item moved to your wishlist!")

        else:
            # --- Guest user: Move item in session ---
            guest_cart = session.get('cart', {})
            guest_wishlist = session.get('guest_wishlist', [])
            item_removed_from_cart = False

            # Create the unique key for the item to remove from the cart
            cart_key = f"{product_id}-{actual_size_name or 'None'}-{actual_color_name or 'None'}"
            if cart_key in guest_cart:
                del guest_cart[cart_key]
                session['cart'] = guest_cart
                session.modified = True
                item_removed_from_cart = True
                current_app.logger.info(f"Removed item (key: {cart_key}) from guest cart session.")
            else:
                current_app.logger.warning(f"Item {product_id} (key: {cart_key}) not found in guest cart session for removal.")

            # Create a unique identifier for the wishlist item
            wishlist_item_identifier = {
                'product_id': product_id,
                'size': actual_size_name,
                'color': actual_color_name
            }

            # Check if this exact variant is already in the guest wishlist
            if wishlist_item_identifier not in guest_wishlist:
                guest_wishlist.append(wishlist_item_identifier)
                session['guest_wishlist'] = guest_wishlist
                session.modified = True
                current_app.logger.info(f"Added item {product_id} to guest wishlist session (variant: {actual_size_name}/{actual_color_name}).")
            else:
                current_app.logger.info(f"Item {product_id} (variant: {actual_size_name}/{actual_color_name}) already exists in guest wishlist session.")

            if item_removed_from_cart:
                flash(f"'{product.name}' moved to your wishlist!", 'success')
            else:
                flash(f"'{product.name}' was not found in your cart, but it's now in your wishlist!", 'warning')
            
            return jsonify(success=True, message="Item moved to your wishlist!")

    except Exception as e:
        if current_user.is_authenticated:
            db.session.rollback()
        current_app.logger.error(f"Error moving cart item to wishlist for product ID {product_id}: {e}", exc_info=True)
        return jsonify(success=False, message=f"An error occurred while moving the item to wishlist: {str(e)}"), 500



@app.route('/remove_from_wishlist', methods=['POST'])
def remove_from_wishlist():
    data = request.get_json()
    product_id = data.get('product_id')
    size = data.get('size') # This will be 'N/A' or an actual size
    color = data.get('color') # This will be 'N/A' or an actual color

    # Normalise size and color for comparison
    normalized_size = size if size and size != 'N/A' else None
    normalized_color = color if color and color != 'N/A' else None

    # Try converting product_id to int for consistent comparison later
    product_id_int = None
    try:
        product_id_int = int(product_id)
    except (ValueError, TypeError):
        pass # If product_id cannot be converted to int, it will remain None or its original string form

    if current_user.is_authenticated:
        # --- Logic for Authenticated Users (Database) ---
        try:
            item_to_remove = Wishlist.query.filter_by(
                user_id=current_user.id,
                product_id=product_id_int # Use int for database lookup
            ).first()

            if item_to_remove:
                db.session.delete(item_to_remove)
                db.session.commit()
                return jsonify({'success': True, 'message': 'Item removed from your database wishlist.'})
            else:
                return jsonify({'success': False, 'message': 'Item not found in your database wishlist.'}), 404
        except Exception as e:
            db.session.rollback()
            # Log the error for debugging purposes
            current_app.logger.error(f"Error removing authenticated wishlist item: {e}", exc_info=True)
            return jsonify({'success': False, 'message': f'An unexpected error occurred: {str(e)}'}), 500

    else:
        # --- Logic for Guest Users (Session) ---
        current_guest_wishlist = session.get('guest_wishlist', [])
        updated_wishlist = []
        item_removed = False

        # We need to handle two potential formats for guest_wishlist:
        # 1. A list of dictionaries (where each dict has product_id, size, color)
        # 2. A list of simple product IDs (integers) - older format or simpler additions
        
        # Check if the existing items in the guest wishlist are dictionaries (implying variants)
        # We assume if one is a dict, all should be, or we handle simple IDs separately.
        if all(isinstance(item, dict) for item in current_guest_wishlist):
            for item in current_guest_wishlist:
                # Compare the product_id (as string) and normalized size/color
                # Only remove the first matching item found to avoid removing duplicates accidentally
                if not (str(item.get('product_id')) == str(product_id) and \
                        item.get('size') == normalized_size and \
                        item.get('color') == normalized_color and \
                        not item_removed):
                    updated_wishlist.append(item)
                else:
                    item_removed = True # Mark as true after first removal
        else:
            # Fallback: Assume it's a list of simple product IDs (integers)
            # We filter this list to build a new one without the target product_id
            
            # Ensure product_id_int is valid for comparison
            if product_id_int is not None:
                for item_id in current_guest_wishlist:
                    if not (item_id == product_id_int and not item_removed):
                        updated_wishlist.append(item_id)
                    else:
                        item_removed = True
            else:
                # If product_id could not be converted to int, and wishlist is simple IDs
                # We can't reliably remove, so just keep all items.
                updated_wishlist = list(current_guest_wishlist)


        # Crucial step: Re-assign the new list to the session.
        # This explicitly tells Flask that the entire session entry has been changed.
        session['guest_wishlist'] = updated_wishlist
        
        # Explicitly mark the session as modified to ensure the cookie is updated.
        session.modified = True

        if item_removed:
            return jsonify({'success': True, 'message': 'Item removed from your guest wishlist.'})
        else:
            return jsonify({'success': False, 'message': 'Item not found in your guest wishlist.'}), 404


@app.route("/toggle-wishlist/<int:product_id>", methods=["POST"])
def toggle_wishlist(product_id):
    """
    Toggles a product's presence in the user's wishlist.
    For logged-in users, this updates the database.
    For guest users, it updates the session.
    """
    try:
        # 1. Validate the product ID
        product = Product.query.get(product_id)
        if not product:
            return jsonify(success=False, message="Product not found."), 404

        is_in_wishlist = False
        message = ""

        # 2. Logic for Logged-in Users
        if current_user.is_authenticated:
            wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product_id).first()
            if wishlist_item:
                # Item exists, so we remove it
                db.session.delete(wishlist_item)
                db.session.commit()
                is_in_wishlist = False
                message = "Product removed from your wishlist."
            else:
                # Item does not exist, so we add it
                new_wishlist_item = Wishlist(user_id=current_user.id, product_id=product_id)
                db.session.add(new_wishlist_item)
                db.session.commit()
                is_in_wishlist = True
                message = "Product added to your wishlist."

        # 3. Logic for Guest Users
        # 3. Logic for Guest Users (store as integers consistently)
        else:
           # normalize existing session list to ints
           guest_wishlist_ids_raw = session.get('guest_wishlist', [])
           guest_wishlist_ids = []
           for x in guest_wishlist_ids_raw:
              try:
                guest_wishlist_ids.append(int(x))
              except (TypeError, ValueError):
                 continue  # skip bad entries

           if product_id in guest_wishlist_ids:
               guest_wishlist_ids.remove(product_id)
               is_in_wishlist = False
               message = "Product removed from your guest wishlist."
           else:
              guest_wishlist_ids.append(product_id)
              is_in_wishlist = True
              message = "Product added to your guest wishlist."

           session['guest_wishlist'] = guest_wishlist_ids  # store ints
           session.modified = True


        return jsonify(in_wishlist=is_in_wishlist, success=True, message=message), 200

    except Exception as e:
        # A good practice to handle potential errors
        if current_user.is_authenticated and 'db' in globals() and db.session.is_active:
            if db.session.is_active:
              db.session.rollback()

        return jsonify(success=False, message=f"An unexpected server error occurred: {str(e)}"), 500
    
@app.route('/clear-recently-viewed', methods=['POST'])
def clear_recently_viewed():
    session.pop('recently_viewed', None)
    return redirect(url_for('home'))


@app.route('/api/product_variants/<int:product_id>', methods=['GET'])
def get_product_variants(product_id):
    try:
        product = Product.query.options(
            joinedload(Product.sizes),
            joinedload(Product.colors)
        ).get(product_id)

        if not product:
            current_app.logger.warning(f"Product with ID {product_id} not found when fetching variants.")
            return jsonify(message="Product not found"), 404

        if not hasattr(product, 'price') or product.price is None:
            current_app.logger.error(f"Product ID {product_id} is missing 'price' attribute.")
            return jsonify(message="Product price not available"), 500

        sizes = [{'id': size.id, 'name': size.name} for size in product.sizes] or [{'id': None, 'name': 'N/A'}]
        colors = [{'id': color.id, 'name': color.name} for color in product.colors] or [{'id': None, 'name': 'N/A'}]

        current_app.logger.debug(f"Fetched variants for Product ID {product_id}: Sizes={len(sizes)}, Colors={len(colors)}")

        return jsonify(
            product_id=product_id,
            product_price=product.price,
            sizes=sizes,
            colors=colors
        )
    except Exception as e:
        current_app.logger.error(f"Error in get_product_variants for product ID {product_id}: {e}", exc_info=True)
        return jsonify(message=f"An internal server error occurred: {str(e)}"), 500

    
    

@limiter.limit("5 per minute")
@app.route("/search")
def search():
    query = request.args.get("q", "").strip()

    if not query:
        flash("Please enter a search term.", "warning")
        return redirect(url_for("home"))

    # Create a list to hold all of our filter conditions
    # We will combine all of them with 'OR'
    conditions = []

    # Run the NLP parser to get structured filters (e.g., {'category': 'jeans'})
    filters = parse_query(query)

    # 1. Add NLP-based filters to the list.
    if 'category' in filters:
        conditions.append(Product.category.ilike(f"%{filters['category']}%"))
    if 'gender' in filters:
        conditions.append(Product.gender.ilike(f"%{filters['gender']}%"))
    if 'neck' in filters:
        conditions.append(Product.neck_type.ilike(f"%{filters['neck']}%"))
    if 'sleeve' in filters:
        conditions.append(Product.sleeve_type.ilike(f"%{filters['sleeve']}%"))
    if 'size' in filters:
        conditions.append(Product.sizes.ilike(f"%{filters['size']}%"))
    if 'price_max' in filters:
        conditions.append(Product.price <= filters['price_max'])

    # 2. Add the fuzzy search for the full query string to the list.
    # This is the core part that ensures a basic search always works.
    conditions.append(Product.name.ilike(f"%{query}%"))
    conditions.append(Product.category.ilike(f"%{query}%"))
    conditions.append(Product.tag.ilike(f"%{query}%"))
    
    # Check if there are any conditions to prevent a malformed query
    if not conditions:
        results = []
    else:
        # 3. Combine all conditions using the OR operator.
        # This will find any product that matches AT LEAST ONE of the conditions.
        products = Product.query.filter(or_(*conditions))
        results = products.all()

    return render_template("search_results.html", query=query, results=results)


@limiter.limit("5 per minute")
@app.route("/autocomplete")
def autocomplete():
    q = request.args.get("q", "")
    matches = Product.query.filter(Product.name.ilike(f"%{q}%")).limit(5).all()
    results = [{"id": p.id, "name": p.name} for p in matches]
    return jsonify(results)


@app.route('/saved-addresses')
@login_required
def saved_addresses():
    addresses = Address.query.filter_by(user_id=current_user.id).all()
    addresses_dict = [addr.to_dict() for addr in addresses]
    return render_template('saved_address.html', addresses=addresses_dict)



@app.route('/save_address', methods=['POST'])
@login_required
def save_address():
    required_fields = ['recipient_name', 'mobile', 'pincode', 'state', 'city', 'house_no']
    for field in required_fields:
        if not request.form.get(field):
            flash(f"{field.replace('_', ' ').title()} is required.", "error")
            return redirect(url_for('saved_addresses'))
        
    addr_id = request.form.get('id')
    if addr_id:
        address = Address.query.filter_by(id=addr_id, user_id=current_user.id).first()
        if not address:
            flash("Address not found.", "error")
            return redirect(url_for('saved_addresses'))
    else:
        address = Address(user_id=current_user.id)

    address.label = request.form.get('label', 'Home')  # default if not provided
    address.recipient_name = request.form.get('recipient_name')
    address.mobile = request.form.get('mobile')
    address.pincode = request.form.get('pincode')
    address.state = request.form.get('state')
    address.city = request.form.get('city')
    address.house_no = request.form.get('house_no')
    address.road = request.form.get('road')
    address.area = request.form.get('area')
    address.is_default = request.form.get('is_default') == 'on'

    db.session.add(address)
    db.session.commit()

    flash("Address saved successfully!", "success")
    return redirect(url_for('saved_addresses'))



@limiter.limit("5 per minute")
@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_mobile = request.form.get('mobile')

        current_user.username = new_username
        current_user.email = new_email
        current_user.mobile = new_mobile

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('edit_profile.html')

@app.route('/update_address', methods=['POST'])
@login_required
def update_address():
    user = current_user
    user.name = request.form.get('name')
    user.mobile = request.form.get('mobile')
    user.pincode = request.form.get('pincode')
    user.state = request.form.get('state')
    user.city = request.form.get('city')
    user.house_no = request.form.get('house_no')
    user.road = request.form.get('road')
    user.area = request.form.get('area')

    # Optionally combine into a full address string if you want
    user.address = f"{user.house_no}, {user.road}, {user.area}, {user.city}, {user.state} - {user.pincode}"

    db.session.commit()
    flash('Address updated successfully!', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/add_address', methods=['GET', 'POST'])
@login_required
def add_address():
    form = AddressForm()
    if form.validate_on_submit():
        new_address = Address(
            user_id=current_user.id,
            label=form.label.data,
            recipient_name=form.recipient_name.data,
            mobile=form.mobile.data,
            house_no=form.house_no.data,
            road=form.road.data,
            area=form.area.data,
            city=form.city.data,
            state=form.state.data,
            pincode=form.pincode.data,
            is_default=form.is_default.data
        )
        if new_address.is_default:
            for addr in current_user.addresses:
                if addr.is_default:
                    addr.is_default = False

        db.session.add(new_address)
        db.session.commit()
        flash('Address added successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('add_edit_address.html', form=form, title='Add New Address')

@app.route('/edit_address/<int:address_id>', methods=['GET', 'POST'])
@login_required
def edit_address(address_id):
    address = Address.query.get_or_404(address_id)
    if address.user_id != current_user.id:
        abort(403) 

    form = AddressForm(obj=address)
    if form.validate_on_submit():
        form.populate_obj(address)
        if address.is_default:
            for addr in current_user.addresses:
                if addr.id != address.id and addr.is_default:
                    addr.is_default = False
        db.session.commit()
        flash('Address updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('add_edit_address.html', form=form, title='Edit Address')

@app.route('/delete_address/<int:address_id>', methods=['POST'])
@login_required
def delete_address(address_id):
    address = Address.query.get_or_404(address_id)
    if address.user_id != current_user.id:
        abort(403)
    db.session.delete(address)
    db.session.commit()
    flash('Address deleted successfully!', 'success')
    return redirect(url_for('profile'))

@limiter.limit("5 per minute")
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    status_filter = request.args.get('status')  # get filter from query param

    if status_filter and status_filter != 'all':
        orders = Order.query.filter_by(status=status_filter).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.order_by(Order.created_at.desc()).all()

    products = Product.query.all()

    return render_template('admin/admin_dashboard.html', orders=orders, products=products, status_filter=status_filter)

@app.route('/admin/products')
@login_required
def admin_products():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    products = Product.query.all()
    return render_template('admin/products.html', products=products)


@app.route('/admin/product/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('You do not have permission to add products.', 'danger')
        return redirect(url_for('index'))

    form = ProductForm()

    all_sizes = Size.query.all()
    all_sizes_json = [{'id': size.id, 'name': size.name} for size in all_sizes]

    all_colors = Color.query.all()
    form.colors.choices = [(c.id, c.name) for c in all_colors]

    print("DEBUG: GET/POST method:", request.method)

    # ---------- Set size choices for FieldList subforms ----------
    for entry in form.sizes_and_quantities.entries:
        entry.form.size.choices = [(s.id, s.name) for s in all_sizes]

    # ---------- Auto-compute stock from quantities if POST ----------
    if request.method == 'POST':
        quantities = []
        for q in request.form.getlist('quantities[]'):
            try:
                quantities.append(int(q))
            except ValueError:
                quantities.append(0)
        form.stock.data = sum(quantities)
        print("DEBUG: Computed total stock from quantities:", form.stock.data)

        # Also set size choices again for newly appended entries (JS may add them)
        for entry in form.sizes_and_quantities.entries:
            entry.form.size.choices = [(s.id, s.name) for s in all_sizes]

    if form.validate_on_submit():
        print("DEBUG: Form validated successfully")
        print("DEBUG: Form data:", form.data)

        # --------- Handle Main Image ----------
        main_image_url = None
        if form.main_image.data:
            if allowed_file(form.main_image.data.filename):
                try:
                    print("DEBUG: Uploading main image...")
                    result = cloudinary.uploader.upload(
                        form.main_image.data,
                        folder=f'clothing/{str(uuid.uuid4())}',
                        resource_type='image'
                    )
                    main_image_url = result['secure_url']
                    print("DEBUG: Main image uploaded:", main_image_url)
                except Exception as e:
                    flash(f'Error uploading main image: {e}', 'danger')
                    print("DEBUG: Main image upload error:", e)
                    return render_template('admin/admin_product_form.html', form=form, title='Add New Product', ALL_SIZES=all_sizes_json)
            else:
                flash('Invalid main image file type. Allowed: png, jpg, jpeg, gif.', 'danger')
                print("DEBUG: Invalid main image type")
                return render_template('admin/admin_product_form.html', form=form, title='Add New Product', ALL_SIZES=all_sizes_json)

        # --------- Create Product ----------
        new_product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            category=form.category.data,
            tag=form.tag.data,
            stock=form.stock.data  # auto-computed
        )
        db.session.add(new_product)
        db.session.flush()  # ensures new_product.id exists
        print("DEBUG: Product created with ID:", new_product.id)

        # --------- Save Main Image ----------
        if main_image_url:
            product_image = ProductImage(
                image_url=main_image_url,
                is_main=True,
                product=new_product
            )
            db.session.add(product_image)
            print("DEBUG: Main image added to session")

        # --------- Save Additional Images ----------
        for field_entry in form.additional_images.entries:
            if field_entry.data and allowed_file(field_entry.data.filename):
                try:
                    print(f"DEBUG: Uploading additional image: {field_entry.data.filename}")
                    result = cloudinary.uploader.upload(
                        field_entry.data,
                        folder=f'clothing/{new_product.id}',
                        resource_type='image'
                    )
                    product_image = ProductImage(
                        image_url=result['secure_url'],
                        is_main=False,
                        product=new_product
                    )
                    db.session.add(product_image)
                    print(f"DEBUG: Additional image uploaded: {result['secure_url']}")
                except Exception as e:
                    flash(f'Warning: Could not upload additional image {field_entry.data.filename}: {e}', 'warning')
                    print("DEBUG: Additional image upload error:", e)
            elif field_entry.data:
                flash(f'Invalid file type for additional image: {field_entry.data.filename}. Allowed: png, jpg, jpeg, gif.', 'warning')
                print("DEBUG: Invalid additional image type:", field_entry.data.filename)

        # --------- Save Colors ----------
        for color_id in form.colors.data:
            try:
                color_obj = Color.query.get(int(color_id))
                if color_obj:
                    new_product.colors.append(color_obj)
                    print("DEBUG: Added color:", color_obj.name)
            except Exception as e:
                print("DEBUG: Error adding color:", e)

        # --------- Save Sizes + Quantities ----------
        for size_data in form.sizes_and_quantities.data:
            try:
                size_id = int(size_data.get('size') or 0)
                quantity = int(size_data.get('quantity') or 0)
            except Exception as e:
                print("DEBUG: Size/quantity conversion error:", e)
                continue

            if size_id and quantity > 0:
                size_obj = Size.query.get(size_id)
                if size_obj:
                    product_size = ProductSize(
                        product_id=new_product.id,
                        size_id=size_obj.id,
                        quantity=quantity
                    )
                    db.session.add(product_size)
                    print(f"DEBUG: Added size {size_obj.name} with quantity {quantity}")

        # --------- Commit ----------
        try:
            db.session.commit()
            flash(f'Product "{new_product.name}" added successfully!', 'success')
            print("DEBUG: Product committed successfully")
            return redirect(url_for('admin_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving product "{new_product.name}". Error: {e}', 'danger')
            print("DEBUG: Commit failed:", e)

    else:
        print("DEBUG: Form validation failed")
        print("DEBUG: Form errors:", form.errors)

    return render_template('admin/admin_product_form.html', form=form, title='Add New Product', ALL_SIZES=all_sizes_json)

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        flash('You do not have permission to edit products.', 'danger')
        return redirect(url_for('index'))

    product = Product.query.get_or_404(product_id)
    form = ProductForm()

    # ---------- Load sizes and colors ----------
    all_sizes = Size.query.order_by(Size.name).all()
    all_sizes_json = [{'id': s.id, 'name': s.name} for s in all_sizes]
    size_choices = [(s.id, s.name) for s in all_sizes]

    all_colors = Color.query.order_by(Color.name).all()
    color_choices = [(c.id, c.name) for c in all_colors]

    # Set WTForms choices
    form.colors.choices = color_choices
    for entry in form.sizes_and_quantities.entries:
        entry.form.size.choices = size_choices

    # ---------- Pre-fill form on GET ----------
    if request.method == 'GET':
        form.name.data = product.name
        form.price.data = product.price
        form.category.data = product.category
        form.tag.data = product.tag
        form.description.data = product.description
        form.colors.data = [c.id for c in product.colors]

        # Reset FieldList for sizes and quantities
        while form.sizes_and_quantities.entries:
            form.sizes_and_quantities.pop_entry()
        for ps in getattr(product, 'product_sizes', []):
            form.sizes_and_quantities.append_entry({'size': ps.size_id, 'quantity': ps.quantity})
            form.sizes_and_quantities.entries[-1].form.size.choices = size_choices
        if not form.sizes_and_quantities.entries:
            form.sizes_and_quantities.append_entry()
            form.sizes_and_quantities.entries[-1].form.size.choices = size_choices

    # ---------- Auto-compute stock from quantities on POST ----------
    if request.method == 'POST':
        quantities = []
        for q in request.form.getlist('quantities[]'):
            try:
                quantities.append(int(q))
            except ValueError:
                quantities.append(0)
        form.stock.data = sum(quantities)
        print("DEBUG: Computed total stock from quantities:", form.stock.data)

        # Ensure subform choices are set again for validation
        for entry in form.sizes_and_quantities.entries:
            entry.form.size.choices = size_choices

    if form.validate_on_submit():
        print("DEBUG: Form validated successfully")
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.category = form.category.data
        product.tag = form.tag.data
        product.stock = form.stock.data
        print(f"DEBUG: Product stock set to {product.stock}")

        # --------- Update Colors ----------
        product.colors.clear()
        for color_id in form.colors.data:
            try:
                color_obj = Color.query.get(int(color_id))
                if color_obj:
                    product.colors.append(color_obj)
                    print("DEBUG: Added color:", color_obj.name)
            except Exception as e:
                print("DEBUG: Error adding color:", e)

        # --------- Update Sizes ----------
        ProductSize.query.filter_by(product_id=product.id).delete()
        db.session.flush()
        for size_data in form.sizes_and_quantities.data:
            try:
                size_id = int(size_data.get('size') or 0)
                quantity = int(size_data.get('quantity') or 0)
            except Exception as e:
                print("DEBUG: Size/quantity conversion error:", e)
                continue

            if size_id and quantity > 0:
                size_obj = Size.query.get(size_id)
                if size_obj:
                    product_size = ProductSize(
                        product_id=product.id,
                        size_id=size_obj.id,
                        quantity=quantity
                    )
                    db.session.add(product_size)
                    print(f"DEBUG: Added size {size_obj.name} with quantity {quantity}")

        # --------- Handle Main Image ----------
        if form.main_image.data and allowed_file(form.main_image.data.filename):
            try:
                result = cloudinary.uploader.upload(
                    form.main_image.data,
                    folder=f'clothing/{product.id}',
                    resource_type='image'
                )
                main_image = ProductImage.query.filter_by(product_id=product.id, is_main=True).first()
                if main_image:
                    main_image.image_url = result['secure_url']
                else:
                    new_main_image = ProductImage(
                        product_id=product.id,
                        image_url=result['secure_url'],
                        is_main=True
                    )
                    db.session.add(new_main_image)
                print(f"DEBUG: Main image uploaded: {result['secure_url']}")
            except Exception as e:
                flash(f'Error uploading main image: {e}', 'danger')
                print("DEBUG: Main image upload error:", e)

        # --------- Handle Additional Images ----------
        for field_entry in form.additional_images.entries:
            if field_entry.data and allowed_file(field_entry.data.filename):
                try:
                    result = cloudinary.uploader.upload(
                        field_entry.data,
                        folder=f'clothing/{product.id}',
                        resource_type='image'
                    )
                    new_image = ProductImage(
                        product_id=product.id,
                        image_url=result['secure_url'],
                        is_main=False
                    )
                    db.session.add(new_image)
                    print(f"DEBUG: Additional image uploaded: {result['secure_url']}")
                except Exception as e:
                    flash(f'Warning: Could not upload additional image {field_entry.data.filename}: {e}', 'warning')
                    print("DEBUG: Additional image upload error:", e)
            elif field_entry.data:
                flash(f'Invalid file type for additional image: {field_entry.data.filename}. Allowed: png, jpg, jpeg, gif.', 'warning')
                print("DEBUG: Invalid additional image type:", field_entry.data.filename)

        # --------- Commit changes ----------
        try:
            db.session.commit()
            flash(f'Product "{product.name}" updated successfully!', 'success')
            print("DEBUG: Product committed successfully")
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving product "{product.name}". Error: {e}', 'danger')
            print("DEBUG: Commit failed:", e)

        return redirect(url_for('admin_products'))

    else:
        print("DEBUG: Form validation failed")
        print("DEBUG: Form errors:", form.errors)

    return render_template(
        'admin/admin_product_form.html',
        form=form,
        title=f'Edit {product.name}',
        product=product,
        ALL_SIZES=all_sizes_json
    )




@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete products.', 'danger')
        return redirect(url_for('index'))

    product = Product.query.get_or_404(product_id)

    try:
        # Delete associated image files from disk
        for image_record in product.images:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], image_record.image_url)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as e:
                    flash(f'Error deleting image file {image_record.image_url} for product {product.name}: {e}', 'warning')

        db.session.delete(product) # Deleting product will also cascade-delete ProductImage records
        db.session.commit()
        flash(f'Product "{product.name}" and its images have been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product "{product.name}": {e}', 'danger')

    return redirect(url_for('admin_products'))



@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        escaped_filename = escape(filename)
        return f'File uploaded successfully! <br><img src="/static/images/{escaped_filename}">'
    return 'Upload failed', 500
   


@app.route("/upload_profile_pic", methods=["POST"])
@login_required
def upload_profile_pic():
    file = request.files['profile_pic']
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.root_path, 'static/profile_pics', filename)
        file.save(filepath)
        current_user.profile_pic = filename
        db.session.commit()
        flash("Profile picture updated successfully!", "success")
    return redirect(url_for("user_dashboard"))

@limiter.limit("5 per minute")
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")

        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "danger")
        else:
            current_user.set_password(new)
            db.session.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for("user_dashboard"))

    return render_template("change_password.html")




@app.route('/cancel_order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = Order.query.get_or_404(order_id)

    # Make sure the order belongs to the user
    if order.user_id != current_user.id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard'))

    # Optional: Prevent cancelling already-cancelled/delivered
    if order.status in ['shipped', 'delivered', 'cancelled']:
        flash("Order cannot be cancelled.", "warning")
        return redirect(url_for('orders', order_id=order_id))

    # Set status and save
    order.status = 'Cancelled'
    db.session.commit()

    flash("Order cancelled successfully.", "success")
    return redirect(url_for('orders', order_id=order.id))



@app.route('/invoice/<int:order_id>')
def generate_invoice(order_id):
    order = Order.query.get_or_404(order_id)

    # 1. Define the company_details dictionary (as before)
    company_details = {
        'name': "PRAUXE FASHIONS PVT LTD", # Your actual company name
        'address_line1': "Your Company Building No., Street Name",
        'address_line2': "Your Company Locality, Area",
        'city': "Your City",
        'state': "Your State",
        'pincode': "XXXXXX",
        'gstin': "YourGSTIN",
        'pan': "YourPAN",
        'cin': "U00000HR0000PTC000000",
        'regd_office': "Your Company Registered Office Full Address",
        'contact_entity': "PRAUXE Support",
        'contact_phone': "0000000000 | 1111111111",
        'website': "www.yourwebsite.com/helpcentre"
    }

    # --- Address Mapping (Crucial for fixing AttributeError) ---
    # Create a pseudo-object (dictionary) for shipping_address from the order fields
    order.shipping_address = {
        'name': order.order_name if order.order_name else (current_user.name if current_user.is_authenticated else 'Guest'),
        'house_no': order.order_house_no if order.order_house_no else '',
        'road': order.order_road if order.order_road else '',
        'area': order.order_area if order.order_area else '',
        'city': order.order_city if order.order_city else '',
        'pincode': order.order_pincode if order.order_pincode else '',
        'state': order.order_state if order.order_state else '',
        'phone': order.order_mobile if order.order_mobile else (current_user.mobile if current_user.is_authenticated else '')
    }

    # For billing_address, since the Order model doesn't have separate fields,
    # we'll use current_user's address as a fallback/default for billing.
    # You might want to store separate billing addresses in your DB in the future.
    order.billing_address = {
        'name': current_user.name if current_user.is_authenticated else 'Guest',
        'house_no': current_user.house_no if current_user.is_authenticated and hasattr(current_user, 'house_no') else '',
        'road': current_user.road if current_user.is_authenticated and hasattr(current_user, 'road') else '',
        'area': current_user.area if current_user.is_authenticated and hasattr(current_user, 'area') else '',
        'city': current_user.city if current_user.is_authenticated and hasattr(current_user, 'city') else '',
        'pincode': current_user.pincode if current_user.is_authenticated and hasattr(current_user, 'pincode') else '',
        'state': current_user.state if current_user.is_authenticated and hasattr(current_user, 'state') else '',
        'phone': current_user.mobile if current_user.is_authenticated and hasattr(current_user, 'mobile') else ''
    }


    # 2. Populate order details with calculated totals and specific invoice fields
    order.invoice_number = "INV" + str(order.id).zfill(10)
    order.invoice_date = order.created_at # Assuming created_at can serve as invoice_date if not separate

    # Calculate total items count
    order.total_items_count = sum(item.quantity for item in order.items)

    # Dummy shipping charges (replace with actual logic/fields from Order model)
    order.shipping_gross_amount = getattr(order, 'shipping_gross_amount', 70.00) # Assuming this would be a field on Order
    order.shipping_discount = getattr(order, 'shipping_discount', 70.00)
    order.shipping_taxable_value = getattr(order, 'shipping_taxable_value', 0.00)
    order.shipping_sgst = getattr(order, 'shipping_sgst', 0.00)
    order.shipping_cgst = getattr(order, 'shipping_cgst', 0.00)
    order.shipping_total = getattr(order, 'shipping_total', 0.00)


    total_gross_amount = 0.0
    total_discounts = 0.0
    total_taxable_value = 0.0
    total_sgst = 0.0
    total_cgst = 0.0
    final_total = 0.0

    # Ensure each item in order.items has the necessary attributes
    for item in order.items:
        # Product details like FSN, HSN/SAC, Warranty, Price, Tax percentages
        # Ideally, these come from a linked Product model (item.product)
        # For now, using getattr with dummy defaults or calculations
        item.fsn = getattr(item, 'fsn', 'FSNXXXX')
        item.hsn_sac = getattr(item, 'hsn_sac', '91021100')
        item.warranty = getattr(item, 'warranty', '2 years warranty for Manufacturing defects')

        # Use 9.0% as a default for SGST/CGST if not explicitly defined on item or product
        item.sgst_percent = getattr(item, 'sgst_percent', 9.0)
        item.cgst_percent = getattr(item, 'cgst_percent', 9.0)

        # Calculations
        item.gross_amount = float(item.price_at_purchase * item.quantity)
        item.discount_amount = float(getattr(item, 'discount_amount', 0.0)) # Needs to be stored on OrderItem or calculated
        item.taxable_value = float(item.gross_amount - item.discount_amount)
        item.sgst_amount = float(item.taxable_value * (item.sgst_percent / 100))
        item.cgst_amount = float(item.taxable_value * (item.cgst_percent / 100))
        item.total_amount = float(item.taxable_value + item.sgst_amount + item.cgst_amount)

        total_gross_amount += item.gross_amount
        total_discounts += item.discount_amount
        total_taxable_value += item.taxable_value
        total_sgst += item.sgst_amount
        total_cgst += item.cgst_amount
        final_total += item.total_amount

    # Add shipping totals to overall totals
    total_gross_amount += order.shipping_gross_amount
    total_discounts += order.shipping_discount
    total_taxable_value += order.shipping_taxable_value
    total_sgst += order.shipping_sgst
    total_cgst += order.shipping_cgst
    final_total += order.shipping_total

    order.total_gross_amount = total_gross_amount
    order.total_discounts = total_discounts
    order.total_taxable_value = total_taxable_value
    order.total_sgst = total_sgst
    order.total_cgst = total_cgst
    order.final_total = final_total

    # 4. Pass company_details and order (with all its enhanced attributes) to the template
    return render_template('invoice_template.html', order=order, company_details=company_details)


@app.route('/track-order/<int:order_db_id>')
@login_required
def track_order(order_db_id): # This parameter is now an integer
    # Query using the database's primary key 'id'
    order = Order.query.filter_by(id=order_db_id, user_id=current_user.id).first_or_404()

    print(f"DEBUG: track_order route - Successfully fetched Order for DB ID: {order_db_id}")
    print(f"DEBUG: Order (Razorpay ID): {order.order_id}, Status: {order.status}, Total: {order.amount}")

    return render_template("track_order.html", order=order)

@app.route('/contact-us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/return-policy')
def return_policy():
    return render_template('return_policy.html')

@app.route('/about-us')
def about_us():
    return render_template('about.html')

@app.route('/careers')
def careers():
    return render_template('careers.html')

@app.route('/stores')
def stores():
    return render_template('stores.html')

@app.route("/privacy_policy")
def privacy_policy():
    return render_template('privacy_policy.html')

# In app.py
# ... (your existing imports and app setup) ...

@app.route("/faq")
def faq():
    """
    Renders the Frequently Asked Questions (FAQ) HTML page.
    """
    return render_template('faq.html')



@app.route("/terms")
def terms_conditions():
    """
    Renders the Terms and Conditions HTML page.
    """
    return render_template('terms_conditions.html')


@app.route('/set_region', methods=['POST'])
def set_region():
    currency = request.form.get('currency')
    if currency:
        session['currency'] = currency
        session['region_set'] = True

    next_url = request.form.get('next')
    return safe_redirect(next_url, fallback='index')


@app.route('/continue_india', methods=['POST'])
def continue_india():
    session['currency'] = 'INR'
    session['region_set'] = True

    return safe_redirect(request.referrer, fallback='home')




@app.route('/check_pincode_serviceability', methods=['POST'])
def check_pincode_serviceability():
    print("\n--- Incoming Pincode Check Request ---")
    
    pincode = None
    if request.is_json:
        data = request.get_json()
        pincode = data.get('pincode')
        print(f"Request is JSON. Pincode: '{pincode}'")
    else:
        pincode = request.form.get('pincode')
        print(f"Request is FORM data. Pincode: '{pincode}'")

    print(f"Received Pincode: '{pincode}' (Type: {type(pincode)})")
    print("--------------------------------------\n")

    if not pincode or not isinstance(pincode, str) or not pincode.isdigit() or len(pincode) != 6:
        print(f"DEBUG: Backend Pincode validation failed for '{pincode}'")
        return jsonify({
            "success": False,
            "serviceable": False,
            "message": "Invalid pincode format."
        }), 400

    if not DELHIVERY_API_TOKEN or DELHIVERY_API_TOKEN == "YOUR_DELHIVERY_API_KEY_HERE":
        print("DEBUG: DELHIVERY_API_TOKEN environment variable is not set or is default!")
        return jsonify({"success": False, "message": "Server error: Delhivery API token missing or invalid."}), 500

    try:
        params = {
            'token': DELHIVERY_API_TOKEN,
            'filter_codes': pincode
        }
        
        response = requests.get(DELHIVERY_API_BASE_URL, params=params)
        
        print("\n--- Delhivery API Response Status Code ---")
        print(response.status_code)
        print("\n--- Delhivery API Response Content (Raw) ---")
        print(response.text)
        print("-------------------------------------------\n")

        response.raise_for_status()
        
        delhivery_data = response.json()
        
        is_serviceable = False
        message_for_frontend = ""
        delivery_time = None 

        if delhivery_data and 'delivery_codes' in delhivery_data and isinstance(delhivery_data['delivery_codes'], list):
            found_pincode_in_delhivery_response = False
            for code_info in delhivery_data['delivery_codes']:
                # MODIFIED: Access 'postal_code' dictionary and then 'pin'
                if isinstance(code_info, dict) and 'postal_code' in code_info and isinstance(code_info['postal_code'], dict):
                    postal_code_data = code_info['postal_code']
                    # Ensure 'pin' matches the requested pincode
                    if str(postal_code_data.get('pin')) == pincode:
                        found_pincode_in_delhivery_response = True
                        # Check 'pre_paid' and 'cash' from 'postal_code_data'
                        if postal_code_data.get('pre_paid') == 'Y' or postal_code_data.get('cash') == 'Y':
                            is_serviceable = True
                            # Delhivery API response doesn't directly provide transit_time in this structure
                            # You might need to look for it elsewhere in their docs or provide a default.
                            # For now, we'll keep it None unless you find it.
                            delivery_time = None # Set this based on actual Delhivery API if available
                            print(f"DEBUG: Pincode {pincode} is SERVICEABLE via 'postal_code.pin'.")
                            message_for_frontend = ""
                            break
                        else:
                            is_serviceable = False 
                            print(f"DEBUG: Pincode {pincode} found but NOT serviceable for prepaid/cash (via 'postal_code.pin').")
                            message_for_frontend = "Currently not serviceable, will come to you soon!"
                            break
            
            if not found_pincode_in_delhivery_response:
                is_serviceable = False
                message_for_frontend = f"Pincode {pincode} data not found in service areas."
                print(f"DEBUG: Pincode {pincode} not found in Delhivery's 'delivery_codes' list or internal 'postal_code'.")

        else:
            is_serviceable = False
            message_for_frontend = "Could not retrieve service data from Delhivery. Please try again."
            print(f"DEBUG: Delhivery response structure unexpected or empty: {delhivery_data}")

        print(f"DEBUG: Final response to frontend - Serviceable: {is_serviceable}, Message: '{message_for_frontend}', Delivery Time: {delivery_time}")
        return jsonify({
            "success": True, 
            "serviceable": is_serviceable,
            "message": message_for_frontend,
            "delivery_time": delivery_time
        }), 200

    except requests.exceptions.HTTPError as err:
        print(f"HTTP error during Delhivery API call: {err.response.status_code} - {err.response.text}")
        return jsonify({"success": False, "message": f"Delhivery API error: {err.response.status_code}"}), 500
    except requests.exceptions.ConnectionError as err:
        print(f"Connection error with Delhivery API: {err}")
        return jsonify({"success": False, "message": "Network error connecting to delivery service."}), 503
    except requests.exceptions.Timeout as err:
        print(f"Timeout error with Delhivery API: {err}")
        return jsonify({"success": False, "message": "Delhivery API request timed out."}), 504
    except ValueError as e:
        print(f"JSON decoding error from Delhivery API: {e}")
        print(f"Delhivery raw response that caused error: {response.text}")
        return jsonify({"success": False, "message": "Received unparseable response from Delhivery API."}), 500
    except Exception as e:
        print(f"An unhandled server error occurred in Delhivery call: {e}")
        return jsonify({"success": False, "message": "An internal server error occurred."}), 500


@app.route('/webhook', methods=['POST'])
@csrf.exempt
def whatsapp_webhook():
    data = request.json
    print("DEBUG: Incoming webhook data:", data)
    payload = data.get("data", {})
    from_me = payload.get("fromMe", False)
    if from_me:
        print("DEBUG: Ignoring own message")
        return jsonify({"status": "ignored"}), 200
    sender_raw = payload.get("from")  # e.g. '917011487072@c.us'
    message = payload.get("body", "").strip().lower()

    if sender_raw and "@c.us" in sender_raw:
      sender = "+" + sender_raw.split("@")[0]
    else:
      sender = None

    print(f"DEBUG: sender={sender}, message={message}")
    if not sender or not message:
        print("DEBUG: Missing sender or message")
        return jsonify({"status": "ignored"}), 200

    reply = ""

    if message == "catalog":
         print("DEBUG: catalog command")

         products = Product.query.limit(5).all()
         product_list = []
         print(f"Found {len(products)} products")
         for product in products:
             try:
                if product.images and len(product.images) > 0:
                   image_url = url_for('static', filename='uploads/' + product.images[0].image_url, _external=True)
                else:
                   image_url = url_for('static', filename='uploads/default.jpg', _external=True)

                product_dict = {
                "name": product.name,
                "price": product.price,
                "image_url": image_url,
                "url": f"https://5bd5b4f3042d.ngrok-free.app/product/{product.id}"
            }

                product_list.append(product_dict)

             except Exception as e:
                 print(f"Error processing product ID {product.id}: {e}")
                 continue  # Skip this product and move to the next

         send_product_catalog(sender, product_list)
         return jsonify({"status": "catalog sent"}), 200

    elif message.startswith("add"):
        print("DEBUG: add command")
        try:
            product_id = int(message.replace("add", "").strip())
            product = Product.query.get(product_id)
            if product:
                existing = WhatsAppCart.query.filter_by(phone_number=sender, product_id=product_id).first()
                if existing:
                    existing.quantity += 1
                else:
                    db.session.add(WhatsAppCart(phone_number=sender, product_id=product_id, quantity=1))
                db.session.commit()
                reply = f"✅ Added *{product.name}* to your cart."
            else:
                reply = "❌ Product not found."
        except ValueError:
            reply = "❌ Invalid format. Use *add 1* to add product ID 1 to cart."

    elif message == "cart":
        cart_items = WhatsAppCart.query.filter_by(phone_number=sender).all()
        if cart_items:
            reply = "🛒 Your Cart:\n"
            total = 0
            for item in cart_items:
                line = f"{item.product.name} x {item.quantity} = ₹{item.product.price * item.quantity}\n"
                reply += line
                total += item.product.price * item.quantity
            reply += f"\n💰 Total: ₹{total}\nType *checkout* to place order."
        else:
            reply = "🛒 Your cart is empty. Type *add <product_id>* to add items."

    elif message == "checkout":
        cart_items = WhatsAppCart.query.filter_by(phone_number=sender).all()
        if not cart_items:
            reply = "🛒 Your cart is empty. Add something first."
        else:
            total = sum(item.product.price * item.quantity for item in cart_items)
            order = Order(
                order_id=f"WSPRAUXE{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                amount=total,
                status="pending",
                order_name="WhatsApp Customer",
                order_mobile=sender.replace("+91", "").strip(),
                delivery_address="To be confirmed",
                shipping_method="WhatsApp"
            )
            db.session.add(order)
            db.session.flush()  # Get order.id without committing

            for item in cart_items:
                db.session.add(OrderItem(
                    order_id=order.id,
                    product_id=item.product_id,
                    name=item.product.name,
                    quantity=item.quantity,
                    price_at_purchase=item.product.price,
                    size_name="-",
                    color_name="-"
                ))
            WhatsAppCart.query.filter_by(phone_number=sender).delete()
            db.session.commit()

            reply = (
                f"✅ Your order (ID: *{order.order_id}*) has been placed for ₹{total}.\n"
                "We’ll contact you for delivery details."
            )
            send_whatsapp_message(sender, reply)
            send_whatsapp_invoice(order)

    elif message.startswith("track "):
        order_id = message.split("track ")[1].strip()
        order = Order.query.filter_by(order_id=order_id).first()
        if order:
            reply = (
                f"📦 Order Update for {order.order_id}:\n"
                f"Status: {order.status}\n"
                f"Shipping Method: {order.shipping_method}\n"
                f"Delivery Address: {order.delivery_address}\n"
                f"Thank you for shopping with Prauxe!"
            )
        else:
            reply = "❌ Sorry, we could not find any order with that ID. Please check and try again."

    else:
        reply = (
            "👋 Welcome to *Prauxe WhatsApp Shop*!\n\n"
            "Commands:\n"
            "- *catalog*: View products\n"
            "- *add <product_id>*: Add product to cart\n"
            "- *cart*: View cart\n"
            "- *checkout*: Place your order\n"
            "- *track <order_id>*: Track your order status"
        )

    send_whatsapp_message(sender, reply)
    return jsonify({"status": "ok"})

@app.route('/send-confirmation/<user_email>')
def send_confirmation(user_email):
    msg = Message(
        subject="Thank you for your order!",
        recipients=[user_email],
        body="""
        Dear Customer,

        Thank you for placing your order with us. We are processing it and will update you shortly!

        Best regards,  
        Your Clothing Brand Team
        """
    )
    mail.send(msg)
    return "Email sent!"




@app.route("/chat", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def chat():
    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    try:
        start_time = time.time()

        response = client.chat.completions.create(
          model="gpt-4o-mini",
          messages=[
             {"role": "system", "content": "You are a helpful assistant."},
             {"role": "user", "content": user_message}
          ]
        )


        duration = time.time() - start_time
        reply = response.choices[0].message.content

        prompt_tokens = response.usage.prompt_tokens
        completion_tokens = response.usage.completion_tokens
        total_tokens = response.usage.total_tokens

        usage = GPTUsage(
            user_id=current_user.id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            duration=duration,
            message=user_message,
            response=reply
        )
        db.session.add(usage)
        db.session.commit()

        return jsonify({"reply": reply})

    except Exception as e:
        import traceback
        print("🔴 GPT Error:", e)
        traceback.print_exc()
        return jsonify({"error": "Something went wrong. Try again later."}), 500



@app.route("/chatgpt")
def chatgpt():
    return render_template("chat.html", csrf_token=(generate_csrf() if current_user.is_authenticated else ""))


@limiter.limit("10 per minute")
@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    user_message = data.get("message", "").lower()

    # Predefined flows
    if "track" in user_message:
        prompt = "User wants to track an order. Ask for the order ID politely and guide them."
    elif "cancel" in user_message:
        prompt = "User wants to cancel their order. Ask for the order number and explain cancellation policy briefly."
    elif "refund" in user_message:
        prompt = "User is asking for refund status. Ask for order ID and inform about refund timeline."
    elif "faq" in user_message or "help" in user_message:
        prompt = "List 3 most common FAQs for an online clothing store (order tracking, return policy, delivery time)."
    else:
        prompt = "You are a customer support bot. Reply in short, polite messages and ask how you can assist."

    # Call GPT
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful support assistant for an online store."},
                {"role": "user", "content": prompt}
            ]
        )
        reply = response.choices[0].message.content.strip()
    except Exception:
        reply = "Sorry, I'm having trouble right now. Please try again later."

    return jsonify({"reply": reply})


@app.route('/api/user/orders')
@login_required
def get_user_orders():
    limit = int(request.args.get('limit', 3))
    offset = int(request.args.get('offset', 0))
    user_id = current_user.id

    orders = (
        Order.query.filter_by(user_id=user_id)
        .order_by(Order.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    
    orders_data = [{
        'order_id': order.id,
        'date': order.created_at.strftime('%Y-%m-%d'),
        'status': order.status
    } for order in orders]
    
    return jsonify(orders=orders_data)

@app.route('/deals')
def personalized_deals():
    user = current_user if current_user.is_authenticated else None
    products = Product.query.all()
    personalized = []

    for product in products:
        price = get_dynamic_price(product, user)
        if price < product.price:
            personalized.append((product, price))

    return render_template('deals.html', deals=personalized)



@app.route('/submit-review', methods=['POST'])
def submit_review():
    review_text = request.form['review']
    
    if is_spam_message(review_text):
        flash("Your message was flagged as spam.", "danger")
        return redirect(url_for('product_page'))

    # Save to database
    new_review = Review(user_id=current_user.id, text=review_text)
    db.session.add(new_review)
    db.session.commit()

    flash("Review submitted!", "success")
    return redirect(url_for('product_page'))



@app.route('/subscribe_newsletter', methods=['POST'])
def subscribe_newsletter():
    email = request.form.get('email')

    if not email:
        return jsonify(success=False, message="Email address is required."), 400

    # Basic email format validation
    if not re.fullmatch(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify(success=False, message="Please enter a valid email address."), 400

    # Check if email already exists
    existing_subscriber = NewsletterSubscriber.query.filter_by(email=email).first()
    if existing_subscriber:
        return jsonify(success=False, message="This email is already subscribed!"), 409 # 409 Conflict

    try:
        new_subscriber = NewsletterSubscriber(email=email)
        db.session.add(new_subscriber)
        db.session.commit()
        return jsonify(success=True, message="Thank you for subscribing to our newsletter!"), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error subscribing newsletter: {e}")
        return jsonify(success=False, message="An error occurred. Please try again later."), 500
#____________________________________________________________________________________________________#
# Dummy product seeding


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com https://www.googletagmanager.com https://www.clarity.ms https://cdn.jsdelivr.net https://cdn.plot.ly; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://www.googletagmanager.com; "
    )
    return response


if __name__ == '__main__':
    with app.app_context():
        seed_initial_data()
        migrate_main_images_to_cloudinary() 
    # file deepcode ignore RunWithDebugTrue: <please specify a reason of ignoring this>
    app.run(host='0.0.0.0', port=5000, debug=True)
