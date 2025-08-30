from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app, url_for
from extensions import db
import json


product_sizes = db.Table('product_sizes',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    db.Column('size_id', db.Integer, db.ForeignKey('size.id'), primary_key=True)
)

product_colors = db.Table('product_colors',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    db.Column('color_id', db.Integer, db.ForeignKey('color.id'), primary_key=True)
)

# ---------------- MODELS ----------------

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    gender = db.Column(db.String(10))
    is_admin = db.Column(db.Boolean, default=False)
    profile_pic = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(100))
    pincode = db.Column(db.String(10))
    state = db.Column(db.String(50))
    city = db.Column(db.String(50))
    house_no = db.Column(db.String(50))
    road = db.Column(db.String(100))
    area = db.Column(db.String(100))
    address = db.Column(db.String(255))
    role = db.Column(db.String(10), default='user')
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    segment = db.Column(db.Integer) 
    orders = db.relationship('Order', back_populates='user', lazy=True)
    wishlist_items = db.relationship("Wishlist", backref="user", lazy=True)
    cart = db.relationship('Cart', backref='user', uselist=False, cascade="all, delete-orphan")
    reviews = db.relationship('Review', backref='author', lazy=True)
    addresses = db.relationship('Address', back_populates='user', lazy=True, cascade="all, delete-orphan")
    otp_code = db.Column(db.String(6), nullable=True) # OTP can be null if not in use
    otp_expiry = db.Column(db.DateTime(timezone=True), nullable=True) # Expiry can be null

    def set_password(self, password):
        if not password:
            raise ValueError("Password cannot be empty or None.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    tag = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    stock = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    popularity = db.Column(db.Integer, default=0) 
    quantity = db.Column(db.Integer, default=0)
    discount = db.Column(db.Float, default=0.0)
    neck_type = db.Column(db.String(20))
    sleeve_type = db.Column(db.String(20))
    gender = db.Column(db.String(20))
    shipping_method = db.Column(db.String(50), nullable=False, default="Standard Shipping")
    
    images = db.relationship('ProductImage', backref='product', lazy=True, cascade='all, delete-orphan')
    sizes = db.relationship('Size', secondary=product_sizes, backref=db.backref('products_sized', lazy='dynamic'))
    price_rules = db.relationship('PriceRule', backref='product', lazy=True)
    reviews = db.relationship('Review', backref='product', lazy=True, cascade="all, delete-orphan")
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    cart_items = db.relationship('CartItem', backref='product', lazy=True, cascade="all, delete-orphan")
    colors = db.relationship(
        'Color',
        secondary=product_colors,
        backref=db.backref('products_colored', lazy='dynamic')
    )
    
    def __repr__(self):
        return f'<Product {self.name} Popularity: {self.popularity}>'
        
    def increment_popularity(self):
        self.popularity += 1
        db.session.commit()
    
    @property
    def main_image_url(self):
        main_img = next((img for img in self.images if img.is_main), None)
        if main_img and main_img.image_url:
           if main_img.image_url.startswith('http://') or main_img.image_url.startswith('https://'):
              return main_img.image_url
           else:
              return url_for('static', filename='uploads/' + main_img.image_url)
        return url_for('static', filename='placeholder.png')

    
    @property
    def final_price(self):
        if self.discount:
            return self.price * (1 - self.discount / 100)
        return self.price

class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(500), nullable=False) # Stores the filename or path relative to static/uploads
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    is_main = db.Column(db.Boolean, default=False) # Optional: Mark one image as main/featured

    def __repr__(self):
        return f'<ProductImage {self.image_url}>'

class Size(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False) # e.g., "S", "M", "L", "XL"

    def __repr__(self):
        return f'<Size {self.name}>'

class ProductSize(db.Model):
    __tablename__ = 'product_size'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    size_id = db.Column(db.Integer, db.ForeignKey('size.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0, nullable=False)

    # Relationships
    product = db.relationship('Product', backref=db.backref('product_sizes', cascade="all, delete-orphan"))
    size = db.relationship('Size')

    __table_args__ = (db.UniqueConstraint('product_id', 'size_id', name='_product_size_uc'),)

class Color(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False) # e.g., "Red", "Blue", "Black"
    hex_code = db.Column(db.String(7), nullable=True) # e.g., "#FF0000"

    def __repr__(self):
        return f'<Color {self.name}>'

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    items = db.relationship('CartItem', backref='cart', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Cart {self.id} for User {self.user_id}>'

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    size_name = db.Column(db.String(20), nullable=True) # Store name directly for simplicity
    color_name = db.Column(db.String(50), nullable=True) # Store name directly for simplicity

    def __repr__(self):
        return f'<CartItem {self.id}: Product {self.product_id}, Qty {self.quantity}, Size {self.size_name}, Color {self.color_name}>'

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    size_name = db.Column(db.String(20), nullable=True)
    color_name = db.Column(db.String(50), nullable=True)
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    product = db.relationship('Product', backref='wishlist_items')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'product_id', 'size_name', 'color_name', name='_user_product_variant_uc'),
    )

    def __repr__(self):
        return f"<Wishlist {self.id}: User {self.user_id}, Product {self.product_id}>"

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_order_user'), nullable=True)
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    payment_id = db.Column(db.String(100), unique=True, nullable=True)
    signature = db.Column(db.String(200), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    delivery_address = db.Column(db.Text, nullable=True)
    email = db.Column(db.String(150), nullable=True)
    expected_delivery_date = db.Column(db.DateTime)
    order_number = db.Column(db.String(32), unique=True, index=True)
    razorpay_order_id = db.Column(db.String(100), unique=True, nullable=True, index=True)
    payment_method = db.Column(db.String(20), default='ONLINE')
    order_name = db.Column(db.String(100), nullable=True)
    order_mobile = db.Column(db.String(15), nullable=True)
    order_pincode = db.Column(db.String(10), nullable=True)
    order_state = db.Column(db.String(50), nullable=True)
    order_city = db.Column(db.String(50), nullable=True)
    order_house_no = db.Column(db.String(100), nullable=True)
    order_road = db.Column(db.String(100), nullable=True)
    order_area = db.Column(db.String(100), nullable=True)
    shipping_method = db.Column(db.String(100), nullable=True) 
    user = db.relationship('User', back_populates='orders', foreign_keys=[user_id])

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False)
    size_name = db.Column(db.String(20), nullable=True)
    color_name = db.Column(db.String(50), nullable=True)
    
    order = db.relationship('Order', backref=db.backref('items', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f'<OrderItem {self.id}: Order {self.order_id}, Product {self.product_id}, Qty {self.quantity}>'

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False) # 1 to 5 stars
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('product_id', 'user_id', name='_product_user_review_uc'),)

class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    label = db.Column(db.String(50), nullable=True)
    recipient_name = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    house_no = db.Column(db.String(50), nullable=False)
    road = db.Column(db.String(100), nullable=False)
    area = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='addresses')
    User.addresses = db.relationship('Address', back_populates='user', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'label': self.label,
            'recipient_name': self.recipient_name,
            'mobile': self.mobile,
            'pincode': self.pincode,
            'state': self.state,
            'city': self.city,
            'house_no': self.house_no,
            'road': self.road,
            'area': self.area,
            'is_default': self.is_default,
            # add other fields you want exposed
        }

class Setting(db.Model):
    """
    Database model for storing application settings as key-value pairs.
    These settings can be managed by an admin user.
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True) # Use Text for potentially longer values

    def __repr__(self):
        return f"<Setting '{self.key}': '{self.value}'>"

    # --- Optional: Class methods for easy access ---

    @classmethod
    def get_setting(cls, key, default=None):
        """Retrieves a setting's value by its key."""
        setting = cls.query.filter_by(key=key).first()
        return setting.value if setting else default

    @classmethod
    def set_setting(cls, key, value):
        """Sets or updates a setting's value."""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = str(value) # Ensure value is stored as string
        else:
            setting = cls(key=key, value=str(value))
            db.session.add(setting)
        db.session.commit()
        return setting

class WhatsAppCart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(15), nullable=False)  # e.g., +919999999999
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

    product = db.relationship('Product')

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    event_type = db.Column(db.String(50))  # e.g., 'view', 'cart', 'purchase'
    activity_type = db.Column(db.String(50)) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100))
    site_tagline = db.Column(db.String(150))
    contact_email = db.Column(db.String(100))
    support_phone = db.Column(db.String(20))
    facebook_url = db.Column(db.String(255))
    instagram_url = db.Column(db.String(255))
    twitter_url = db.Column(db.String(255))
    linkedin_url = db.Column(db.String(255))
    footer_about = db.Column(db.Text)
    footer_links = db.Column(db.Text)  # JSON string or plain HTML
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    logo_path = db.Column(db.String(200))
    favicon_path = db.Column(db.String(200))
    
    google_analytics_id = db.Column(db.String(100))
    microsoft_clarity_id = db.Column(db.String(100))
    
    meta_title = db.Column(db.String(150))
    meta_description = db.Column(db.Text)
    meta_keywords = db.Column(db.Text)
    enable_razorpay = db.Column(db.Boolean, default=True)
    enable_cod = db.Column(db.Boolean, default=True)
    maintenance_mode = db.Column(db.Boolean, default=False)
    # Theme-related fields
    primary_color = db.Column(db.String(20), default="#e91e63")
    background_color = db.Column(db.String(20), default="#ffffff")
    font_family = db.Column(db.String(100), default="'Inter', sans-serif")
    custom_css_file = db.Column(db.String(255))  # optional

    @staticmethod
    def get():
        settings = SiteSettings.query.first()
        if not settings:
            settings = SiteSettings()
            db.session.add(settings)
            db.session.commit()
        return settings

class Banner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(200), nullable=False)
    heading = db.Column(db.String(100))
    subheading = db.Column(db.String(200))
    link = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='user_logs')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    admin = db.relationship('User', backref='activity_logs')

class ThemeSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    theme_name = db.Column(db.String(50))
    primary_color = db.Column(db.String(20))
    background_color = db.Column(db.String(20))
    font_family = db.Column(db.String(50))
    is_dark_mode = db.Column(db.Boolean, default=False)



class GPTUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prompt_tokens = db.Column(db.Integer)
    completion_tokens = db.Column(db.Integer)
    total_tokens = db.Column(db.Integer)
    duration = db.Column(db.Float)
    message = db.Column(db.Text)  # optional: store user message
    response = db.Column(db.Text)  # optional: store GPT response
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='gpt_usages')

class ChatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text)
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PriceRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    rule_type = db.Column(db.String(50))  # 'time', 'inventory', 'user_behavior'
    condition = db.Column(db.String(255))  # e.g., {"time_range": ["20:00", "23:59"]}
    discount_percent = db.Column(db.Float)
    active = db.Column(db.Boolean, default=True)


class DiscountRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_type = db.Column(db.String(50), nullable=False)  # e.g. time, inventory, user_behavior
    condition_json = db.Column(db.Text, nullable=False)  # store condition as JSON string
    discount_percent = db.Column(db.Float, nullable=False)
    active = db.Column(db.Boolean, default=True)
    
    def get_condition(self):
        return json.loads(self.condition_json)
    
    def set_condition(self, condition_dict):
        self.condition_json = json.dumps(condition_dict)

class UserProductView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    view_count = db.Column(db.Integer, default=1)

class ForecastData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    prediction = db.Column(db.Float)
    lower_bound = db.Column(db.Float)
    upper_bound = db.Column(db.Float)


class Click(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    page = db.Column(db.String(255))
    x = db.Column(db.Integer)
    y = db.Column(db.Integer)
    screen_width = db.Column(db.Integer)
    screen_height = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class NewsletterSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Subscriber {self.email}>"