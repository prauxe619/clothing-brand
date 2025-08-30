import os
from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def init_mail(app):
    # Configure mail settings using environment variables or directly here
    app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", 587))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")  # your email
    app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")  # app password or real password
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER", app.config['MAIL_USERNAME'])

    mail.init_app(app)

def send_order_confirmation(to_email, order):
    with current_app.app_context():
        msg = Message(subject="🛍️ Order Confirmation - Your Order Has Been Received!",
                      recipients=[to_email])

        msg.body = f"""
Hi {order.order_name},

Thank you for your order!

🧾 Order ID: {order.order_id}
💰 Amount: ₹{order.total / 100:.2f}
📦 Shipping To: {order.address}

We'll notify you when your order ships.

Thanks again for shopping with us!
"""

        mail.send(msg)
