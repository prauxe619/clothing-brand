# In your admin_bp file
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, jsonify, Response, current_app
from flask_login import login_required, current_user
from models import db, User, Order, OrderItem, Product, Size, Color, Setting, SiteSettings, Banner, UserActivityLog, ActivityLog, ForecastData, Click, NewsletterSubscriber
from datetime import datetime, timedelta
from sqlalchemy import func, desc
from forms import BannerForm, AdminSettingsForm, AdminUserForm
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import csv
from io import StringIO, TextIOWrapper
import os
from decorators import admin_required, role_required
import uuid
from extensions import cache


admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
THEME_UPLOAD_FOLDER = 'static/themes' 


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('admin/user_detail.html', user=user, orders=orders)


@admin_bp.route('/users/<int:user_id>/promote', methods=['POST'])
@login_required
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role != 'admin':
        user.role = 'admin'
        db.session.commit()
        return jsonify({'message': 'User promoted to admin.'}), 200
    return jsonify({'message': 'User is already admin.'}), 400

@admin_bp.route('/users/<int:user_id>/demote', methods=['POST'])
@login_required
@admin_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        user.role = 'user'
        db.session.commit()
        return jsonify({'message': 'User demoted to regular user.'}), 200
    return jsonify({'message': 'User is not admin.'}), 400

@admin_bp.route('/users/<int:user_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    db.session.commit()
    return jsonify({'message': 'User banned.'}), 200

@admin_bp.route('/users/<int:user_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    return jsonify({'message': 'User unbanned.'}), 200


@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    total_orders = Order.query.count()
    total_users = User.query.count()
    total_products = Product.query.count()
    
    today_sales = db.session.query(func.sum(Order.amount))\
        .filter(func.date(Order.created_at) == func.current_date()).scalar() or 0

    month_revenue = db.session.query(func.sum(Order.amount))\
        .filter(func.date_trunc('month', Order.created_at) == func.date_trunc('month', func.now()))\
        .scalar() or 0

    low_stock = Product.query.filter(Product.stock < 5).all()

    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()

    return render_template("admin/dashboard.html",
        total_orders=total_orders,
        total_users=total_users,
        total_products=total_products,
        today_sales=today_sales,
        month_revenue=month_revenue,
        low_stock=low_stock,
        recent_orders=recent_orders
    )


@admin_bp.route('/orders/export')
@login_required
@admin_required
def export_orders():
    orders = Order.query.all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Order ID', 'User', 'Amount', 'Status', 'Date'])

    for o in orders:
        writer.writerow([o.id, o.user.email, o.amount / 100, o.status, o.created_at])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=orders.csv"
    return output


@admin_bp.route('/upload-csv', methods=['GET', 'POST'])
@login_required
@admin_required
def upload_csv():
    if request.method == 'POST':
        file = request.files.get('csv_file')
        if not file or file.filename == '':
            flash("No file selected", "warning")
            return redirect(url_for('admin.upload_csv'))

        if not file.filename.endswith('.csv'):
            flash("Invalid file type. Only CSV files are allowed.", "danger")
            return redirect(url_for('admin.upload_csv'))

        try:
            try:
                decoded_file = file.stream.read().decode('utf-8')
            except UnicodeDecodeError:
                file.stream.seek(0)
                decoded_file = file.stream.read().decode('latin1')

            stream = StringIO(decoded_file, newline='')
            reader = csv.reader(stream)
            header = next(reader)

            expected_fields = ['name', 'description', 'price', 'stock', 'category']
            if [h.strip().lower() for h in header] != expected_fields:
                flash("Invalid CSV header. Expected: name, description, price, stock, category", "danger")
                return redirect(url_for('admin.upload_csv'))

            added = 0
            for row_num, row in enumerate(reader, start=2):
                if len(row) != 5:
                    print(f"Row {row_num} skipped: expected 5 fields, got {len(row)}")
                    continue
                try:
                    name, description, price, stock, category = row
                    product = Product(
                        name=name.strip(),
                        description=description.strip(),
                        price=int(float(price.strip())),
                        stock=int(stock.strip()),
                        category=category.strip()
                    )
                    db.session.add(product)
                    added += 1
                except Exception as e:
                    print(f"Row {row_num} skipped: {e}")
                    continue

            db.session.commit()
            flash(f"{added} products imported successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"CSV upload failed: {str(e)}", "danger")

        # ✅ Always redirect to a fixed, safe route
        return redirect(url_for('admin.upload_csv'))

    return render_template('admin/upload_csv.html')



@admin_bp.route('/sizes', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_sizes():
    if request.method == 'POST':
        size_name = request.form.get('name')
        if size_name:
            if not Size.query.filter_by(name=size_name).first():
                new_size = Size(name=size_name)
                db.session.add(new_size)
                db.session.commit()
                flash(f'Size "{size_name}" added successfully!', 'success')
            else:
                flash(f'Size "{size_name}" already exists.', 'warning')
        else:
            flash('Size name cannot be empty.', 'danger')
        return redirect(url_for('admin.manage_sizes'))
    
    sizes = Size.query.all()
    return render_template('admin/manage_sizes.html', sizes=sizes)


@admin_bp.route('/sizes/delete/<int:size_id>', methods=['POST'])
@login_required
@admin_required
def delete_size(size_id):
    size = Size.query.get_or_404(size_id)
    for product in list(size.products):
        product.sizes.remove(size)
    db.session.delete(size)
    db.session.commit()
    flash('Size deleted successfully!', 'success')
    return redirect(url_for('admin.manage_sizes'))


@admin_bp.route('/colors', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_colors():
    if request.method == 'POST':
        color_name = request.form.get('name')
        if color_name:
            if not Color.query.filter_by(name=color_name).first():
                new_color = Color(name=color_name)
                db.session.add(new_color)
                db.session.commit()
                flash(f'Color "{color_name}" added successfully!', 'success')
            else:
                flash(f'Color "{color_name}" already exists.', 'warning')
        else:
            flash('Color name cannot be empty.', 'danger')
        return redirect(url_for('admin.manage_colors'))
    
    colors = Color.query.all()
    return render_template('admin/manage_colors.html', colors=colors)


@admin_bp.route('/colors/delete/<int:color_id>', methods=['POST'])
@login_required
@admin_required
def delete_color(color_id):
    color = Color.query.get_or_404(color_id)
    for product in list(color.products):
        product.colors.remove(color)
    db.session.delete(color)
    db.session.commit()
    flash('Color deleted successfully!', 'success')
    return redirect(url_for('admin.manage_colors'))


@admin_bp.route('/analytic_settings', methods=['GET', 'POST'], endpoint='analytic_settings')
@login_required
@admin_required
def settings():
    settings = SiteSettings.query.first()
    form = AdminSettingsForm()
    
    if form.validate_on_submit():
        if not settings:
            settings = SiteSettings()
            form.populate_obj(settings)
            db.session.add(settings)
            db.session.commit()
        settings_data = {
            "site_name": form.site_name.data,
            "site_tagline": form.site_tagline.data,
            "contact_email": form.contact_email.data,
            "support_phone": form.support_phone.data,
            "facebook_url": form.facebook_url.data,
            "instagram_url": form.instagram_url.data,
            "twitter_url": form.twitter_url.data,
            "linkedin_url": form.linkedin_url.data,
            "footer_about": form.footer_about.data,
            "footer_links": form.footer_links.data,
            "google_analytics_id": form.google_analytics_id.data,
            "microsoft_clarity_id": form.microsoft_clarity_id.data,
            "meta_title": form.meta_title.data,
            "meta_description": form.meta_description.data,
            "meta_keywords": form.meta_keywords.data,
            "maintenance_mode": form.maintenance_mode.data,
            "enable_razorpay": form.enable_razorpay.data,
            "enable_cod": form.enable_cod.data,
        }
        upload_path = os.path.join(current_app.root_path, 'static', 'uploads')
        os.makedirs(upload_path, exist_ok=True)
        if form.logo_file.data:
            logo_filename = secure_filename(form.logo_file.data.filename)
            form.logo_file.data.save(os.path.join(upload_path, 'logo', logo_filename))
            settings_data['logo_path'] = f'/static/uploads/logo/{logo_filename}'
        if form.favicon_file.data:
            favicon_filename = secure_filename(form.favicon_file.data.filename)
            form.favicon_file.data.save(os.path.join(upload_path, 'favicon', favicon_filename))
            settings_data['favicon_path'] = f'/static/uploads/favicon/{favicon_filename}'
        for key, value in settings_data.items():
            setattr(settings, key, value)

        db.session.add(settings)
        db.session.commit()

        flash("Settings updated successfully!", "success")
        return redirect(url_for('admin.analytic_settings'))
    return render_template('admin/analytic_settings.html', form=form, settings=settings)


@admin_bp.route('/banners', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_banners():
    form = BannerForm()
    banners = Banner.query.order_by(Banner.created_at.desc()).all()
    if form.validate_on_submit():
        upload_dir = os.path.join(current_app.root_path, 'static', 'uploads', 'banners')
        os.makedirs(upload_dir, exist_ok=True)
        filename = secure_filename(form.image.data.filename)
        filepath = os.path.join(upload_dir, filename)
        form.image.data.save(filepath)
        banner = Banner(
            image_path=f'/static/uploads/banners/{filename}',
            heading=form.heading.data,
            subheading=form.subheading.data,
            link=form.link.data,
            is_active=form.is_active.data
        )
        db.session.add(banner)
        db.session.commit()
        flash('Banner added successfully!', 'success')
        return redirect(url_for('admin.manage_banners'))
    return render_template('admin/banners.html', form=form, banners=banners)

@admin_bp.route('/banners/delete/<int:banner_id>', methods=['POST'])
@login_required
@admin_required
def delete_banner(banner_id):
    banner = Banner.query.get_or_404(banner_id)
    try:
        image_file = os.path.join(current_app.root_path, banner.image_path.strip("/"))
        if os.path.exists(image_file):
            os.remove(image_file)
        db.session.delete(banner)
        db.session.commit()
        flash('Banner deleted.', 'info')
    except Exception as e:
        flash(f'Error deleting banner: {e}', 'danger')
    return redirect(url_for('admin.manage_banners'))


@admin_bp.route('/activity-logs')
@login_required
@admin_required
def activity_logs():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    return render_template('admin/activity_logs.html', logs=logs)


@admin_bp.route('/user-activity')
@login_required
@admin_required
def user_activity():
    logs = UserActivityLog.query.order_by(UserActivityLog.timestamp.desc()).limit(100).all()
    return render_template('admin/user_activity_logs.html', logs=logs)


@admin_bp.route("/admins")
@login_required
@role_required('superadmin')
def manage_admins():
    admins = User.query.filter(User.role != 'user').all()
    return render_template("admin/manage_admins.html", admins=admins)


@admin_bp.route("/admins/add", methods=["GET", "POST"])
@login_required
@role_required('superadmin')
def add_admin():
    form = AdminUserForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Scenario 1: Update an existing user's role and password
        if user:
            user.role = form.role.data
            user.username = form.username.data
            if form.password.data:
                user.set_password(form.password.data)
            db.session.commit()
            flash("Updated existing user as admin.", "success")
        
        # Scenario 2: Create a new user
        else:
            # A password is required to create a new user
            if not form.password.data:
                flash("A password is required to create a new user.", "danger")
                return render_template("admin/edit_admin.html", form=form, action="Add")
            
            # Use a unique placeholder for the 'mobile' number to avoid errors
            unique_mobile_placeholder = str(uuid.uuid4().int)[:10]

            new_admin = User(
                email=form.email.data,
                role=form.role.data,
                mobile=unique_mobile_placeholder
            )
            new_admin.set_password(form.password.data) 
            db.session.add(new_admin)
            db.session.commit()
            flash("Created new admin user.", "success")
        
        return redirect(url_for('admin.manage_admins'))
    
    return render_template("admin/edit_admin.html", form=form, action="Add")

@admin_bp.route("/admins/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@role_required('superadmin')
def edit_admin(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.role = form.role.data
        # Only set password if a new one is provided
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash("Admin updated successfully.", "success")
        return redirect(url_for('admin.manage_admins'))
    
    return render_template("admin/edit_admin.html", form=form, action="Edit")

@admin_bp.route("/admins/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required('superadmin')
def delete_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'superadmin':
        flash("Cannot delete a superadmin.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash("Admin deleted.", "success")
    return redirect(url_for('admin.manage_admins'))

@admin_bp.route('/admin/theme-settings', methods=['GET', 'POST'])
@admin_required
def theme_settings():
    themes = {
        "default": {
            "primary_color": "#e91e63",
            "background_color": "#ffffff",
            "font_family": "'Inter', sans-serif"
        },
        "dark": {
            "primary_color": "#f59e0b",
            "background_color": "#1a1a1a",
            "font_family": "'Playfair Display', serif"
        },
        "gold": {
            "primary_color": "#FFD700",
            "background_color": "#ffffff",
            "font_family": "'Playfair Display', serif"
        }
    }

    settings = SiteSettings.get()

    if request.method == 'POST':
        settings.primary_color = request.form.get('primary_color')
        settings.background_color = request.form.get('background_color')
        settings.font_family = request.form.get('font_family')

        # Handle custom CSS file upload
        css_file = request.files.get('custom_css')
        if css_file and css_file.filename.endswith('.css'):
            filename = secure_filename(css_file.filename)
            save_path = os.path.join(THEME_UPLOAD_FOLDER, filename)
            css_file.save(save_path)
            settings.custom_css_file = filename  # Save filename to DB

        # Save and clear cache
        db.session.commit()
        cache.delete('theme_settings')

        flash("Theme updated successfully!", "success")
        return redirect(url_for('admin.theme_settings'))

    return render_template('admin/theme_settings.html', settings=settings, themes=themes)


@admin_bp.route('/admin/analytics/forecast')
@login_required
@admin_required
def forecast_view():
    forecasts = ForecastData.query.order_by(ForecastData.date).all()

    if not forecasts:
        return render_template('admin/analytics/forecast.html',
                               no_data=True,
                               dates=[],
                               predictions=[],
                               lower_bounds=[],
                               upper_bounds=[],
                               actual_dates=[],
                               actual_sales=[],
                               alert=None)

    dates = [f.date.strftime('%Y-%m-%d') for f in forecasts]
    predictions = [float(f.prediction) for f in forecasts]
    lower_bounds = [float(f.lower_bound) for f in forecasts]
    upper_bounds = [float(f.upper_bound) for f in forecasts]

    # Actual sales from Orders
    sales_data = (
        db.session.query(
            db.func.date(Order.created_at).label('date'),
            db.func.sum(Order.amount).label('total')
        )
        .filter(Order.status.in_(["paid", "completed", "delivered"]))
        .group_by(db.func.date(Order.created_at))
        .all()
    )
    actual_dates = [d.date.strftime('%Y-%m-%d') for d in sales_data]
    actual_sales = [float(d.total) for d in sales_data]

    # Business alert if forecast looks low
    threshold = 1000
    alert = None
    if predictions and predictions[-1] < threshold:
        alert = "⚠️ Forecasted sales for next week are low. Consider promotions or campaigns."

    return render_template('admin/analytics/forecast.html',
                           no_data=False,
                           dates=dates,
                           predictions=predictions,
                           lower_bounds=lower_bounds,
                           upper_bounds=upper_bounds,
                           actual_dates=actual_dates,
                           actual_sales=actual_sales,
                           alert=alert)


@admin_bp.route('/admin/analytics/segments')
def segment_view():
    segments = db.session.execute("""
        SELECT segment, COUNT(*) FROM user GROUP BY segment
    """).fetchall()
    return render_template("admin/analytics/segments.html", segments=segments)


@admin_bp.route('/click-report')
def click_report():
    clicks = Click.query.order_by(Click.timestamp.desc()).all()

    total_clicks = len(clicks)
    unique_users = len(set(c.user_id for c in clicks if c.user_id))
    unique_pages = len(set(c.page for c in clicks))

    return render_template(
        'admin/analytics/click_report.html',
        clicks=clicks,
        total_clicks=total_clicks,
        unique_users=unique_users,
        unique_pages=unique_pages
    )


@admin_bp.route('/forecast')
def admin_forecast():
    forecasts = ForecastData.query.order_by(ForecastData.date).all()
    if not forecasts:
        return render_template('admin/forecast.html', no_data=True)

    # Forecast data
    dates = [f.date.strftime('%Y-%m-%d') for f in forecasts]
    predictions = [f.prediction for f in forecasts]
    lower_bounds = [f.lower_bound for f in forecasts]
    upper_bounds = [f.upper_bound for f in forecasts]

    # Get actual sales per day from Orders
    sales_data = (
        db.session.query(
            db.func.date(Order.created_at).label('date'),
            db.func.sum(Order.amount).label('total')
        )
        .filter(Order.status == 'completed')  # Or use 'paid' depending on your logic
        .group_by(db.func.date(Order.created_at))
        .all()
    )

    actual_dates = [d.date.strftime('%Y-%m-%d') for d in sales_data]
    actual_sales = [float(d.total) for d in sales_data]

    # Optional: Check if future forecast is low
    threshold = 1000  # set based on your business logic
    alert = None
    if forecasts[-1].prediction < threshold:
        alert = "⚠️ Forecasted sales for next week are low. Consider boosting marketing or reducing stock."

    return render_template(
        'admin/analytics/forecast.html',
        dates=dates,
        predictions=predictions,
        lower_bounds=lower_bounds,
        upper_bounds=upper_bounds,
        actual_dates=actual_dates,
        actual_sales=actual_sales,
        alert=alert
    )


@admin_bp.route('/admin/newsletter-subscribers') # Changed URL for clarity/admin path
@login_required
def list_subscribers_admin():
    # --- IMPORTANT: Admin Role Check ---
    # You need to have an 'is_admin' attribute or similar role checking logic on your User model
    # For example: current_user.is_admin or current_user.role == 'admin'
    if not current_user.is_authenticated:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))
    subscribers = NewsletterSubscriber.query.all()
    return render_template('admin/subscribers.html', subscribers=subscribers)


@admin_bp.route("/admin/orders/<int:order_id>/update_status", methods=["POST"])
@login_required
def update_order_status(order_id):
    # Only allow admins
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return redirect(url_for("admin_dashboard"))

    order = Order.query.get_or_404(order_id)
    new_status = request.form.get("status")

    if new_status not in ["created", "paid", "shipped", "delivered", "cancelled"]:
        flash("Invalid status", "danger")
        return redirect(url_for("admin_dashboard"))

    order.status = new_status
    db.session.commit()
    flash(f"Order #{order.order_id} updated to {new_status.title()}", "success")
    return redirect(url_for("admin_dashboard"))
