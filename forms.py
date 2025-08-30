from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, FileField, SubmitField, TextAreaField, IntegerField
from wtforms import BooleanField, SelectField, SelectMultipleField, PasswordField, FloatField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, URL, NumberRange, Email, EqualTo, ValidationError, Optional
from flask_wtf.file import FileAllowed, FileRequired
from wtforms.widgets import NumberInput
from wtforms import FieldList, Form, FormField
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, FileField
import json

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

ALL_SIZES = [
    {'name': 'XS'},
    {'name': 'S'},
    {'name': 'M'},
    {'name': 'L'},
    {'name': 'XL'},
    {'name': 'XXL'},
    
]


# Subform for sizes + quantities
class ProductSizeQuantityForm(Form):  # Subform, not FlaskForm
    size = SelectField('Size', coerce=int, choices=[], validators=[Optional()])  # optional to avoid validation errors
    quantity = IntegerField('Quantity', validators=[Optional(), NumberRange(min=0)])

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    category = SelectField(
        'Category',
        choices=[('men','Men'),('women','Women'),('kids','Kids'),('accessories','Accessories')],
        validators=[DataRequired()]
    )
    tag = StringField('Tag', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional()])
    
    # Make stock optional because we compute from sizes/quantities
    stock = IntegerField('Stock', validators=[Optional(), NumberRange(min=0)])

    main_image = FileField(
        'Main Product Image',
        validators=[Optional(), FileAllowed(['jpg','png','jpeg','gif'],'Images only!')]
    )
    additional_images = FieldList(
        FileField('Additional Product Image',
                  validators=[FileAllowed(['jpg','png','jpeg','gif'],'Images only!'), Optional()]),
        min_entries=0, max_entries=5
    )

    # Sizes + quantities FieldList (dynamic via JS)
    sizes_and_quantities = FieldList(FormField(ProductSizeQuantityForm), min_entries=1)

    # Colors set dynamically in view
    colors = SelectMultipleField('Colors', coerce=int, choices=[], validators=[Optional()])

    submit = SubmitField('Save Product')


    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Length(max=150)])
    password = StringField('Password', validators=[DataRequired(), Length(min=6)])
    mobile = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=15)])
    gender = SelectField('Gender', choices=[('', 'Select'), ('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[Optional()])
    submit = SubmitField('Register')

class BannerForm(FlaskForm):
    image = FileField('Banner Image', validators=[FileRequired(), FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    description = StringField('Description (e.g., "Main Banner")', validators=[Length(max=255), Optional()])
    is_active = BooleanField('Is Active', default=True)
    submit = SubmitField('Upload Image')

class ReviewForm(FlaskForm):
    rating = IntegerField('Rating (1-5 Stars)', validators=[
        DataRequired('Please provide a rating.'),
        NumberRange(min=1, max=5, message='Rating must be between 1 and 5.')
    ], widget=NumberInput())
    comment = TextAreaField('Your Review', validators=[Length(max=500, message='Comment cannot exceed 500 characters.'), Optional()])
    submit = SubmitField('Submit Review')

class AddressForm(FlaskForm):
    label = StringField('Address Label (e.g., Home, Work)', validators=[Length(max=50), Optional()])
    recipient_name = StringField('Recipient Name', validators=[DataRequired(), Length(max=100)])
    mobile = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=15)])
    house_no = StringField('House No./Building Name', validators=[DataRequired(), Length(max=50)])
    road = StringField('Road Name/Area/Colony', validators=[Length(max=100), Optional()])
    area = StringField('Locality/Area', validators=[Length(max=100), Optional()])
    city = StringField('City', validators=[DataRequired(), Length(max=50)])
    state = StringField('State', validators=[DataRequired(), Length(max=50)])
    pincode = StringField('Pincode', validators=[DataRequired(), Length(min=5, max=10)])
    is_default = BooleanField('Set as default address', default=False)
    submit = SubmitField('Save Address')

class ProfileEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Length(max=150)])
    mobile = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=15)])
    name = StringField('Full Name', validators=[Length(max=100), Optional()])
    gender = SelectField('Gender', choices=[('', 'Select'), ('male', 'Male'), ('female', 'Female'), ('other', 'Other')], validators=[Optional()])
    profile_pic = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png'], 'Images only!'), Optional()])
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    old_password = StringField('Old Password', validators=[DataRequired()])
    new_password = StringField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = StringField('Confirm New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Change Password')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = StringField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = StringField('Confirm New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Reset Password')

class AddToCartForm(FlaskForm):
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1, message='Quantity must be at least 1')], default=1)
    color = SelectField('Color', validators=[DataRequired()])
    size = SelectField('Size', validators=[DataRequired()])
    submit = SubmitField('Add to Cart')


class PaymentSettingsForm(FlaskForm):
    """
    Form for managing payment gateway settings.
    """
    razorpay_key = StringField(
        'Razorpay Key ID',
        validators=[DataRequired(message='Razorpay Key ID is required.')],
        render_kw={"placeholder": "Enter your Razorpay Key ID"}
    )
    razorpay_secret = StringField(
        'Razorpay Key Secret',
        validators=[DataRequired(message='Razorpay Key Secret is required.')],
        render_kw={"placeholder": "Enter your Razorpay Key Secret"}
    )
    submit = SubmitField('Save Settings')


class GeneralSettingsForm(FlaskForm):
    """Form for general site information."""
    site_name = StringField(
        'Site Name',
        validators=[DataRequired('Site name is required.')],
        render_kw={"placeholder": "e.g., Chic Boutique"}
    )
    site_tagline = StringField(
        'Site Tagline',
        validators=[Optional()],
        render_kw={"placeholder": "e.g., Where style meets comfort"}
    )
    contact_email = StringField(
        'Contact Email',
        validators=[DataRequired('Contact email is required.')],
        render_kw={"placeholder": "e.g., info@yourstore.com"}
    )
    support_phone = StringField(
        'Support Phone',
        validators=[Optional()],
        render_kw={"placeholder": "e.g., +1-555-123-4567"}
    )
    address = TextAreaField(
        'Business Address',
        validators=[Optional()],
        render_kw={"rows": 3, "placeholder": "Your business's physical address"}
    )
    logo_url = StringField(
        'Logo URL (or Filename)',
        validators=[Optional(), URL(message='Must be a valid URL if provided.')], # Use URL validator if expecting a full URL
        render_kw={"placeholder": "e.g., /static/images/logo.png or http://example.com/logo.png"}
    )
    submit_general = SubmitField('Save General Settings')


class SocialMediaSettingsForm(FlaskForm):
    """Form for social media links."""
    facebook_url = StringField(
        'Facebook URL',
        validators=[Optional(), URL(message='Must be a valid URL.')],
        render_kw={"placeholder": "e.g., https://facebook.com/yourstore"}
    )
    instagram_url = StringField(
        'Instagram URL',
        validators=[Optional(), URL(message='Must be a valid URL.')],
        render_kw={"placeholder": "e.g., https://instagram.com/yourstore"}
    )
    twitter_url = StringField(
        'Twitter (X) URL',
        validators=[Optional(), URL(message='Must be a valid URL.')],
        render_kw={"placeholder": "e.g., https://twitter.com/yourstore"}
    )
    pinterest_url = StringField(
        'Pinterest URL',
        validators=[Optional(), URL(message='Must be a valid URL.')],
        render_kw={"placeholder": "e.g., https://pinterest.com/yourstore"}
    )
    submit_social = SubmitField('Save Social Media Settings')


class FeatureTogglesForm(FlaskForm):
    """Form for enabling/disabling site features."""
    maintenance_mode = BooleanField('Enable Maintenance Mode')
    new_user_registration_enabled = BooleanField('Enable New User Registration')
    reviews_enabled = BooleanField('Enable Product Reviews')
    guest_checkout_enabled = BooleanField('Enable Guest Checkout')
    submit_features = SubmitField('Save Feature Toggles')


class EcommerceSettingsForm(FlaskForm):
    """Form for e-commerce specific operational settings."""
    items_per_page_catalog = IntegerField(
        'Items Per Page (Catalog)',
        validators=[DataRequired(), NumberRange(min=1, message='Must be at least 1.')],
        default=12, # A good default value
        render_kw={"placeholder": "e.g., 12"}
    )
    default_currency = StringField(
        'Default Currency',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g., USD, INR, EUR"}
    )
    shipping_cost_flat_rate = DecimalField(
        'Flat Rate Shipping Cost',
        validators=[Optional()],
        render_kw={"placeholder": "e.g., 5.00"}
    )
    free_shipping_min_order_amount = DecimalField(
        'Free Shipping Minimum Order Amount',
        validators=[Optional()],
        render_kw={"placeholder": "e.g., 50.00"}
    )
    tax_rate_percentage = DecimalField(
        'Global Tax Rate (%)',
        validators=[Optional(), NumberRange(min=0, max=100, message='Must be between 0 and 100.')],
        render_kw={"placeholder": "e.g., 8.25"}
    )
    order_confirmation_email_sender = StringField(
        'Order Confirmation Email Sender',
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g., no-reply@yourstore.com"}
    )
    submit_ecommerce = SubmitField('Save E-commerce Settings')


class SeoAnalyticsForm(FlaskForm):
    """Form for SEO and analytics settings."""
    default_meta_description = TextAreaField(
        'Default Meta Description',
        validators=[Optional()],
        render_kw={"rows": 3, "placeholder": "Default description for search engines"}
    )
    default_meta_keywords = StringField(
        'Default Meta Keywords',
        validators=[Optional()],
        render_kw={"placeholder": "comma, separated, keywords"}
    )
    google_analytics_id = StringField(
        'Google Analytics ID',
        validators=[Optional()],
        render_kw={"placeholder": "e.g., UA-XXXXXXXXX-Y or G-XXXXXXXXXX"}
    )
    submit_seo = SubmitField('Save SEO & Analytics Settings')



class AdminSettingsForm(FlaskForm):
    site_name = StringField('Site Name', validators=[DataRequired()])
    site_tagline = StringField('Tagline', validators=[Optional()])
    contact_email = StringField('Contact Email', validators=[Optional(), Email()])
    support_phone = StringField('Support Phone', validators=[Optional()])
    facebook_url = StringField('Facebook URL')
    instagram_url = StringField('Instagram URL')
    twitter_url = StringField('Twitter URL')
    linkedin_url = StringField('LinkedIn URL')
    enable_razorpay = BooleanField('Enable Razorpay')
    enable_cod = BooleanField('Enable Cash on Delivery (COD)')

    footer_about = TextAreaField('Footer About Section')
    footer_links = TextAreaField('Footer Links (HTML or JSON)')
    
    logo_file = FileField('Upload Logo', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'svg'], 'Images only!')])
    favicon_file = FileField('Upload Favicon', validators=[FileAllowed(['ico', 'png'], 'Only .ico or .png!')])
    
    google_analytics_id = StringField('Google Analytics ID', validators=[Optional()])
    microsoft_clarity_id = StringField('Microsoft Clarity ID', validators=[Optional()])
    
    meta_title = StringField('Meta Title', validators=[Optional()])
    meta_description = StringField('Meta Description', validators=[Optional()])
    meta_keywords = StringField('Meta Keywords', validators=[Optional()])
    
    maintenance_mode = BooleanField('Maintenance Mode')
    
    submit = SubmitField('Save Settings')


class BannerForm(FlaskForm):
    image = FileField("Banner Image", validators=[
        FileRequired(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Images only!')
    ])
    heading = StringField("Heading", validators=[Optional()])
    subheading = StringField("Subheading", validators=[Optional()])
    link = StringField("Link URL", validators=[Optional()])
    is_active = BooleanField("Show on site", default=True)
    submit = SubmitField("Add Banner")



class AdminUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('user', 'User'), ('staff', 'Staff'), ('admin', 'Admin'), ('superadmin', 'Super Admin')], validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[Optional(), EqualTo('confirm_password', message='Passwords must match'), Length(min=6, message='Password must be at least 6 characters long')])
    confirm_password = PasswordField('Repeat Password')
    submit = SubmitField('Save Admin')


class RuleForm(FlaskForm):
    rule_type = SelectField('Rule Type', choices=[('time', 'Time'), ('inventory', 'Inventory'), ('user_behavior', 'User Behavior')], validators=[DataRequired()])
    condition_json = StringField('Condition (JSON format)', validators=[DataRequired()])
    discount_percent = FloatField('Discount %', validators=[DataRequired()])
    active = BooleanField('Active', default=True)
    submit = SubmitField('Save')

    def validate_condition_json(form, field):
        try:
            json.loads(field.data)
        except Exception:
            raise ValidationError('Condition must be valid JSON.')
