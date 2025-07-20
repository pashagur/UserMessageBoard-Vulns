import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, URLField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL, Optional
from models import User


def validate_no_html_js(form, field):
    """Custom validator to prevent HTML/JavaScript content in usernames."""
    dangerous_patterns = [
        r'<[^>]*>',  # HTML tags
        r'javascript:',  # JavaScript protocol
        r'on\w+\s*=',  # JavaScript event handlers
        r'&[#\w]+;',  # HTML entities
        r'[<>"\']',  # Potentially dangerous characters
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, field.data, re.IGNORECASE):
            raise ValidationError('Username cannot contain HTML, JavaScript, or special characters.')
    
    # Only allow alphanumeric characters, underscores, hyphens, and spaces
    if not re.match(r'^[a-zA-Z0-9_\-\s]+$', field.data):
        raise ValidationError('Username can only contain letters, numbers, underscores, hyphens, and spaces.')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        validate_no_html_js
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists. Please use a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])
    submit = SubmitField('Login')


class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[
        DataRequired(),
        Length(min=1, max=500)
    ])
    submit = SubmitField('Post Message')
    
    def validate_content(self, content):
        """Validate message content to prevent XSS attacks."""
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'<iframe[^>]*>.*?</iframe>',  # Iframe tags
            r'javascript:',  # JavaScript protocol
            r'on\w+\s*=',  # JavaScript event handlers
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content.data, re.IGNORECASE | re.DOTALL):
                raise ValidationError('Message content cannot contain potentially harmful scripts or code.')


class ProfileUpdateForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50),
        validate_no_html_js
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    avatar_url = URLField('Avatar URL', validators=[
        Optional(),
        URL(message='Please enter a valid URL')
    ])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password')
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Update Profile')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already exists. Please use a different one.')
