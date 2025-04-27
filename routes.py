from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User, Message
from forms import RegistrationForm, LoginForm, MessageForm, ProfileUpdateForm


@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html', title='Welcome to Bulletin Board')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('bulletin'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('bulletin'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('bulletin'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/bulletin', methods=['GET', 'POST'])
@login_required
def bulletin():
    """Bulletin board route for viewing and posting messages."""
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(content=form.content.data, author=current_user)
        db.session.add(message)
        db.session.commit()
        flash('Your message has been posted!', 'success')
        return redirect(url_for('bulletin'))
    
    # Get all messages, ordered by newest first
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    
    return render_template('bulletin.html', title='Bulletin Board', form=form, messages=messages)


@app.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    """Route for deleting a message."""
    message = Message.query.get_or_404(message_id)
    if message.author != current_user:
        abort(403)  # Forbidden access
    
    db.session.delete(message)
    db.session.commit()
    flash('Your message has been deleted!', 'success')
    return redirect(url_for('bulletin'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile route for viewing and updating user information."""
    form = ProfileUpdateForm(original_username=current_user.username, original_email=current_user.email)
    
    if form.validate_on_submit():
        # Check if current password is provided and correct when updating password
        if form.new_password.data:
            if not form.current_password.data:
                flash('Current password is required to set a new password.', 'danger')
                return render_template('profile.html', title='Profile', form=form)
            
            if not check_password_hash(current_user.password_hash, form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile.html', title='Profile', form=form)
            
            current_user.password_hash = generate_password_hash(form.new_password.data)
            flash('Your password has been updated.', 'success')
        
        # Update username and email
        current_user.username = form.username.data
        current_user.email = form.email.data
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    
    # Get user's messages
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    
    return render_template('profile.html', title='Profile', form=form, messages=messages)


@app.errorhandler(404)
def page_not_found(e):
    """404 error handler."""
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    """403 error handler."""
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    """500 error handler."""
    return render_template('500.html'), 500
