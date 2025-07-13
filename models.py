from datetime import datetime
import os
import requests
from app import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)  # renamed to avoid conflict with UserMixin
    post_count = db.Column(db.Integer, default=0)
    avatar_url = db.Column(db.Text)
    
    # Relationship with Message model
    messages = db.relationship('Message', backref='author', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def is_active(self):
        """Flask-Login requires is_active property."""
        return self.active
        
    def get_badge(self):
        """Determine user's activity badge based on post count."""
        if self.post_count >= 50:
            return {
                'name': 'Gold Contributor',
                'icon': 'trophy',
                'color': '#FFD700'
            }
        elif self.post_count >= 25:
            return {
                'name': 'Silver Contributor',
                'icon': 'award',
                'color': '#C0C0C0'
            }
        elif self.post_count >= 10:
            return {
                'name': 'Bronze Contributor',
                'icon': 'star',
                'color': '#CD7F32'
            }
        elif self.post_count >= 5:
            return {
                'name': 'Active Member',
                'icon': 'thumbs-up',
                'color': '#4682B4'
            }
        else:
            return {
                'name': 'New Member',
                'icon': 'user',
                'color': '#808080'
            }
    
    def get_avatar_filename(self):
        """Generate a unique filename for the user's avatar."""
        return f"avatar_{self.id}.jpg"
    
    def get_avatar_path(self):
        """Get the full path to the user's avatar file."""
        return os.path.join('static', 'avatars', self.get_avatar_filename())
    
    def download_avatar(self, url):
        """Download avatar from URL and save it locally."""
        try:
            # Create avatars directory if it doesn't exist
            avatars_dir = os.path.join('static', 'avatars')
            os.makedirs(avatars_dir, exist_ok=True)
            
            # Download the image
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Check if it's an image
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('image/'):
                return False, "URL does not point to an image"
            
            # Save the image
            avatar_path = self.get_avatar_path()
            with open(avatar_path, 'wb') as f:
                f.write(response.content)
            
            return True, "Avatar downloaded successfully"
            
        except requests.exceptions.RequestException as e:
            return False, f"Failed to download avatar: {str(e)}"
        except Exception as e:
            return False, f"Error saving avatar: {str(e)}"
    
    def get_avatar_url(self):
        """Get the URL for the user's avatar or default avatar."""
        avatar_path = self.get_avatar_path()
        if os.path.exists(avatar_path):
            return f"/static/avatars/{self.get_avatar_filename()}"
        else:
            # Return a default avatar URL
            return f"https://ui-avatars.com/api/?name={self.username}&background=random&size=64"


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Message {self.id} by User {self.user_id}>'
