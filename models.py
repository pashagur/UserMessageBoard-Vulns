from datetime import datetime
from app import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)  # renamed to avoid conflict with UserMixin
    post_count = db.Column(db.Integer, default=0)
    
    # Relationship with Message model
    messages = db.relationship('Message', backref='author', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'
        
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


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Message {self.id} by User {self.user_id}>'
