
#!/usr/bin/env python3
"""
Seed script to populate the database with default users and sample messages.
"""

from app import app, db
from models import User, Message
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import random

def create_sample_users():
    """Create sample users with different activity levels."""
    sample_users = [
        {
            'username': 'alice_admin',
            'email': 'alice@example.com',
            'password': 'password123',
            'post_count': 52,  # Gold contributor
            'days_ago': 30
        },
        {
            'username': 'bob_silver',
            'email': 'bob@example.com', 
            'password': 'password123',
            'post_count': 28,  # Silver contributor
            'days_ago': 20
        },
        {
            'username': 'charlie_bronze',
            'email': 'charlie@example.com',
            'password': 'password123', 
            'post_count': 12,  # Bronze contributor
            'days_ago': 15
        },
        {
            'username': 'diana_active',
            'email': 'diana@example.com',
            'password': 'password123',
            'post_count': 7,   # Active member
            'days_ago': 10
        },
        {
            'username': 'eve_newbie',
            'email': 'eve@example.com',
            'password': 'password123',
            'post_count': 2,   # New member
            'days_ago': 5
        }
    ]
    
    created_users = []
    
    for user_data in sample_users:
        # Check if user already exists
        existing_user = User.query.filter_by(username=user_data['username']).first()
        if existing_user:
            print(f"User {user_data['username']} already exists, skipping...")
            created_users.append(existing_user)
            continue
            
        user = User()
        user.username = user_data['username']
        user.email = user_data['email']
        user.password_hash = generate_password_hash(user_data['password'])
        user.post_count = user_data['post_count']
        user.date_joined = datetime.utcnow() - timedelta(days=user_data['days_ago'])
        
        db.session.add(user)
        created_users.append(user)
        print(f"Created user: {user.username}")
    
    db.session.commit()
    return created_users

def create_sample_messages(users):
    """Create sample messages from the users."""
    sample_messages = [
        "Welcome to our bulletin board! This is a great place to share ideas.",
        "Has anyone tried the new Python 3.12 features? They look amazing!",
        "Looking for recommendations on good Flask tutorials.",
        "Just deployed my first web app. Feeling accomplished! 🎉",
        "Does anyone know how to optimize database queries in SQLAlchemy?",
        "Coffee or tea? The eternal developer question ☕",
        "Working on a machine learning project. Any dataset suggestions?",
        "The new Bootstrap 5 features are really nice for responsive design.",
        "Debugging can be frustrating, but finding the bug is so satisfying!",
        "What's everyone's favorite code editor? I'm curious to hear opinions.",
        "Just learned about Flask-Login. Authentication is much easier now!",
        "Anyone attending any tech conferences this year?",
        "CSS Grid vs Flexbox - when do you use which one?",
        "Successfully fixed a performance issue today. Small wins matter!",
        "What are your thoughts on the latest JavaScript frameworks?"
    ]
    
    message_count = 0
    for user in users:
        # Create messages based on user's post count
        messages_to_create = min(user.post_count, len(sample_messages))
        user_messages = random.sample(sample_messages, messages_to_create)
        
        for i, content in enumerate(user_messages):
            message = Message()
            message.content = content
            message.user_id = user.id
            # Spread messages over time
            message.timestamp = datetime.utcnow() - timedelta(
                days=random.randint(1, 20),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            db.session.add(message)
            message_count += 1
    
    db.session.commit()
    print(f"Created {message_count} sample messages")

def seed_database():
    """Main function to seed the database with sample data."""
    with app.app_context():
        print("Seeding database with sample data...")
        
        # Create sample users
        users = create_sample_users()
        
        # Create sample messages
        create_sample_messages(users)
        
        print("Database seeding completed!")
        print("\nSample login credentials:")
        print("Email: alice@example.com, Password: password123 (Gold)")
        print("Email: bob@example.com, Password: password123 (Silver)")
        print("Email: charlie@example.com, Password: password123 (Bronze)")
        print("Email: diana@example.com, Password: password123 (Active)")
        print("Email: eve@example.com, Password: password123 (New)")

if __name__ == "__main__":
    seed_database()
