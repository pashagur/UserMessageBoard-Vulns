
#!/usr/bin/env python3
"""
Cleanup script to remove all users, messages from database and avatar files from disk.
WARNING: This will permanently delete all data!
"""

import os
import sys
import shutil
from app import app, db
from models import User, Message

def cleanup_database():
    """Remove all messages and users from the database."""
    with app.app_context():
        print("Cleaning up database...")
        
        # Delete all messages first (due to foreign key constraints)
        message_count = Message.query.count()
        Message.query.delete()
        print(f"Deleted {message_count} messages")
        
        # Delete all users
        user_count = User.query.count()
        User.query.delete()
        
        # Commit the changes
        db.session.commit()
        print(f"Deleted {user_count} users")
        
def cleanup_avatars():
    """Remove all avatar files from disk."""
    avatars_dir = os.path.join('static', 'avatars')
    
    if os.path.exists(avatars_dir):
        # Count files before deletion
        avatar_files = [f for f in os.listdir(avatars_dir) if f.startswith('avatar_')]
        file_count = len(avatar_files)
        
        # Remove the entire avatars directory and recreate it
        shutil.rmtree(avatars_dir)
        os.makedirs(avatars_dir, exist_ok=True)
        
        print(f"Deleted {file_count} avatar files")
    else:
        print("No avatars directory found")

def cleanup_all():
    """Main function to clean up all data."""
    # Check for /delete_all parameter
    if len(sys.argv) > 1 and sys.argv[1] == "/delete_all":
        print("Non-interactive mode: Proceeding with deletion...")
        
        # Clean database
        cleanup_database()
        
        # Clean avatar files
        cleanup_avatars()
        
        print("\nCleanup completed successfully!")
        print("The database and avatar files have been cleared.")
        print("You can run seed_data.py to populate with sample data again.")
        
    else:
        print("=" * 50)
        print("WARNING: This will permanently delete ALL data!")
        print("- All user accounts")
        print("- All messages")
        print("- All avatar images")
        print("=" * 50)
        
        confirm = input("Are you sure you want to proceed? Type 'DELETE ALL' to confirm: ")
        
        if confirm == "DELETE ALL":
            print("\nStarting cleanup process...")
            
            # Clean database
            cleanup_database()
            
            # Clean avatar files
            cleanup_avatars()
            
            print("\nCleanup completed successfully!")
            print("The database and avatar files have been cleared.")
            print("You can run seed_data.py to populate with sample data again.")
            
        else:
            print("Cleanup cancelled. No data was deleted.")

if __name__ == "__main__":
    cleanup_all()
