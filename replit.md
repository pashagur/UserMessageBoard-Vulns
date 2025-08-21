# Alpha BSS Application

## Overview

This is a Flask-based Alpha BSS web application that allows users to register, login, and post messages to a shared community bulletin board. The application features user authentication, message posting, and user profiles with activity badges based on posting frequency.

## System Architecture

### Backend Architecture
- **Framework**: Flask web framework with SQLAlchemy ORM
- **Database**: Flexible database configuration supporting both PostgreSQL (production) and SQLite (development)
- **Authentication**: Flask-Login for session management with password hashing using Werkzeug
- **Forms**: WTForms with Flask-WTF for form handling and validation

### Frontend Architecture
- **Template Engine**: Jinja2 templates with inheritance-based layout
- **CSS Framework**: Bootstrap 5 with dark theme from Replit CDN
- **Icons**: Font Awesome for UI icons
- **JavaScript**: Vanilla JavaScript for form validation and interactive features

### Database Schema
- **User Model**: Stores user credentials, metadata, and activity tracking
- **Message Model**: Stores bulletin board posts with author relationships
- **Relationships**: One-to-many relationship between users and messages

## Key Components

### Core Application Files
- `app.py`: Application factory and configuration setup
- `main.py`: Application entry point for development server
- `models.py`: SQLAlchemy database models
- `routes.py`: Flask route handlers for all endpoints
- `forms.py`: WTForms form definitions with validation

### User Authentication System
- Registration with username/email uniqueness validation
- Secure password hashing with Werkzeug
- Session-based authentication using Flask-Login
- User profile management with activity badges

### Message System
- Community bulletin board for posting messages
- User activity tracking with post count
- Message authorship and timestamp tracking
- Responsive message display with user badges

### Template Structure
- `base.html`: Main layout template with navigation
- `index.html`: Landing page with feature overview
- `register.html`/`login.html`: Authentication forms
- `bulletin.html`: Main bulletin board interface
- `profile.html`: User profile management

## Data Flow

1. **User Registration**: Form validation → Password hashing → Database storage
2. **Authentication**: Login form → Password verification → Session creation
3. **Message Posting**: Authenticated form submission → Database storage → Post count increment
4. **Bulletin Display**: Database query → Template rendering → Responsive display

## External Dependencies

### Python Packages
- Flask: Web framework
- Flask-SQLAlchemy: Database ORM
- Flask-Login: Authentication management
- Flask-WTF: Form handling
- WTForms: Form validation
- Werkzeug: Password hashing and utilities

### Frontend Dependencies
- Bootstrap 5: UI framework (via CDN)
- Font Awesome: Icon library (via CDN)
- Custom CSS: Application-specific styling

### Database Support
- PostgreSQL: Production database (Heroku-compatible)
- SQLite: Development fallback database

## Deployment Strategy

### Configuration Management
- Environment variable-based configuration
- Database URL detection with fallback support
- Session secret management
- Proxy fix for HTTPS URL generation

### Database Migration
- SQLAlchemy model-based schema management
- Automatic table creation on first run
- Connection pooling with health checks

### Production Considerations
- ProxyFix middleware for reverse proxy deployment
- Database connection pooling and recycling
- Environment-specific secret key management

## Changelog
- July 01, 2025. Initial setup
- August 21, 2025. Changed application name from "Bulletin Board" to "Alpha BSS"

## User Preferences

Preferred communication style: Simple, everyday language.