from main import app, db  # Import both the app and db from your main application file

# Set up an application context
with app.app_context():
    db.create_all()
