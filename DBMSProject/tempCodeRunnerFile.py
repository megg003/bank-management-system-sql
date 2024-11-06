from flask import Flask, render_template, request, redirect, url_for, flash, session
import nest_asyncio
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum
import os
import uuid
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# Apply nest_asyncio to avoid event loop issues
nest_asyncio.apply()

# Create a Flask application instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:AngelsAndDemons666@localhost/bank'
app.config['SECRET_KEY'] = "my super secret key"
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'meghanaaithal1863@gmail.com'  # Replace with your actual Gmail address
app.config['MAIL_PASSWORD'] = 'dgqb fvti raic qnco'  # Replace with the app password you generated
app.config['MAIL_DEFAULT_SENDER'] = 'meghanaaithal1863@gmail.com'  # Set your email here

mail = Mail(app)

# Initialize the database
db = SQLAlchemy(app)

class UserStatus(Enum):
    ACTIVE = 'active'
    SUSPENDED = 'suspended'
    ON_HOLD = 'on_hold'
    CANCELLED = 'cancelled'

class UserInfo(db.Model):
    __tablename__ = 'User_Info'
    user_id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(12), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    middle_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    user_name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date)
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    pincode = db.Column(db.String(10))
    address = db.Column(db.String(200))
    phone_number = db.Column(db.String(15))
    access_type = db.Column(db.String(20))
    user_status = db.Column(db.Enum(UserStatus), default=UserStatus.ACTIVE.value)

class LoanStatus(Enum):
    APPROVED = 'approved'
    PENDING = 'pending'
    REJECTED = 'rejected'

class Loan(db.Model):
    __tablename__ = 'Loans'  # Corrected the table name definition
    loan_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User_Info.user_id'))
    loan_amount = db.Column(db.Numeric(10, 2))
    interest_rate = db.Column(db.Numeric(5, 2))
    tenure = db.Column(db.Integer)
    documents = db.Column(db.String(255))
    status = db.Column(db.Enum(LoanStatus), default=LoanStatus.PENDING.value)  # Use Enum's value
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    modified_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    tracking_id = db.Column(db.String(36), unique=True, nullable=False)  # New field for tracking ID

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Retrieve user from database based on username
        user = UserInfo.query.filter_by(user_name=username).first()

        if user is None:
            flash('Username not found. Please register.', 'danger')
        elif check_password_hash(user.password, password):
            session['user_id'] = user.user_id  # Store user ID in session
            flash(f'Logged in successfully! Your user ID is {user.user_id}', 'success')
            return redirect(url_for('homepage'))  # Redirect to homepage or other page
        else:
            flash('Incorrect password. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    reset_link = url_for('reset_password', token='your_secure_token', _external=True)

    # Create the email message
    msg = Message(
    'Password Reset Request',
    sender=app.config['MAIL_DEFAULT_SENDER'],  # This should work
    recipients=[email])

    msg.body = f'Please click the link to reset your password: {reset_link}'

    try:
        mail.send(msg)
        flash('A password reset link has been sent to your email.', 'success')
    except Exception as e:
        flash('An error occurred while sending the email. Please try again later.', 'danger')
        print(f'Error sending email: {e}')  # Log the error to the console

    return redirect(url_for('login'))

@app.route('/test-email')
def test_email():
    msg = Message(
        'Test Email',
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=['aithalmeghana21@gmail.com']  # Change to a valid email for testing
    )
    msg.body = 'This is a test email to verify the configuration.'
    try:
        mail.send(msg)
        return 'Test email sent successfully!'
    except Exception as e:
        return f'Failed to send test email: {e}'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract data from the form
        first_name = request.form['first_name']
        middle_name = request.form.get('middle_name', '')  # Optional
        last_name = request.form['last_name']
        user_name = request.form['username']
        email = request.form['email']
        password = request.form['password']
        date_of_birth = request.form['dob']
        city = request.form['city']
        state = request.form['state']
        pincode = request.form['pincode']
        address = request.form['address']
        phone_number = request.form['phoneNumber']
        access_type = request.form['accessType']

        # Hash the password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Generate a unique 12-character account ID
        account_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

        # Create a new UserInfo object
        new_user = UserInfo(
            account_id=account_id,
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            user_name=user_name,
            email=email,
            password=hashed_password,
            date_of_birth=datetime.strptime(date_of_birth, '%Y-%m-%d'),
            city=city,
            state=state,
            pincode=pincode,
            address=address,
            phone_number=phone_number,
            access_type=access_type
        )

        # Add the user to the session and commit to the database
        db.session.add(new_user)
        db.session.commit()
        flash(f'Registration successful! Your account ID is {account_id}. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/deposit')
def deposit():
    return render_template('deposit.html')

@app.route('/withdraw')
def withdraw():
    return render_template('withdraw.html')

@app.route('/loan', methods=['GET', 'POST'])
def loan():
    if request.method == 'POST':
        # Get the logged-in user ID from the session
        user_id = session.get('user_id')  
        
        # Check if the user is logged in
        if not user_id:
            flash('You must be logged in to apply for a loan.', 'danger')
            return redirect(url_for('login'))

        # Extract form data
        loan_amount = request.form['loan_amount']
        interest_rate = request.form['interest_rate']
        tenure = request.form['tenure']

        # Handle file uploads
        if 'documents' not in request.files:
            flash('Please upload required documents.', 'danger')
            return redirect(request.url)

        documents = request.files.getlist('documents')
        document_paths = []

        # Save each document
        for document in documents:
            if document.filename == '':
                flash('No document selected', 'danger')
                continue
            document_path = os.path.join(app.config['UPLOAD_FOLDER'], document.filename)
            document.save(document_path)
            document_paths.append(document_path)

        if not document_paths:  # If no documents were uploaded, flash an error
            flash('At least one document is required.', 'danger')
            return redirect(request.url)

        document_paths_str = ','.join(document_paths)

        # Generate a unique tracking ID (UUID)
        tracking_id = str(uuid.uuid4())[:10]  # First 10 characters of UUID

        # Create a new Loan entry
        new_loan = Loan(
            user_id=user_id,
            loan_amount=loan_amount,
            interest_rate=interest_rate,
            tenure=tenure,
            documents=document_paths_str,
            tracking_id=tracking_id,
            status=LoanStatus.PENDING.value  # Use Enum's value
        )

        db.session.add(new_loan)
        db.session.commit()

        # Redirect to the loan confirmation page with the tracking ID
        return redirect(url_for('loan_confirmation', tracking_id=tracking_id))

    return render_template('loan.html')

@app.route('/loan-confirmation/<tracking_id>')
def loan_confirmation(tracking_id):
    return f'Your loan application is submitted! Tracking ID: {tracking_id}'

if __name__ == '__main__':
    app.run(debug=True)
