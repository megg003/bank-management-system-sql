from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
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
import jwt
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from sqlalchemy import Numeric
from decimal import Decimal, getcontext
from sqlalchemy import func

# Apply nest_asyncio to avoid event loop issues
nest_asyncio.apply()

# Create a Flask application instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:AngelsAndDemons666@localhost/bank'
app.config['SECRET_KEY'] = "my super secret key"
UPLOAD_FOLDER = r"C:\Users\91984\Downloads\DBMSProject\uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'meghanaaithal1863@gmail.com'  # Replace with your actual Gmail address
app.config['MAIL_PASSWORD'] = 'dgqb fvti raic qnco'  # Replace with the app password you generated
app.config['MAIL_DEFAULT_SENDER'] = 'meghanaaithal1863@gmail.com'  # Set your email here

IST_OFFSET = timedelta(hours=5, minutes=30)
IST = timezone(IST_OFFSET)

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
    atm_pin = db.Column(db.String(255))  # Encrypted 4-digit PINs
    balance = db.Column(Numeric(10, 2), default=Decimal('0.00'))
  
    
class Transactions(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User_Info.user_id'), nullable=False)
    transaction_type = db.Column(db.String(100), nullable=False)  # 'deposit' or 'withdraw'
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))

    user = db.relationship('UserInfo', backref='transactions')
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
    status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending' as default
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(IST))
    modified_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(IST), onupdate=lambda: datetime.now(IST))
    tracking_id = db.Column(db.String(36), unique=True, nullable=False)  # New field for tracking ID
    emi = db.Column(db.Numeric(10, 2), nullable=True)  # Monthly installment amount
    amount_due = db.Column(db.Numeric(10, 2), nullable=True)  # Total outstanding amount


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
            session['is_admin'] = user.access_type.lower() == 'admin'  # Store admin status in session
            print(f"User is admin: {session['is_admin']}")
            flash(f'Logged in successfully!', 'success')
            return redirect(url_for('homepage'))  # Redirect to homepage or other page
        else:
            flash('Incorrect password. Please try again.', 'danger')

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    flash('You have been logged out successfully.', 'success')  # Flash a success message
    return redirect(url_for('homepage'))  # Redirect to homepage or login page


# Secret key for JWT (make sure it's secure)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change to a secure key

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token to get the user_id
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
        user = UserInfo.query.get(user_id)

        if request.method == 'POST':
            new_password = request.form['new_password']
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been reset successfully. You can log in now.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)  # Render a template for resetting password

    except jwt.ExpiredSignatureError:
        flash('The reset link has expired. Please request a new one.', 'danger')
    except jwt.InvalidTokenError:
        flash('Invalid reset link. Please request a new one.', 'danger')

    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    user = UserInfo.query.filter_by(email=email).first()
    
    if user:
        # Generate a secure token for the user
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        # Create the reset link with the actual token
        reset_link = url_for('reset_password', token=token, _external=True)

        # Create the email message
        msg = Message(
            'Password Reset Request',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        msg.body = f'Please click the link to reset your password: {reset_link}'

        try:
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
        except Exception as e:
            flash('An error occurred while sending the email. Please try again later.', 'danger')
            print(f'Error sending email: {e}')
    else:
        flash('No account found with that email address.', 'danger')

    return redirect(url_for('login'))


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

        # Generate a unique 12-character account ID only if the user is not an admin
        account_id = None
        if access_type.lower() != 'admin':  # Assuming 'admin' is the access type for admin users
            account_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

        # Create a new UserInfo object
        new_user = UserInfo(
            account_id=account_id,  # Set account_id to None if the user is an admin
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

        # Flash a success message
        if account_id:
            flash(f'Registration successful! Your account ID is {account_id}. Please log in.', 'success')
        else:
            flash('Registration successful! You can log in as an admin.', 'success')

        return redirect(url_for('login'))

    return render_template('register.html')


from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/atm', methods=['GET', 'POST'])
def atm():
    user_id = session.get('user_id')  # Get the logged-in user's user_id from the session
    if not user_id:
        flash('You must be logged in to access the ATM page.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user = UserInfo.query.filter_by(user_id=user_id).first()  # Get user info
    
    if user.atm_pin is None:
        # If no ATM PIN is set, show the option to create one
        if request.method == 'POST':
            pin = request.form.get('atm_pin')
            if len(pin) == 4 and pin.isdigit():
                user.atm_pin = generate_password_hash(pin)  # Encrypt the PIN
                db.session.commit()
                flash("ATM PIN set successfully!", 'success')
                return redirect(url_for('atm'))  # Redirect to ATM page after setting PIN
            else:
                flash("Please enter a valid 4-digit PIN.", 'danger')
        
        return render_template('atm.html', user=user, create_pin=True)
    
    # If ATM PIN is set, allow user to perform ATM actions
    if request.method == 'POST':
        entered_pin = request.form.get('entered_pin')
        if check_password_hash(user.atm_pin, entered_pin):  # Validate entered PIN
            action = request.form.get('action')
            amount = request.form.get('amount', 0)

            # Convert the amount to a decimal to prevent type issues
            amount = Decimal(amount)  # Convert amount to Decimal

            if action == 'savings' and amount > 0:
                # Deposit action
                user.balance += amount  # Add amount to balance
                new_transaction = Transactions(
                    user_id=user.user_id,
                    transaction_type='deposit',
                    amount=amount
                )
                db.session.add(new_transaction)
                db.session.commit()
                flash(f"${amount} added to your savings account.", 'success')
                return redirect(url_for('atm'))  # Redirect to ATM page

            elif action == 'withdraw' and amount > 0:
                # Withdraw action with balance check
                if amount <= user.balance:
                    user.balance -= amount  # Subtract amount from balance
                    new_transaction = Transactions(
                        user_id=user.user_id,
                        transaction_type='withdraw',
                        amount=amount
                    )
                    db.session.add(new_transaction)
                    db.session.commit()
                    flash(f"${amount} withdrawn from your account.", 'success')
                    return redirect(url_for('atm'))  # Redirect to ATM page
                else:
                    flash("Insufficient balance.", 'danger')
        else:
            flash("Incorrect PIN.", 'danger')

    return render_template('atm.html', user=user, create_pin=False)

from sqlalchemy import text

from sqlalchemy import text

from flask_mail import Message
from flask import current_app

@app.route('/account_details', methods=['GET', 'POST'])
def account_details():
    user_id = session.get('user_id')  # Get the logged-in user's ID from the session
    
    if not user_id:
        flash('You must be logged in to view account details.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    # Retrieve user details from the database
    user = UserInfo.query.get(user_id)
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if user not found
    
    # Fetch the loan details associated with the user
    loans = Loan.query.filter_by(user_id=user_id).all()  # Fetch all loans for the logged-in user

    # Fetch the deposit details associated with the user
    deposits = Deposit.query.filter_by(user_id=user.user_id).all()  # Fetch all deposits for the logged-in user
    
    # Implement pagination for transaction history (10 per page)
    page = request.args.get('page', 1, type=int)
    transactions = Transactions.query.filter_by(user_id=user_id) \
        .order_by(Transactions.timestamp.desc()) \
        .paginate(page=page, per_page=10, error_out=False)

    # Handle POST request when "Show Account Summary" button is clicked
    account_summary = []
    if request.method == 'POST':
        try:
            # Call the stored procedure to get the account summary
            result = db.session.execute(
                text("CALL get_account_summary(:user_id)"),
                {'user_id': user_id}
            )
            account_summary = result.fetchall()  # Fetch all rows returned by the stored procedure

            # Format account summary for email
            summary_html = "<h3>Account Summary</h3><table border='1'><tr><th>Account ID</th><th>Type of Account</th><th>Final Amount</th></tr>"
            for account in account_summary:
                summary_html += f"<tr><td>{account[1]}</td><td>{account[2]}</td><td>${float(account[3]):.2f}</td></tr>"
            summary_html += "</table>"

            # Create the email message
            msg = Message(
                'Your Account Summary',
                sender=current_app.config['MAIL_DEFAULT_SENDER'],  # Sender's email from config
                recipients=[user.email]  # Recipient is the logged-in user's email
            )
            msg.html = summary_html  # Set the email body with the HTML formatted account summary
            
            # Send the email
            mail.send(msg)

            flash('Account summary sent to your email.', 'success')

        except Exception as e:
            flash(f"Error fetching account summary: {str(e)}", 'danger')

    # Return the template with the necessary data
    return render_template('account_details.html', user=user, loans=loans, deposits=deposits, 
                           transactions=transactions, account_summary=account_summary)

import logging

logging.basicConfig(level=logging.ERROR)

from flask import request
@app.route('/pay_emi/<int:loan_id>', methods=['POST', 'GET'])
def pay_emi(loan_id):
    # Get the logged-in user's ID from session
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to pay EMI.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Retrieve user and loan details
    user = UserInfo.query.get(user_id)
    loan = Loan.query.get(loan_id)

    if not user or not loan:
        flash('Loan or user not found.', 'danger')
        return redirect(url_for('account_details'))  # Redirect to account details if not found

    # Ensure the loan is approved and there is an outstanding amount
    if loan.status != 'APPROVED' or loan.amount_due <= 0:
        flash('No pending EMI for this loan.', 'danger')
        return redirect(url_for('account_details'))  # Redirect if the loan is not approved or no amount due

    # Check if the user has enough balance to pay the EMI
    if user.balance < loan.emi:
        flash('Insufficient balance to pay EMI.', 'danger')
        return redirect(url_for('account_details'))  # Redirect if insufficient balance

    # Deduct the EMI from user's balance
    user.balance -= loan.emi
    # Deduct the EMI from the loan's amount due
    loan.amount_due -= loan.emi

    try:
        # Save the changes to the database
        db.session.commit()

        # Create a new transaction record for EMI payment
        transaction = Transactions(
            user_id=user_id,
            transaction_type='Pay EMI',
            amount=loan.emi,
            timestamp=datetime.utcnow()
        )
        db.session.add(transaction)
        db.session.commit()

        flash('EMI paid successfully!', 'success')

    except Exception as e:
        db.session.rollback()  # Rollback in case of any errors
        flash(f'Error occurred while processing payment: {e}', 'danger')
        print(f"Error: {e}")

    # Implement pagination for transaction history (10 per page)
    page = request.args.get('page', 1, type=int)
    transactions = Transactions.query.filter_by(user_id=user_id).paginate(page=page, per_page=10, error_out=False)

    # Fetch all loans for the logged-in user
    loans = Loan.query.filter_by(user_id=user_id).all()

    # Redirect to account details page with the transactions
    return render_template('account_details.html', user=user, loans=loans, transactions=transactions.items)



@app.route('/update_user', methods=['GET', 'POST'])
def update_user():
    user_id = session.get('user_id')  # Get the logged-in user's ID from the session
    
    if not user_id:
        flash('You must be logged in to update account details.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    user = UserInfo.query.get(user_id)  # Retrieve user details from the database

    if request.method == 'POST':
        # Retrieve form data
        user.first_name = request.form.get('first_name', user.first_name)
        user.middle_name = request.form.get('middle_name', user.middle_name)
        user.last_name = request.form.get('last_name', user.last_name)
        user.email = request.form.get('email', user.email)
        user.phone_number = request.form.get('phone_number', user.phone_number)
        user.city = request.form.get('city', user.city)
        user.state = request.form.get('state', user.state)
        user.pincode = request.form.get('pincode', user.pincode)
        user.address = request.form.get('address', user.address)
        
        db.session.commit()  # Commit the changes to the database
        flash('Your details have been updated successfully!', 'success')
        return redirect(url_for('account_details'))

    return render_template('update_user.html', user=user)


class Deposit(db.Model):
    __tablename__ = 'deposit'

    deposit_ID = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary Key
    account_id = db.Column(db.String(12), nullable=False, unique=True)  # Unique account_id
    final_amount = db.Column(db.Numeric(18, 2), nullable=False)  # Final deposit amount
    interest_rate = db.Column(db.Numeric(5, 2), nullable=False)  # Interest rate
    principal_amount = db.Column(db.Numeric(18, 2), nullable=False)  # Principal amount
    tenure = db.Column(db.Integer, nullable=False)  # Tenure
    created_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(IST))  # Timestamp of creation
    modified_at = db.Column(db.TIMESTAMP, default=lambda: datetime.now(IST), onupdate=lambda: datetime.now(IST))  # Timestamp for updates
    status = db.Column(db.String(20))
    # Foreign key to user_info table
    user_id = db.Column(db.Integer, db.ForeignKey('User_Info.user_id'))
    # Relationship to UserInfo table (optional, if you want easy access from Deposit to UserInfo)
    user = db.relationship('UserInfo', backref='deposits', lazy=True)

    def __repr__(self):
        return f'<Deposit {self.deposit_ID} - Account ID {self.account_id}>'

# Function to generate unique account IDs
import random
import string

def generate_account_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

# Flask route to handle deposit
from flask import render_template, request, redirect, url_for, flash, session

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    user_id = session.get('user_id')
    
    if not user_id:
        flash('You must be logged in to add a deposit.', 'danger')
        return redirect(url_for('login'))
    
    final_amount = None  # Initialize final_amount to None
    
    if request.method == 'POST':
        account_id = generate_account_id()  # Generate new account ID for deposit
        
        # Check if account_id already has an active deposit (unique check)
        existing_deposit = Deposit.query.filter_by(account_id=account_id).first()
        
        if existing_deposit:
            flash(f"Account {account_id} already has an active deposit.", 'danger')
            return redirect(url_for('deposit'))
        
        principal_amount = Decimal(request.form['principal_amount'])
        
        # Minimum deposit check
        if principal_amount < 1000:
            flash('The minimum deposit amount is 1000.', 'danger')
            return redirect(url_for('deposit'))
        
        # Convert interest_rate and tenure to Decimal
        interest_rate = Decimal(request.form['interest_rate'])  # Ensure interest_rate is Decimal
        tenure = Decimal(request.form['tenure'])  # Ensure tenure is Decimal
        
        # Calculate the final amount using compound interest formula
        final_amount = principal_amount * (1 + interest_rate / 100) ** (tenure / 12)
        
        # Create the Deposit entry
        new_deposit = Deposit(
            account_id=account_id,
            final_amount=final_amount,
            interest_rate=interest_rate,
            principal_amount=principal_amount,
            tenure=tenure,
            user_id=user_id  # Use the logged-in user's user_id
        )
        
        # Add the deposit record to the database
        db.session.add(new_deposit)
        db.session.commit()

        flash(f'Deposit added successfully! Final amount after tenure: {final_amount:.2f}', 'success')
        print(f"The calculated final amount is: {final_amount:.2f}")
        
        return redirect(url_for('deposit'))

    return render_template('deposit.html', final_amount=final_amount)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'jpg', 'jpeg'}

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/close_deposit/<int:deposit_id>', methods=['POST'])
def close_deposit(deposit_id):
    # Get the deposit record to retrieve the amount
    deposit = Deposit.query.get(deposit_id)
    
    if deposit:
        # Get the user associated with the deposit
        user = UserInfo.query.get(deposit.user_id)
        
        if user:
            # Update the user's balance
            user.balance += deposit.final_amount
            
            # Mark the deposit as closed (optional)
            deposit.status = 'closed'
            
            db.session.commit()  # Commit the changes to the database
            
            flash('Deposit closed successfully and balance updated!', 'success')
        else:
            flash('User not found.', 'error')
    else:
        flash('Deposit not found.', 'error')

    return redirect(url_for('account_details', user_id=deposit.user_id))


@app.route('/loan', methods=['GET', 'POST'])
def loan():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            flash('You must be logged in to apply for a loan.', 'danger')
            return redirect(url_for('login'))

        try:
            loan_amount = float(request.form['loan_amount'])
            tenure = int(request.form['tenure'])

            # Calculate interest rate based on tenure
            def calculate_interest_rate(tenure):
                if tenure == 12:
                    return 5
                elif tenure == 24:
                    return 7.5
                elif tenure == 36:
                    return 10
                elif tenure == 48:
                    return 12.5
                elif tenure == 60:
                    return 15
                return 0
            
            interest_rate = calculate_interest_rate(tenure)

            # Calculate EMI
            monthly_rate = (interest_rate / 100) / 12
            emi = (loan_amount * monthly_rate * (1 + monthly_rate) ** tenure) / ((1 + monthly_rate) ** tenure - 1)

            if 'documents' not in request.files:
                flash('Please upload required documents.', 'danger')
                return redirect(request.url)

            # Handle file upload and path generation
            documents = request.files.getlist('documents')
            document_paths = []
            for document in documents:
                if document.filename == '':
                    flash('No document selected', 'danger')
                    continue
                if not allowed_file(document.filename):
                    flash('Invalid file type. Only PDF, DOCX, and JPG are allowed.', 'danger')
                    continue
                document_filename = f"{str(uuid.uuid4())[:10]}_{document.filename}"
                document_path = os.path.join(app.config['UPLOAD_FOLDER'], document_filename)
                document.save(document_path)
                document_paths.append(document_path)

            if not document_paths:
                flash('At least one document is required.', 'danger')
                return redirect(request.url)

            document_paths_str = ','.join(document_paths)
            tracking_id = str(uuid.uuid4())[:10]

            # Create loan application
            new_loan = Loan(
                user_id=user_id,
                loan_amount=loan_amount,
                interest_rate=interest_rate,
                tenure=tenure,
                documents=document_paths_str,
                tracking_id=tracking_id,
                status=LoanStatus.PENDING.value,
                emi=emi,
                amount_due=loan_amount
            )

            db.session.add(new_loan)
            db.session.commit()
            flash('Your loan application has been submitted successfully.', 'success')
            return redirect(url_for('loan_confirmation', tracking_id=tracking_id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing loan application: {str(e)}', 'danger')
            print(f"Error: {e}")  # Log error to console for debugging
            return redirect(request.url)

    return render_template('loan.html')

@app.route('/loan-confirmation/<tracking_id>')
def loan_confirmation(tracking_id):
    return render_template('loan_confirmation.html', tracking_id=tracking_id)

@app.route('/admin')
def admin():
    user_id = session.get('user_id')  # Get the logged-in user's ID from the session

    if not user_id:
        flash('You must be logged in to access the admin dashboard.', 'danger')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user = UserInfo.query.get(user_id)  # Retrieve user details from the database

    if user.access_type.lower() != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('homepage'))  # Redirect to homepage if user is not admin

    return render_template('admin.html')  # Render the admin dashboard page

@app.route('/admin/manage_users')
def manage_users():
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')

    if not user_id or not is_admin:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('homepage'))  # Redirect to homepage if the user is not an admin

    users = UserInfo.query.all()  # Fetch all users
    return render_template('manage_users.html', users=users)

@app.route('/admin/view_transactions')
def view_transactions():
    user_id = session.get('user_id')
    user = UserInfo.query.get(user_id)

    # Check if the user is an admin
    if not user or user.access_type.lower() != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('homepage'))

    # Paginate transactions, showing 10 per page by default
    page = request.args.get('page', 1, type=int)
    transactions = Transactions.query.order_by(Transactions.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)

    # Render the transactions with pagination support
    return render_template('view_transactions.html', transactions=transactions)


@app.route('/admin/loans')
def manage_loans():
    # Check if the logged-in user is an admin
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    if not user_id or not is_admin:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('homepage'))  # Redirect if not an admin
    
    # Fetch all loan applications
    loans = Loan.query.order_by(Loan.created_at.desc()).all()
    return render_template('manage_loans.html', loans=loans)

@app.route('/admin/approve_loan/<int:loan_id>', methods=['POST'])
def approve_loan(loan_id):
    # Check admin authorization
    if not session.get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('homepage'))
    
    # Retrieve the loan and user information
    loan = Loan.query.get(loan_id)
    if loan:
        loan.status = LoanStatus.APPROVED.value
        db.session.commit()

        # Retrieve the user associated with the loan
        user = UserInfo.query.get(loan.user_id)
        
        # Add the loan amount to the user's balance
        if user:
            try:
                user.balance += loan.loan_amount  # Assuming 'balance' and 'amount' columns exist
                db.session.commit()
                
                # Send email notification to the user
                msg = Message(
                    'Loan Application Approved',
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[user.email]
                )
                msg.body = (f"Dear {user.first_name},\n\n"
                            f"Your loan application with tracking ID {loan.tracking_id} "
                            f"has been approved and the loan amount of {loan.amount} has been "
                            f"credited to your account balance.\n\nThank you for choosing our bank.")
                mail.send(msg)
                flash('Loan approved, amount credited, and notification email sent.', 'success')
            except Exception as e:
                db.session.rollback()  # Rollback if there's an error with the email
                flash(f'Loan approved and amount credited, but email notification failed: {e}', 'warning')
        else:
            flash('User associated with this loan could not be found.', 'danger')

    return redirect(url_for('manage_loans'))


@app.route('/admin/deny_loan/<int:loan_id>', methods=['POST'])
def deny_loan(loan_id):
    # Check admin authorization
    if not session.get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('homepage'))

    # Retrieve the loan and user information
    loan = Loan.query.get(loan_id)
    if loan:
        loan.status = LoanStatus.REJECTED.value
        db.session.commit()

        # Retrieve the user associated with the loan
        user = UserInfo.query.get(loan.user_id)
        
        # Send email notification to the user
        if user:
            try:
                msg = Message(
                    'Loan Application Denied',
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[user.email]
                )
                msg.body = (f"Dear {user.first_name},\n\n"
                            f"Your loan application with tracking ID {loan.tracking_id} "
                            f"has been denied. If you have any questions, please contact our support team.\n\n"
                            f"Thank you for choosing our bank.")
                mail.send(msg)
                flash('Loan denied, and notification email sent.', 'success')
            except Exception as e:
                flash(f'Loan denied, but email notification failed: {e}', 'warning')
        else:
            flash('User associated with this loan could not be found.', 'danger')

    return redirect(url_for('manage_loans'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'uploads'), filename)

# Route to view a user
@app.route('/view_user/<int:user_id>')
def view_user(user_id):
    user = UserInfo.query.get(user_id)
    
    if user:
        # Nested query to count the approved loans for this user
        approved_loan_count = db.session.query(func.count(Loan.loan_id)).filter(
            Loan.user_id == user_id,
            Loan.status == LoanStatus.APPROVED.value
        ).scalar() or 0

        # Aggregate query to calculate the total approved loan amount for this user
        total_approved_loan_amount = db.session.query(func.sum(Loan.amount_due)).filter(
            Loan.user_id == user_id,
            Loan.status == LoanStatus.APPROVED.value
        ).scalar() or 0

        # Nested query to get the average loan amount for this user
        average_loan_amount = db.session.query(func.avg(Loan.amount_due)).filter(
            Loan.user_id == user_id,
            Loan.status == LoanStatus.APPROVED.value
        ).scalar() or 0

        return render_template(
            'view_user.html', 
            user=user, 
            approved_loan_count=approved_loan_count,
            total_approved_loan_amount=total_approved_loan_amount,
            average_loan_amount=average_loan_amount
        )

    flash('User not found.', 'danger')
    return redirect(url_for('manage_users'))

# Route to delete a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = UserInfo.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(debug=True)
