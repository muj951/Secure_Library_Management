from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import logging
from functools import wraps
import os
import secrets
import random
import re

# Initialize Flask and basic security controls
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32)) # NOSONAR
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False) 
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default='User')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    is_available = db.Column(db.Boolean, default=True) # NEW: Tracks if the book is in stock

class BorrowRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Librarian':
            logging.warning(f"Unauthorized access attempt by {current_user.email if current_user.is_authenticated else 'Anonymous'}")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- SECURE ROUTES ---

@app.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not first_name or not last_name or not email or not password:
            flash('All fields are required.')
            return redirect(url_for('register'))
            
        # FIX: Defense in Depth - Validate email format to block malicious payloads
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash('Please enter a valid email address format.')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        new_user = User(first_name=first_name, last_name=last_name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        logging.info(f"New user registered: {email}")
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email') 
        password = request.form.get('password')
        
        # 1. Defense in Depth: Validate email format FIRST
        if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash('Please enter a valid email address format.')
            return redirect(url_for('login'))
            
        # 3. NOW it is safe to query the database
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            logging.info(f"User logged in: {email}")
            return redirect(url_for('dashboard'))
        
        logging.warning(f"Failed login attempt for email: {email}")
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- CORE APPLICATION LOGIC ---

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    search_query = request.args.get('q', '')
    edit_id = request.args.get('edit_id')
    
    if search_query:
        books = Book.query.filter(
            (Book.title.ilike(f'%{search_query}%')) | 
            (Book.category.ilike(f'%{search_query}%'))
        ).all()
    else:
        books = Book.query.all()
        
    admin_requests = []
    my_requests = []
    
    if current_user.role == 'Librarian':
        admin_requests = db.session.query(BorrowRequest, User.email, Book.title)\
            .join(User, BorrowRequest.user_id == User.id)\
            .join(Book, BorrowRequest.book_id == Book.id)\
            .filter(BorrowRequest.status == 'Pending').all()
    else:
        my_requests = db.session.query(BorrowRequest, Book.title)\
            .join(Book, BorrowRequest.book_id == Book.id)\
            .filter(BorrowRequest.user_id == current_user.id).all()

    return render_template('dashboard.html', books=books, search_query=search_query, 
                           admin_requests=admin_requests, my_requests=my_requests, edit_id=edit_id)

@app.route('/add_book', methods=['POST'])
@login_required
@admin_required
def add_book():
    title = request.form.get('title')
    category = request.form.get('category')
    
    if not title or not category:
        flash('Title and category are required.')
        return redirect(url_for('dashboard'))
        
    new_book = Book(title=title, category=category, is_available=True)
    db.session.add(new_book)
    db.session.commit()
    
    logging.info(f"Book added by admin {current_user.email}: {title}")
    flash('Book added successfully!')
    return redirect(url_for('dashboard'))

@app.route('/edit_book/<int:book_id>', methods=['POST'])
@login_required
@admin_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    title = request.form.get('title')
    category = request.form.get('category')
    
    if not title or not category:
        flash('Title and category are required.')
        return redirect(url_for('dashboard', edit_id=book.id))
        
    book.title = title
    book.category = category
    db.session.commit()
    
    logging.info(f"Book updated by admin {current_user.email}: ID {book.id}")
    flash('Book updated successfully!')
    return redirect(url_for('dashboard'))

@app.route('/delete_book/<int:book_id>', methods=['POST'])
@login_required
@admin_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    BorrowRequest.query.filter_by(book_id=book.id).delete()
    db.session.delete(book)
    db.session.commit()
    
    logging.info(f"Book deleted by admin {current_user.email}: {book.title}")
    flash(f'Book "{book.title}" has been deleted.')
    return redirect(url_for('dashboard'))

@app.route('/borrow/<int:book_id>', methods=['POST'])
@login_required
def borrow_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    if not book.is_available:
        flash('This book is currently checked out.')
        return redirect(url_for('dashboard'))
        
    # FIX: Only block if the user already has a Pending or Approved request for this book
    existing_request = BorrowRequest.query.filter(
        BorrowRequest.user_id == current_user.id,
        BorrowRequest.book_id == book.id,
        BorrowRequest.status.in_(['Pending', 'Approved'])
    ).first()
    
    if existing_request:
        flash('You already have a pending or approved request for this book.')
        return redirect(url_for('dashboard'))
        
    new_request = BorrowRequest(user_id=current_user.id, book_id=book.id)
    db.session.add(new_request)
    db.session.commit()
    
    logging.info(f"Borrow request by {current_user.email} for book ID {book.id}")
    flash(f'Successfully requested to borrow: {book.title}')
    return redirect(url_for('dashboard'))

# NEW ROUTE: Allow users to return books
@app.route('/return_book/<int:req_id>', methods=['POST'])
@login_required
def return_book(req_id):
    req = BorrowRequest.query.get_or_404(req_id)
    
    # Security check: Ensure the user returning it actually made the request
    if req.user_id != current_user.id:
        abort(403)
        
    # Mark request as returned
    req.status = 'Returned'
    
    # Mark the book as available in the library again
    book = Book.query.get(req.book_id)
    if book:
        book.is_available = True
        
    db.session.commit()
    logging.info(f"Book {book.id} returned by user {current_user.email}")
    flash('Book returned successfully! Thank you.')
    return redirect(url_for('dashboard'))

@app.route('/approve/<int:req_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(req_id):
    req = BorrowRequest.query.get_or_404(req_id)
    req.status = 'Approved'
    
    # NEW: Mark the book as checked out!
    book = Book.query.get(req.book_id)
    if book:
        book.is_available = False
        
    db.session.commit()
    logging.info(f"Request {req_id} approved by {current_user.email}")
    flash('Request approved and book marked as checked out.')
    return redirect(url_for('dashboard'))

@app.route('/reject/<int:req_id>', methods=['POST'])
@login_required
@admin_required
def reject_request(req_id):
    req = BorrowRequest.query.get_or_404(req_id)
    req.status = 'Rejected'
    db.session.commit()
    logging.info(f"Request {req_id} rejected by {current_user.email}")
    flash('Request rejected.')
    return redirect(url_for('dashboard'))

# --- DAST SECURITY FIXES: Adding global HTTP security headers ---
@app.after_request
def apply_security_headers(response):
    # Fix 1: Missing Anti-clickjacking Header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Fix 2: X-Content-Type-Options Header Missing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Fix 3: Content Security Policy (Basic)
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(email='admin@library.local').first():
            admin = User(first_name='Admin', last_name='System', email='admin@library.local', role='Librarian')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)