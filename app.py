from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from functools import wraps
from bson import ObjectId
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['user_identification_system']
users_collection = db['users']
notes_collection = db['notes']

def calculate_profile_completion(user_data):
    total_fields = 6
    filled_fields = 0
    if user_data.get("first_name"):
        filled_fields += 1
    if user_data.get("last_name"):
        filled_fields += 1
    if user_data.get("email"):
        filled_fields += 1
    if user_data.get("mobile"):
        filled_fields += 1
    if user_data.get("dob"):
        filled_fields += 1
    if user_data.get("address"):
        filled_fields += 1
    completion_percentage = (filled_fields / total_fields) * 100
    return completion_percentage
@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        flash('Please log in to access your notes.')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        # Get the note content from the form - changed from note_content to notes
        note_content = request.form.get('notes')  # Changed to match the form field name

        # Update or create a new note for the user
        notes_collection.update_one(
            {'user_id': user_id},
            {'$set': {
                'content': note_content,
                'last_updated': datetime.now()
            }},
            upsert=True
        )

        flash('Note saved successfully!', 'success')
        return redirect(url_for('notes'))

    # Retrieve the user's note if it exists
    user_note = notes_collection.find_one({'user_id': user_id})
    note_content = user_note.get('content', "") if user_note else ""  # Added .get() with default value

    # Retrieve user profile data from the database
    user_data = users_collection.find_one({'_id': ObjectId(user_id)}, {
        "first_name": 1,
        "last_name": 1,
        "email": 1,
        "mobile": 1,
        "dob": 1,
        "address": 1
    }) or {}

    # Calculate profile completion
    completion_percentage = calculate_profile_completion(user_data)

    # Pass note content and completion percentage to the template
    return render_template('notes.html', note_content=note_content, completion_percentage=completion_percentage)

# Configure upload folder
UPLOAD_FOLDER = 'static/profile_photos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    is_authenticated = 'user_id' in session
    if is_authenticated:
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        return render_template('home.html', is_authenticated=True, user=user)
    return render_template('home.html', is_authenticated=False)
from datetime import datetime
from werkzeug.security import generate_password_hash

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        email = request.form.get('email')
        password = request.form.get('password')
        mobile = request.form.get('mobile')
        dob = request.form.get('dob')
        address = request.form.get('address')

        # Calculate age if dob is provided
        age = None
        if dob:
            dob_date = datetime.strptime(dob, '%Y-%m-%d')
            today = datetime.today()
            age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))

        if users_collection.find_one({'email': email}):
            flash('You already have an account. Please log in.', 'warning')
            return redirect(url_for('signup'))

        profile_photo = request.files.get('profilePhoto')
        profile_photo_data = None

        if profile_photo and allowed_file(profile_photo.filename):
            profile_photo_data = base64.b64encode(profile_photo.read()).decode('utf-8')

        new_user = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': generate_password_hash(password),
            'mobile': mobile,
            'dob': dob,
            'age': age,
            'address': address,
            'profile_photo': profile_photo_data
        }

        result = users_collection.insert_one(new_user)
        session['user_id'] = str(result.inserted_id)
        
        flash('Account created successfully!')
        return redirect(url_for('home'))

    return render_template('signup.html')


    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        
        flash('Invalid email or password')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('profile.html', user=user)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    first_name = request.form.get('firstName')
    last_name = request.form.get('lastName')
    email = request.form.get('email')
    mobile = request.form.get('mobile')
    dob = request.form.get('dob')
    address = request.form.get('address')

    # Calculate age
    dob_date = datetime.strptime(dob, '%Y-%m-%d')
    today = datetime.today()
    age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))

    profile_photo = request.files.get('profilePhoto')
    profile_photo_data = user['profile_photo']  # Keep the current photo if no new photo is uploaded

    if profile_photo and allowed_file(profile_photo.filename):
        profile_photo_data = base64.b64encode(profile_photo.read()).decode('utf-8')

    # Update user profile in the database
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "mobile": mobile,
                "dob": dob,
                "age": age,
                "address": address,
                "profile_photo": profile_photo_data
            }
        }
    )

    flash("Profile updated successfully!")
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)