# app/routes/auth.py
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import mongo, limiter
from datetime import datetime
import pyotp
from bson import ObjectId

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if user exists
        if mongo.db.users.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 400

        # Create user
        user = {
            'email': data['email'],
            'password': generate_password_hash(data['password']),
            'mfa_secret': pyotp.random_base32(),
            'mfa_enabled': False,
            'created_at': datetime.utcnow(),
            'last_login': None,
            'status': 'active'
        }
        
        mongo.db.users.insert_one(user)
        
        return jsonify({
            'message': 'Registration successful',
            'email': user['email']
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400

        user = mongo.db.users.find_one({'email': data['email']})
        
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401

        # Check if MFA is enabled
        if user.get('mfa_enabled'):
            temp_token = create_access_token(
                identity=str(user['_id']),
                expires_delta=timedelta(minutes=5)
            )
            return jsonify({
                'message': 'MFA required',
                'require_mfa': True,
                'temp_token': temp_token
            }), 200

        # Update last login
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Create access token
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'email': user['email'],
                'id': str(user['_id'])
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/verify-mfa', methods=['POST'])
@jwt_required()
def verify_mfa():
    try:
        data = request.get_json()
        user_id = get_jwt_identity()
        
        if not data or not data.get('token'):
            return jsonify({'error': 'MFA token is required'}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404

        totp = pyotp.TOTP(user['mfa_secret'])
        if not totp.verify(data['token']):
            return jsonify({'error': 'Invalid MFA token'}), 401

        # Update last login
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Create new access token
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'email': user['email'],
                'id': str(user['_id'])
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500