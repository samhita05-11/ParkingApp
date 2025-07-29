import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'samhitasiddamshetty'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bookings = db.relationship('Booking', backref='user', lazy=True, cascade="all, delete")

class ParkingLot(db.Model):
    __tablename__ = 'parking_lots'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    price_per_hour = db.Column(db.Float, nullable=False)
    spots = db.relationship('ParkingSpot', backref='lot', lazy=True, cascade="all, delete-orphan")

class ParkingSpot(db.Model):
    __tablename__ = 'parking_spots'
    id = db.Column(db.Integer, primary_key=True)
    spot_number = db.Column(db.String(20), nullable=False)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lots.id'), nullable=False)
    is_occupied = db.Column(db.Boolean, default=False)
    
class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spots.id'), nullable=False)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lots.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    total_cost = db.Column(db.Float, nullable=True)
    spot = db.relationship('ParkingSpot', backref=db.backref('booking', uselist=False))
    lot = db.relationship('ParkingLot', backref='bookings')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)