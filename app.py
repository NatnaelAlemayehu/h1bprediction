from flask import Flask,render_template,Response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

import numpy as np
import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.linear_model import LogisticRegression
# from sklearn.metrics import confusion_matrix, classification_report
# from statistics import mode
# import re
# from xgboost import XGBClassifier

app=Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_usernmae(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class h1bForm(FlaskForm):
    companychoices = [
        ('gth inc.','gth inc.'),
        ('umbel corp', 'umbel corp'),
        ('quicklogix, inc.', 'quicklogix, inc.'),
        ('westfield corporation', 'westfield corporation'),
        ('mcchrystal group, llc', 'mcchrystal group, llc'),
        ('quicklogix llc', 'quicklogix llc'),
        ('vricon, inc.', 'vricon, inc.'),
        ('burger king corporation', 'burger king corporation'),
        ('goodman networks, inc.', 'goodman networks, inc.'),
        ('university of michigan', 'university of michigan'),
        ('cardiac science corporation', 'cardiac science corporation'),
        ('mcchrystal group, llc', 'mcchrystal group, llc'),
        ('sensorhound, inc.', 'sensorhound, inc.'),
        ('pronto general agency, ltd.', 'pronto general agency, ltd.'),
        ('natural american foods inc.', 'natural american foods inc.'),
        ('parallels, inc.', 'parallels, inc.'),
        ('rancho la puerta llc', 'rancho la puerta llc')       
    ]

    occupationchoices = [
        ('computer occupations','computer occupations'),
        ('Mathematical Occupations','Mathematical Occupations'),
        ('Education Occupations','Education Occupations'),
        ('Medical Occupations','Medical Occupations'),
        ('Management Occupation','Management Occupation'),
        ('Marketing Occupation','Marketing Occupation'),
        ('Financial Occupation','Financial Occupation'),
        ('Architecture & Engineering','Architecture & Engineering')       
    ]
    jobtype = SelectField(u'Full time job?', choices=[('1', 'Yes'), ('0', 'No')])
    companyname = SelectField(u'Company', choices=companychoices)   
    occupationcategory = SelectField(u'Category?', choices=occupationchoices)
    prevailingwage = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "prevailing wage"})
    
    submit = SubmitField("Make prediction")



@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('videopage'))
    return render_template('login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('h1b'))
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():  
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():   
    logout_user()
    return redirect(url_for('login')) 


@app.route('/h1b', methods=['GET', 'POST'])
@login_required
def videopage():
    form = h1bForm()
    global result
    result = ""
    if form.validate_on_submit():
       result = 'Result: you are likely to be rejected!'        

    return render_template('h1b.html', form=form, modelresult=result)


if __name__=="__main__":
    app.run(debug=True)

