"""My 'Secrets' website

This 'Flask' app creates a 'Secrets' website that the user can download a secret 'Flask cheat sheet' file
provided that they register with the website first. The website allows users to register and secures their
passwords by hashing and salting their passwords. The 'secrets' route can only be accessed
when the user is logged in.

This script requires that 'Flask', 'Flask-SQLAlchemy', 'werkzeug'
be installed within the Python
environment you are running this script in.
"""

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

login_manager = LoginManager() # Create the LoginManager class
login_manager.init_app(app) # Configure your actual application object for login

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model): # Inherit User Mixin in User Class
    """
    A class used to represent a user in the users table.
    ...
    Attributes
    ----------
    id: db.Column
        an integer column representing the primary key
    email: db.Column
        a string column representing the email of the user
    password: db.Column
        a string column representing the password of the user
    name: db.Column
        a string column representing the name of the user
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


#Line below only required once, when creating DB. 
# db.create_all()


# provide a user_loader callback
@login_manager.user_loader
def load_user(user_id): # The callback is supposed to reload the user object from the user ID stored in the session
    """a user_loader call back function that returns the current logged in user from the Users table

    Parameters:
    -----------
    user_id: int
        the id of the user that is currently logged in

    Returns:
    --------
        the user object representing the user that is currently logged in
    """
    return User.query.get(user_id) # it is supposed to return the User object for a particular user_id
                                    # not exactly sure how this method works to be honest but since the docs said it's
                                    # supposed to return our user object, then I tried this


@app.route('/')
def home():
    """the landing page for the website

    GET: the landing page
    """
    return render_template("index.html")


#Register a new user and then redirect them to the secrets page
@app.route('/register', methods=['GET', 'POST'])
def register():
    """the web page that allows the user to register an account with the website

    GET: displays a form for the user to register their account to the website
    POST: requests to add the user to the database, redirects to the 'secrets' page
    """
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first(): # Checks if a User exists with an email
            flash('You\'ve already registered your email. Please try signing in.')
            return redirect('login')
        new_user = User(
            email=request.form['email'],
            name=request.form['name'],
            password=generate_password_hash(
                password=request.form['password'],
                method='pbkdf2:sha256',
                salt_length=8
            )
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user) # login the user, user should be an instance of our User class
        return redirect(url_for('secrets', name=request.form['name']))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """displays a webpage to allow the user to login if they have previously registered

    GET: displays a form for the user to login to the website
    POST: requests to log the user in to the website, redirects to the login page if the login information was incorrect.
            redirects to the secrets page if the user logged in successfully.
    """
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first() # obtain the sqlalchemy user object
        if user is None:
            flash('That email does not exist, please try again.') # Add this flash message if the email doesnt exist
            return redirect(url_for('login')) # The flash message will appear in the next request to this template
        if check_password_hash(pwhash=user.password, password=request.form.get('password')): # validate password
            login_user(user) # login the user, user should be an instance of our User class
            flash('Logged in successfully')
            return redirect(url_for('secrets', name=user.name))
        else:
            flash('Password incorrect. Please try again.') # If the email exists, and the password was wrong, flash
            return redirect(url_for('login'))
    return render_template("login.html")


#Pass in the name to the template using jinja
@app.route('/secrets')
@login_required # add decorator to require a user to be logged in
def secrets():
    """web page that allows the user to download the secret file after logging in

    GET: web page that allows the user to download the secret file after logging in
    """
    name = request.args.get('name')
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    """allows the user to log out of the website

    GET: logs the user out, redirects to the landing page
    """
    logout_user() # log out the current user
    return redirect(url_for('home'))


@app.route('/download')
@login_required # add decorator to require a user to be logged in
def download():
    """starts the download of the secret file for the user

    GET: starts the download of the secret file for the user
    """
    return send_from_directory(directory='static', filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
