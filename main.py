from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
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
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

# provide a user_loader callback
@login_manager.user_loader
def load_user(user_id): # The callback is supposed to reload the user object from the user ID stored in the session
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html")

#Register a new user and then redirect them to the secrets page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
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
        login_user(new_user)
        return redirect(url_for('secrets', name=request.form['name']))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first() # obtain the sqlalchemy user object
        if check_password_hash(pwhash=user.password, password=request.form.get('password')): # validate password
            login_user(user) # login the user, user should be an instance of our User class
            flash('Logged in successfully')
            return redirect(url_for('secrets', name=user.name))
    return render_template("login.html")

#Pass in the name to the template using jinja
@app.route('/secrets')
@login_required # add decorator to require a user to be logged in
def secrets():
    name = request.args.get('name')
    return render_template("secrets.html", name=name)


@app.route('/logout')
@login_required # add decorator to require a user to be logged in
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
