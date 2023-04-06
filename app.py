import os
import yaml
import MySQLdb.cursors
from flask_mysqldb import MySQL
import base64
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, g, request, \
    abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode
from datetime import timedelta

# create application instance
app = Flask(__name__)
app.config.from_object('config')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.secret_key =os.urandom(24)
#configuring the mysql db
db=yaml.load(open('db.yaml'))
app.config['MYSQL_HOST']= db['mysql_host']
app.config['MYSQL_USER']= db['mysql_user']
app.config['MYSQL_PASSWORD']= db['mysql_password']
app.config['MYSQL_DB']= db['mysql_db']
# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
mysql=MySQL(app)
#add a comment

#----------------------------------------------------
#-----the real deal....performs this action every time any request is made
@app.before_request
def before_request():
    g.type=None
    g.loggedin= None
    g.id=None
    g.email=None
    g.Fname=None
    if 'loggedin' in session:
        g.type=session['type']
        g.loggedin= session['loggedin']
        g.id=session['id']
        g.email=session['email']
        g.Fname=session['Fname']

def MergeDicts(dict1,dict2):
    if isinstance(dict1,list) and isinstance(dict2,list):
        return dict1 + dict2
    elif isinstance(dict1,dict) and isinstance(dict2,dict):
        return dict(list(dict1.items()) + list(dict2.items()))
    return False

class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))


    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-DCMNT:{0}?secret={1}&issuer=2FA-DCMNT' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm,):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(min=3, max=20)], render_kw={'style': 'width: 30rem;'})
    password = PasswordField('Password', validators=[Required(), Length(min=8, max=64)], render_kw={'style': 'width: 30rem;'})
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')], render_kw={'style': 'width: 30rem;'})
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(min=3, max=20)], render_kw={'style': 'width: 25rem; margin-left: 0rem;'})
    password = PasswordField('Password', validators=[Required(), Length(min=8, max=64) ], render_kw={'style': 'width: 25rem; margin-left: 0rem;'})
    token = StringField('Token', validators=[Required(), Length(6)], render_kw={'style': 'width: 25rem; margin-left: 0rem;'})
    submit = SubmitField('Login', render_kw={'style': 'width: 10rem; margin-left: 15rem'})


@app.route('/')
def about():
    return render_template('about.html')

@app.route('/admin/index')
def index():
    if not g.type=='admin':
        return redirect('/admin/login')
    return render_template('index.html')

@app.route('/admins')
def admins():
    return render_template('admin.html')

#-----------------------------------------------------------------
#---------------------ADMIN PAGE----------------------------------
#-----------------------------------------------------------------
@app.route('/admin/login', methods=['GET','POST'])
def adminLogin():
    msg=''
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']
        cur=mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute('SELECT * FROM admin WHERE email = %s AND password=%s', (email,password))
        account = cur.fetchone()
        cur.close()
        if account:
            session['type']='admin'
            session['loggedin'] = True
            session['id'] = account['id']
            session['email'] = account['email']
            session['Fname']=account['Fname']
            return redirect('/admin')
        else:
            msg='incorrect email/password'
    return render_template('logins.html',msg=msg)

@app.route('/admin')
def admin():
    if not g.type=='admin':
        return redirect('/admin/login')
    #cur=mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #cur.execute('SELECT * FROM shop')
    #shop = cur.fetchall()
    #cur.close()
    #Fname=g.Fname
    return render_template('index.html')

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if not g.type=='admin':
        return redirect('/admin/login')
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('about'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('about'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('about'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.permanent = True
    """User login route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('about'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('about'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    session.clear()
    logout_user()
    return redirect(url_for('about'))


# create database tables if they don't exist yet
db.create_all()

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8086, debug=True)
