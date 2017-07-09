from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'SecretClubhousePassword'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'wall')

@app.route('/')
def index():
    if 'login' not in session:
        session['login'] = False

    if session['login']:
        return redirect('/forum')
    else:
        return render_template('index.html')

@app.route('/create', methods=['POST'])
def create():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    passwordconfirm = request.form['passwordconfirm']

    query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    data = { 'email': email }
    user = mysql.query_db(query, data)

    if len(user) > 0:
        flash('Account already created with this email, please login to continue using our forum.','errors')
        return redirect('/login')

    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
    errors = []
    if not EMAIL_REGEX.match(email):
    	errors.append('Invalid email format.')
        if len(email) < 1:
            errors.append('Email can not be blank.')
    elif len(first_name) < 3 or len(last_name) < 3:
        errors.append('Please provide at least one character for both first name and last name.')
    elif len(password) < 8:
        errors.append('Password must be at least eight characters long.')
    elif password != passwordconfirm:
            errors.append('Passwords must match.')
    for errors in errors:
	    flash(errors, 'errors')

    if len(errors) > 0:
        return render_template('index.html')
    else:
        pw_hash = bcrypt.generate_password_hash(password)
        query = "INSERT INTO users(first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
        data = { 'first_name': first_name, 'last_name': last_name, 'email': email, 'pw_hash': pw_hash }
        mysql.query_db(query, data)
        flash('Account created. Please log in to the forum!','success')
        return redirect('/login')

@app.route('/login')
def login():
 return render_template('login.html')

@app.route('/login_process', methods=['POST'])
def login_process():
    email = request.form['email']
    password = request.form['password']

    query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    data = { 'email': email }
    user = mysql.query_db(query, data)

    if len(user) > 0:
        user = user[0]
        if bcrypt.check_password_hash(user['pw_hash'], password):
            session['login'] = True
            session['first_name'] = user['first_name']
            session['last_name'] = user['last_name']
            session['user_id'] = user['id']
            return redirect('/forum')
        else:
            flash('Incorrect password.', 'errors')
            return render_template('login.html')
    else:
        flash('Account doesn\'t exist for this email, please create an account to continue using our forum.','errors')
        return render_template('login.html')

@app.route('/forum')
def success():
    query = "SELECT messages.id, CONCAT_WS(' ', users.first_name, users.last_name) as full_name, messages.message, messages.updated_at FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.id DESC"
    messages = mysql.query_db(query)

    query = "SELECT CONCAT_WS(' ', users.first_name, users.last_name) as full_name, comments.comment, comments.updated_at FROM users JOIN messages ON users.id = messages.user_id JOIN comments ON messages.id = comments.message_id ORDER BY comments.updated_at ASC"
    comments = mysql.query_db(query)

    return render_template('wall.html', comments=comments, messages = messages)

@app.route('/post', methods=['POST'])
def post():
    query = "INSERT INTO messages(user_id, message, created_at, updated_at) VALUES (:user_id, :content, NOW(), NOW())"
    data =  {
        'user_id': session['user_id'],
        'content': request.form.get('content')
        }

    mysql.query_db(query, data)

    return redirect('/forum')

@app.route('/reply/<id>', methods=['POST'])
def reply(id):
    query = "INSERT INTO comments(message_id, user_id, comment, created_at, updated_at) VALUES (:message_id, :user_id, :comment, NOW(), NOW())"
    data =  {
        'message_id': id,
        'user_id': session['user_id'],
        'comment': request.form.get('content')
        }
    mysql.query_db(query, data)
    return redirect('/forum')

@app.route('/logout')
def logout():
    session['login'] = False
    errors = []
    return redirect('/')

app.run(debug=True)
