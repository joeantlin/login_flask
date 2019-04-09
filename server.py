from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL      # import the function that will return an instance of a connection
from flask_bcrypt import Bcrypt
app = Flask(__name__)
import re

app.secret_key = 'keep it secret, keep it safe'

bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods = ["POST"])
def submit():
    is_valid = True
    if len(request.form["new_first"]) < 1:
        is_valid = False
        flash("Please enter a first name")
        print("Please enter a first name")
    if len(request.form["new_last"]) < 1:
        is_valid = False
        flash("Please enter a last name")
        print("Please enter a last name")
    if not EMAIL_REGEX.match(request.form["new_email"]):
        is_valid = False
        flash("Email is not Valid")
        print("Email is not Valid")

    if len(request.form["new_password"]) < 6:
        is_valid = False
        flash("Password must be at least 6 characters long.")
        print("Password must be at least 6 characters long.")
    elif request.form["new_password"] != request.form["con_password"]:
        is_valid = False
        flash("Passwords don't match")
        print("Passwords Don't Match")
    else:
        pw_hash = bcrypt.generate_password_hash(request.form["new_password"])
        print(pw_hash)

    if not is_valid:
        return redirect('/')
    else:
        data = {
            "fn": request.form["new_first"],
            "ln": request.form["new_last"],
            "em": request.form["new_email"],
            "pw": pw_hash
        }
        print("Data collected")
        session['name'] = data['fn'] + ' ' + data['ln']
        mysql = connectToMySQL('log_flask')
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES(%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW());"
        flash(f"You've been successfully registered")
        print("You've been successfully registered")
        new_account = mysql.query_db(query, data)
        return redirect('/success')

@app.route('/login', methods = ['POST'])
def login():
    mysql = connectToMySQL('log_flask')
    query = "SELECT * FROM users WHERE email = %(em)s"
    data = {
        "em": request.form["user_email"]
    }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        if bcrypt.check_password_hash(result[0]['password'], request.form['user_password']):
            session['name'] = result[0]['first_name'] + ' ' + result[0]['last_name']
            flash(f"You've been successfully registered")
            print("You've been successfully registered")
            return redirect('/success')
    flash("You could not be logged in")
    return redirect("/")

@app.route('/success')
def success():
    #mysql = connectToMySQL('log_flask')
    #the_emails = mysql.query_db('SELECT * FROM emails;')
    return render_template('success.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You've been successfully logged out")
    print("You've been successfully logged out")
    return redirect("/")

if __name__ =='__main__':
    app.run(debug=True)