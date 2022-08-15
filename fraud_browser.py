import json
from pyngrok import ngrok
import pandas as pd
import stripe
from flask import Flask, render_template, redirect, url_for, request, send_file
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
import sqlite3 as sql
from pandas import read_csv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = os.getenv('DB_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User class to create our User object
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))


# Create Database Variable
create_table = '''CREATE TABLE user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE ,
        password TEXT NULL
        )'''

# Checks to see if database exist, if not user creates database
if os.path.exists('users.db'):
    pass
else:
    try:
        conn = sql.connect('users.db')
        curs = conn.cursor()
        curs.execute(create_table)
        conn.commit()
        conn.close()
    finally:
        pass


# Loads our User by id in our SQL database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('fraud'))

    return render_template('login.html')


@app.route('/login_handler', methods=['GET', 'POST'])
def login_handler():
    if current_user.is_authenticated:
        return redirect(url_for('fraud'))

    usernames = request.form.get('username')
    print(usernames)
    pwd = request.form.get('password')
    print(pwd)

    user = User.query.filter_by(username=usernames).first()
    if user:
        if check_password_hash(user.password, pwd):
            login_user(user, remember=True)
            return redirect(url_for('fraud'))

        return '<h1>Invalid username or password!</h1>'

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    return render_template('signup.html')


@app.route('/signup_handler', methods=['GET', 'POST'])
def signup_handler():
    usernames = request.form.get('username')
    pwd = generate_password_hash(request.form.get('password'), method='sha256')
    new_user = User(username=usernames, password=pwd)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download_file():
    p = f"csvs/{current_user.username}_fingerprints.csv"
    return send_file(p,as_attachment=True)

@app.route('/test')
@login_required
def test():
    return render_template('test.html')


@app.route('/fraud', methods=['GET', 'POST'])
@login_required
def fraud():
    return render_template('fraud.html')


@app.route('/fraud_handler', methods=['GET', 'POST'])
@login_required
def fraud_handler():
    stripe.api_key = os.getenv('STRIPE_TOKEN')
    stripe.api_version = "2020-08-27"

    # Lists for caveman recursive searching
    spacelist = []
    checkedSpaces = []
    checkedPrints = []
    fingerprintlist = []
    finaldict = {}

    d = []

    def initsearch():
        # Takes a cc fingerprint via input
        firstprint = request.form.get('fingerprint')
        if len(firstprint) == 0:
            return
        # Create a querystring and search stripe for that query
        initquery = "payment_method_details.card.fingerprint:'" + firstprint + "'"
        firstList = stripe.Charge.search(query=initquery)
        # Proceeds with script if our stripe search returns data
        if len(firstList.data) != 0:
            # paginate the Stripe object returned from query and append every SPACE associated with the FINGERPRINT provided
            for space in firstList.auto_paging_iter():
                if len(space.metadata) != 0:
                    if space.metadata.space_id not in spacelist:
                        spacelist.append(space.metadata.space_id)
            # Call next function and pass a list of spaces
            fPrintRetriever(spacelist)
        else:
            return print("you stupid")

    def fPrintRetriever(Spaces):
        # For each space in our SpaceList
        for space in Spaces:
            # Ensure the space has not been checked, then add it to our CHECKED spaces list
            if space not in checkedSpaces:
                print('checking: ', space)
                checkedSpaces.append(space)

                # Build a new querystring that searches for the SPACE by metadata
                query = "metadata['space_id']:'" + space + "'"
                printsRetrieved = stripe.Charge.search(query=str(query))

                # add the space to our final dictionary and build an empty list
                finaldict[space] = []

                # for each charge in the space, paginate over the object and retrieve the CC fingerprint
                for fPrint in printsRetrieved.auto_paging_iter():
                    curPrint = fPrint.payment_method_details.card.fingerprint

                    # if the fingerprint is not associated to the space, associate it via our dictionary, AND add it to our FINGERPRINT list
                    if curPrint not in finaldict[space]:
                        fingerprintlist.append(curPrint)
                        finaldict[space].append(curPrint)

        # if our FINGERPRINT list is longer than our CHECKED fingerprints, we have more fingerprints to search
        if len(fingerprintlist) > len(checkedPrints):
            spaceRetriever(fingerprintlist)

    def spaceRetriever(fPrintList):

        # For each FINGERPRINT in our list, ensure we have not checked that fingerprint
        for fPrint in fPrintList:
            if fPrint not in checkedPrints:

                # Add the fingerprint to our CHECKED list
                checkedPrints.append(fPrint)

                # Build a new querystring to search the fingerprints
                printQuery = "payment_method_details.card.fingerprint:'" + fPrint + "'"
                spacesRetrieved = stripe.Charge.search(query=str(printQuery))

                # For each charge associated with that fingerprint, paginate over the object and retrieve the SPACE metadata
                for space in spacesRetrieved.auto_paging_iter():

                    # IF the space metadata is not in our SPACE list, add it
                    if len(space.metadata) != 0:
                        if space.metadata.space_id not in spacelist:
                            spacelist.append(space.metadata.space_id)

        # IF our space list is longer than our CHECKED spaces list, we have more searches to make
        if len(spacelist) > len(checkedSpaces):
            fPrintRetriever(spacelist)

    # Starts our initial search and prints the final dictionary when we exhaust all SPACES and FINGERPRINTS associated with the origin FINGERPRINT
    initsearch()
    for space in finaldict:
        d.append(("https://internal.signalwire.com/spaces/" + space, finaldict[space]))
        print("https://internal.signalwire.com/spaces/" + space, finaldict[space])
    user_name = current_user
    df = pd.DataFrame(d, columns=('Space', 'fingerprint'))
    df.to_csv(f'csvs/{user_name.username}_fingerprints.csv', index=False, encoding='utf-8')
    return results(user_name)


@app.route('/results', methods=['GET', 'POST'])
@login_required
def results(user_name):
    # converting csv to html
    data = pd.read_csv(f'csvs/{user_name.username}_fingerprints.csv')
    users = User.query
    user_cvs = read_csv(f"csvs/{user_name.username}_fingerprints.csv")
    usercsv = user_cvs.to_json()
    usercsv = json.loads(usercsv)
    print(usercsv['Space'])
    return render_template('results.html', tables=[data.to_html()], titles=[''], users=users, json=usercsv)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Set the ngrok URL as the webhook for our SW phone
def start_ngrok():
    # Set up a tunnel on port 5000 for our Flask object to interact locally
    url = ngrok.connect(5000).public_url
    print(' * Tunnel URL:', url)


if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        start_ngrok()
    app.run(debug=True)
