import os
import json
import pandas as pd
from pyngrok import ngrok
from dotenv import load_dotenv
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, logout_user, current_user, login_user
from flask import Flask, render_template, redirect, url_for, request, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import stripe

STRIPE_API_VERSION = "2020-08-27"

load_dotenv()
os.chdir(os.path.dirname(os.path.abspath(__file__)))

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'users.db')

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = os.getenv('DB_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
session = db.session

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('fraud'))
    return render_template('login.html')


@app.route('/login_handler', methods=['POST'])
def login_handler():
    if current_user.is_authenticated:
        return redirect(url_for('fraud'))

    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user, remember=True)
        return redirect(url_for('fraud'))

    return '<h1>Invalid username or password!</h1>', 401


@app.route('/signup_handler', methods=['POST'])
def signup_handler():
    username = request.form.get('username')
    password = generate_password_hash(request.form.get('password'), method='scrypt')

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download_file():
    p = f"csvs/{current_user.username}_fingerprints.csv"
    return send_file(p, as_attachment=True)


@app.route('/fraud', methods=['GET', 'POST'])
@login_required
def fraud():
    return render_template('fraud.html')


@app.route('/fraud_handler', methods=['GET', 'POST'])
@login_required
def fraud_handler():
    stripe.api_key = os.getenv('STRIPE_TOKEN')
    stripe.api_version = STRIPE_API_VERSION

    # Use sets for faster existence checking
    spaces = set()
    checked_spaces = set()
    fingerprints = set()
    checked_fingerprints = set()

    final_dict = {}

    def search_and_retrieve(space_id=None, fingerprint=None):
        if space_id is not None:
            query = f"metadata['space_id']:'{space_id}'"
        else:  # If space_id is not provided, fingerprint must be
            query = f"payment_method_details.card.fingerprint:'{fingerprint}'"

        charge_list = stripe.Charge.search(query=query)

        for charge in charge_list.auto_paging_iter():
            if len(charge.metadata) != 0 and 'space_id' in charge.metadata:
                current_space_id = charge.metadata['space_id']
                current_fingerprint = charge.payment_method_details.card.fingerprint

                if current_space_id not in final_dict:
                    final_dict[current_space_id] = set()

                if current_fingerprint not in final_dict[current_space_id]:
                    fingerprints.add(current_fingerprint)
                    final_dict[current_space_id].add(current_fingerprint)

                if current_space_id not in spaces:
                    spaces.add(current_space_id)

    # Take a cc fingerprint via input
    first_fingerprint = request.form.get('fingerprint')
    if len(first_fingerprint) != 0:
        search_and_retrieve(fingerprint=first_fingerprint)

    while spaces > checked_spaces or fingerprints > checked_fingerprints:
        for space in spaces - checked_spaces:
            checked_spaces.add(space)
            search_and_retrieve(space_id=space)

        for fingerprint in fingerprints - checked_fingerprints:
            checked_fingerprints.add(fingerprint)
            search_and_retrieve(fingerprint=fingerprint)

    d = [(f"https://internal.signalwire.com/spaces/{space}", list(final_dict[space])) for space in final_dict]
    user_name = current_user
    df = pd.DataFrame(d, columns=('Space', 'fingerprint'))
    df.to_csv(f'csvs/{user_name.username}_fingerprints.csv', index=False, encoding='utf-8')
    return results(user_name)



@app.route('/results', methods=['GET', 'POST'])
@login_required
def results(user_name):
    data = pd.read_csv(f'csvs/{user_name.username}_fingerprints.csv')
    users = User.query.all()
    user_csv = data.to_json()
    user_csv = json.loads(user_csv)

    return render_template('results.html', tables=[data.to_html()], titles=[''], users=users, json=user_csv)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def start_ngrok():
    url = ngrok.connect(5000).public_url
    print(' * Tunnel URL:', url)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        start_ngrok()
    app.run(debug=True)
