import json.decoder

import flask
import werkzeug
from flask import Flask, Response, jsonify, flash, request, render_template, redirect, sessions
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from flask_wtf.csrf import CSRFProtect

from selenium import webdriver
from time import sleep

from selenium.common.exceptions import TimeoutException

from database import db, init_db
import requests
import const
import os
import re
from mysessioninterface import MySessionInterface


app = Flask(__name__, static_folder='static')
app.config.from_object('config')
app.session_interface = MySessionInterface()
csrf = CSRFProtect(app)

init_db(app)

from models import User

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template('index.html', user=current_user)


@app.route('/users/<int:user_id>', methods=['GET'])
@login_required
def show_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    return render_template('users/show.html', user=user)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if user_id != current_user.id:
            flash('Forbidden...')
            return redirect('error.html')

    if request.method == "GET":
        user = User.query.filter_by(id=user_id).first()

        return render_template('users/edit.html', user=user)

    elif request.method == "POST":
    
        username = request.form.get('username')
        private_message = request.form.get('private_message')
        profile = request.form.get('profile')

        user = User.query.filter_by(id=user_id).first()
        if username:
            if User.query.filter(User.id != user_id, User.username == username).count() > 0:
                flash('already user exists...')
                return render_template('users/edit.html', user=user)

            user.username = username

        if private_message:
            user.private_message = private_message

        if profile:
            user.profile = profile

        db.session.commit() 
        return redirect(f'/users/{user_id}')


@app.route('/users/<int:user_id>/private_message', methods=['GET'])
@login_required
def get_private_message(user_id):
    if current_user.id != user_id:
        return Response(response="", status=200)

    user = User.query.filter_by(id=current_user.id).first()
    headers = {'Content-Type': 'text/plain'}

    return Response(response=user.private_message, headers=headers, status=200)


@app.route('/users/<int:user_id>/report', methods=['POST'])
@login_required
def report(user_id):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Remote(
        command_executor="http://selenium-server:4444/wd/hub",
        options=options
    )
    driver.set_page_load_timeout(15)

    driver.implicitly_wait(10)

    url = 'http://proxy:3000'

    s = requests.Session()

    admin_id = os.getenv('ADMIN_ID')
    admin_password = os.getenv('ADMIN_PASSWORD')

    r = s.get(f'{url}/login')
    regex = re.compile(r'name="csrf_token" value="(.*?)"')
    m = regex.search(r.text)
    if m:
        csrf_token = m.groups(1)[0]

    data = {
        'csrf_token': csrf_token,
        'username': admin_id,
        'password': admin_password
    }

    s.post(f'{url}/login', data=data)

    session_cookie = s.cookies.get('session')

    try:
        driver.get(f'{url}/static/css/users/signin.css')

        driver.add_cookie({
            'name': 'session',
            'value': session_cookie,
        })
        sleep(2)
        driver.get(f'{url}/users/{user_id}')
        driver.save_screenshot('/sample_app/images/ss.png')
        driver.get(f'{url}/users/{user_id}')
        sleep(1)
    except TimeoutException:
        print("Time out Request")
    finally:
        driver.quit()

    return redirect(f'/users/{user_id}')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        profile = request.form.get('profile')
        
        if User.query.filter_by(username=username).count() > 0:
            flash('already user exists...')
            return render_template('signup.html')

        user = User(username=username, password=generate_password_hash(password, method='sha256'), profile=profile, role=const.USER_ROLE_USER)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    else:
        return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        redirect_path = request.form.get('redirect')

        if not redirect_path:
            redirect_path = '/'

        user = User.query.filter_by(username=username).first()

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(redirect_path)
        else:
            flash('Login failed...')
            return render_template('login.html')
    else:
        if current_user.is_authenticated:
            return redirect('/')

        return render_template('login.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/debug', methods=['GET', 'POST'])
@csrf.exempt
def debug():
    headers = {}
    for header in request.headers:
        headers[header[0]] = header[1]

    return jsonify(body=request.form, headers=headers)


@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/login')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
