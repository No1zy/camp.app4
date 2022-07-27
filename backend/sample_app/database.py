import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

from models import User
import const

def init_db(app):
    with app.app_context():
        db.init_app(app)
        db.drop_all()
        db.create_all()
        create_user()
        db.session.commit()

def create_user():
    admin_id = os.getenv('ADMIN_ID')
    admin_password = os.getenv('ADMIN_PASSWORD')
    admin = User(
        username=admin_id,
        password=generate_password_hash(admin_password, method='sha256'),
        private_message='Flag{hogehoge}',
        profile='I\'m Admin!',
        role=const.USER_ROLE_ADMIN
    )
    db.session.add(admin)
