from database import db
from flask_login import UserMixin


class User(db.Model, UserMixin):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(25))
    profile = db.Column(db.String(1000))
    private_message = db.Column(db.String(100))
    role = db.Column(db.Integer())


    def __repr__(self):
        return '<User id={} username={}>'.format(self.id, self.username)
