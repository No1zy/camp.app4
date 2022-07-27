import os

base_dir = os.path.dirname(__file__)

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(base_dir, "data.sqlite")
SECRET_KEY = os.getenv("SECRET_KEY")
SQLALCHEMY_TRACK_MODIFICATIONS = False