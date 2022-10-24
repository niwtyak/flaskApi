from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import enum

db = SQLAlchemy()


class Role(enum.Enum):
    admin = 'admin'
    creator = 'creator'
    consumer = 'consumer'


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    role = db.Column(db.String(250), nullable=False)
    content = db.relationship('Post', backref='app_user', cascade='all, delete-orphan', lazy=True)

    def __init__(self, name, password, role):
        self.name = name
        self.password = generate_password_hash(password, method='sha256')
        self.role = Role[role].value

    @classmethod
    def verify(cls, name, password):
        if not name or not password:
            return None

        user = cls.query.filter_by(name=name).one_or_none()
        if not user or not check_password_hash(user.password, password):
            return None

        return user

    def serialize(self):
        posts = [post.serialize() for post in self.content]
        return dict(id=self.id, name=self.name, password=self.password, role=self.role, content=posts)


class Post(db.Model):
    __tabelname__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, user_id, content):
        self.user_id = user_id
        self.content = content

    def serialize(self):
        return dict(id=self.id, user_id=self.user_id, content=self.content, date_created=self.date_created,
                    date_last_updated=self.date_last_updated)
