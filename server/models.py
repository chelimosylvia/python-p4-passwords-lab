from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    _password_hash = db.Column(db.String(128), nullable=False)

    @hybrid_property
    def password_hash(self):
        raise Exception('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, plain_text_password):
        self._password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def authenticate(self, plain_text_password):
        return bcrypt.check_password_hash(self._password_hash, plain_text_password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
        }

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'
