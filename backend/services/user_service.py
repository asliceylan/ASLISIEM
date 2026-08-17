from werkzeug.security import generate_password_hash

from backend.database.db import db
from backend.database.models import User


def list_users():
    return User.query.order_by(User.username).all()


def get_user(user_id):
    return User.query.get(user_id)


def create_user(username, password, role, tenant_id=None):
    user = User(
        username=username, password_hash=generate_password_hash(password),
        role=role, tenant_id=tenant_id if role == "tenant_admin" else None,
    )
    db.session.add(user)
    db.session.commit()
    return user


def reset_password(user_id, new_password):
    user = User.query.get(user_id)
    if not user:
        return None
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    return user


def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return False
    db.session.delete(user)
    db.session.commit()
    return True
