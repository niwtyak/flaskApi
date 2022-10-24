import secrets
from datetime import timedelta, datetime, timezone
from flask import Flask, render_template, request, redirect, jsonify, make_response
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, JWTManager, \
    current_user
from werkzeug.security import generate_password_hash

from model import User, Post, db, Role

app = Flask(__name__)

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)

db.init_app(app)
jwt = JWTManager(app)


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@app.route('/login', methods=['POST'])
def login():
    name = request.json['name']
    password = request.json['password']

    if not User.verify(name, password):
        return 'Invalid credentials', 400

    user = User.query.filter_by(name=name).one_or_none()
    access_token = create_access_token(identity=user)
    refresh_token = create_refresh_token(identity=user)
    return jsonify(access_token=access_token, refresh_token=refresh_token)


@app.route('/register', methods=['POST'])
def register():
    name = request.json['name']
    password = request.json['password']
    role = request.json['role']

    if not name or not password:
        return 'No name or password', 404

    if not Role[role]:
        return 'No such role', 404

    user = User(name=name, password=password, role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify(user.serialize())


@app.route('/users/all', methods=['GET'])
@jwt_required()
def show_all_users():
    if current_user.role == Role.admin.value:
        users = db.session.query(User).all()
        return jsonify(users=[i.serialize() for i in users])

    return f'Access denied (only admin can enter this route, but you are {current_user.role})', 403


@app.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def find_user_by_id(user_id):
    # user = db.session.query(User).filter_by(id=user_id).one_or_none()
    # if not user:
    #    return 'No such user', 404

    if current_user.role == Role.admin.value:
        user = db.get_or_404(User, user_id)
        return jsonify(user.serialize())

    return f'Access denied (only admin can enter this route, but you are {current_user.role})', 403


@app.route('/users/<int:user_id>/edit', methods=['POST'])
@jwt_required()
def update_user(user_id):

    edited_user = db.get_or_404(User, user_id)

    if not edited_user:
        return 'No such user id', 404
    try:
        new_name = request.json['name']
        new_password = request.json['password']
    except():
        return 'Invalid data', 400

    edited_user.name = new_name
    edited_user.password = generate_password_hash(new_password, method='sha256')

    db.session.add(edited_user)
    db.session.commit()

    return jsonify(edited_user.serialize())


@app.route('/users/<int:user_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if current_user.role != Role.admin.value:
        return f'Access denied (only admin can enter this route, but you are {current_user.role})', 403
    user_to_delete = db.get_or_404(User, user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify(user_to_delete.serialize())


@app.route('/post', methods=['POST'])
@jwt_required()
def post():
    if current_user.role == Role.consumer:
        return f'Access denied (only admin can enter this route, but you are {current_user.role})', 403

    content = request.json['content']
    if not content:
        return 'Empty post', 400

    new_post = Post(current_user.id, content)
    db.session.add(new_post)
    db.session.commit()

    return jsonify(new_post.serialize())


@app.route('/posts', methods=['GET'])
@jwt_required()
def feed():
    posts = db.session.query(Post).all()
    return jsonify(posts=[i.serialize() for i in posts])


@app.route('/post/<int:post_id>/edit', methods=['POST'])
@jwt_required()
def edit_post(post_id):
    edited_post = db.get_or_404(Post, post_id)

    if current_user.id == edited_post.user_id or current_user.role == Role.admin.value:
        edited_post.content = request.json['content']
        edited_post.date_last_updated = datetime.utcnow()
        db.session.add(edited_post)
        db.session.commit()
        return jsonify(edited_post.serialize())

    return 'You have no rights to edit this post', 403


@app.route('/posts/<int:post_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    post_to_delete = db.get_or_404(Post, post_id)
    if current_user.id == post_to_delete.user_id or current_user.role == Role.admin.value:
        db.session.delete(post_to_delete)
        db.session.commit()
        return jsonify(post_to_delete.serialize())
    return 'You have no rights to delete this post', 403


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
