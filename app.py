import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from email_validator import validate_email

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)


# db.init_app(app)

class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(255), nullable=False)
  password = db.Column(db.String(255), nullable=False)

  def __init__(self, email, password):
    self.email = email
    self.password = password


class Todo(db.Model):
  __tablename__ = 'todos'

  id = db.Column(db.Integer, primary_key=True)
  task = db.Column(db.String(255), nullable=False)
  done = db.Column(db.Boolean(), default=False, nullable=False)

  def __repr__(self):
    if len(self.task) < 40:
      return '<Task {}'.format(self.task)
    return '<Task {}'.format(self.task[:40])


with app.app_context():
  db.create_all()


@app.errorhandler(404)
def not_found(e):
    return generate_response(404, 'Resource not found.')


@app.errorhandler(400)
def bad_request(e):
    return generate_response(400, 'Bad request.')

  

def todo_serializer(todo):
  """ Serialize a To-Do object to a dict """
  todo_dict = {'id': todo.id, 'task': todo.task, 'done': todo.done}
  return todo_dict


def generate_response(code, message, todo=None):
  """ Generate a Flask response with a json playload and HTTP code  """
  if todo:
    return jsonify({'code': code, 'message': message, 'todo': todo}), code
  return jsonify({'code': code, 'message': message}), code



# API ROUTES

@app.route("/signup", methods=["POST"])
def signup():
  user_hash = request.get_json()

  if not user_hash:
      return generate_response(400, 'Invalid payload.')

  email = user_hash.get('email', None)
  password = user_hash.get('password', None)
  pw_hash = bcrypt.generate_password_hash(password)

  if not email or not password:
    return generate_response(400, 'Invalid payload.')

  if not is_email_valid(email):
    return generate_response(400, 'Please choose valid email.')

  if User.query.filter_by(email=email).first():
    return generate_response(400, 'Email is already taken')

  user = User(email, pw_hash)
  db.session.add(user)
  db.session.commit()

  access_token = create_access_token(identity= user.id)
  return jsonify(access_token=access_token)

@app.route("/login", methods=["POST"])
def login():
  post_data = request.get_json()
  if not post_data:
      return generate_response(400, 'Invalid payload.')

  email = post_data.get('email', None)
  password = post_data.get('password', None)

  user = User.query.filter_by(email=email).first() 
  if not user:
    return generate_response(404, 'User not found.')
  
  if not bcrypt.check_password_hash(user.password, password):
    return generate_response(401, 'Email or Password is wrong')

  access_token = create_access_token(identity= user.id)
  return jsonify(access_token=access_token)


@app.route('/todos/', methods=['GET'])
@jwt_required()
def list_all_todos():
    return jsonify([*map(todo_serializer, Todo.query.all())])


@app.route('/todos/<int:todo_id>', methods=['GET'])
@jwt_required()
def list_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return generate_response(404, 'Task not found.')

    return jsonify(todo_serializer(todo))

@app.route('/todos/', methods=['POST'])
@jwt_required()
def add_todo():
    post_data = request.get_json()
    if not post_data:
        return generate_response(400, 'Invalid payload.')

    task = post_data.get('task')
    todo = Todo(task=task)
    db.session.add(todo)
    db.session.commit()

    return generate_response(201, 'Task added.', todo_serializer(todo))


@app.route('/todos/<int:todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return generate_response(404, 'Task not found.')

    post_data = request.get_json()
    if not post_data:
        return generate_response(400, 'Invalid payload.')


    todo.done = post_data.get('done', todo.done)
    todo.task = post_data.get('task', todo.task)
    db.session.commit()

    return generate_response(200, 'Task updated.', todo_serializer(todo))


@app.route('/todos/<int:todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return generate_response(404, 'Task not found.')

    db.session.delete(todo)
    db.session.commit()
    return generate_response(200, 'Task deleted.')


# validator helpers

def is_email_valid(email):
  try:
    validate_email(email)
    return True 
  
  except:
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0')