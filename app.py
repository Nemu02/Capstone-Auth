from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemySchema
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')

db = SQLAlchemy(app)
ma = Marshmallow(app)
bc = Bcrypt(app)
CORS(app, supports_credentials=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable= False, unique = True)
    password = db.Column(db.String, nullable= False)
    email = db.Column(db.String, unique= True)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "password", "email")

user_schema = UserSchema()
many_user_schema = UserSchema(many=True)

# Endpoints

@app.route("/user/add", methods=['POST'])
def new_user():
    if request.content_type != "application/json":
        return jsonify("Error Creating New User Account")

    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")
    email = post_data.get("email")

    pw_hash = bc.generate_password_hash(password).decode('utf-8')

    new_record = User(username, pw_hash, email)
    db.session.add(new_record)
    db.session.commit()

    return jsonify(user_schema.dump(new_record))

# verify user
@app.route("/user/verify", methods= ["POST"])
def user_verify():
    if request.content_type != "application/json":
        return jsonify("Error resubmitr Info")

    post_data = request.get_json()
    email = post_data.get('email')
    password = post_data.get("password")

    user = db.session.query(User).filter(User.email == email).first()

    if user is None:
        return jsonify("Not Logged IN")

    if not bc.check_password_hash(user.password, password):
        return jsonify("wrong password/email")

    return jsonify("user verified")

# get user
@app.route("/user/get")
def get_items():
    all_items = db.session.query(User).all()
    return jsonify(many_user_schema.dump(all_items))

# delete user
@app.route('/user/delete/<id>', methods=["DELETE"])
def delete_user(id):
    user_to_delete = db.session.query(User).filter(User.id == id).first()
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify("The Requested User is no More", user_schema.dump(user_to_delete))

# update user
@app.route("/user/update/<id>", methods=["PUT"])
def user_update(id):
    if request.content_type != "application/json":
        return jsonify("error updating user data")
    
    put_data = request.get_json()
    username = put_data.get("username")
    email = put_data.get("email")

    user_update = db.session.query(User).filter(User.id == id).first()

    if username != None:
        user_update.username = username

    if email != None:
        user_update.email = email

    db.session.commit()
    return jsonify(user_schema.dump(user_update))

@app.route("/user/pwUpdate/<id>", methods=["PUT"])
def update_pw(id):
    if request.content_type != "application/json":
        return jsonify("error updating user info")

    password = request.get_json().get("password")
    user = db.session.query(User).filter(User.id == id).first()
    pw_hash = bc.generate_password_hash(password).decode('utf-8')
    user.password = pw_hash

    db.session.commit()
    return jsonify(user_schema.dump(user))












if __name__ == "__main__":
    app.run(app.run(host="127.0.0.1", port=8000, debug=True))
