from flask import Flask, request, make_response, render_template, jsonify
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e144b86bd4934ce7b7afe819c17b84a3'

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({"message": "token missing"}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "expired token"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "invalid token"}), 401
        return func(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/public')
def public():
    return "For public"

@app.route('/auth')
@token_required
def auth():
    return f"Authenticated user {jwt.decode(request.args.get('token'), app.config['SECRET_KEY'], algorithms=['HS256'])['username']}"

@app.route('/login', methods=["POST"])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'meeka' and password == '1234':
        token = jwt.encode({
            "username": username,
            "exp": int((datetime.now(timezone.utc) + timedelta(seconds=120)).timestamp())
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('utf-8')})
    else:
        return make_response('Unable to Authenticate', 403, {'WWW-Authenticate': "Auth Failed"})

if __name__ == "__main__":
    app.run(debug=True)
