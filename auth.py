# auth.py
import json, os, hashlib

USER_FILE = 'users.json'

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists!"
    users[username] = hash_password(password)
    save_users(users)
    return True, "Registration successful!"

def authenticate_user(username, password):
    users = load_users()
    hashed = hash_password(password)
    if username in users and users[username] == hashed:
        return True
    return False
