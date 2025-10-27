# crypto_module.py
import os, base64, random
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password, salt=None):
    if isinstance(salt, str):
        salt = base64.b64decode(salt)
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    token = fernet.encrypt(data)
    out = filepath + '.enc'
    with open(out, 'wb') as f:
        f.write(token)
    return out

def decrypt_file(encpath, key):
    with open(encpath, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    dec = fernet.decrypt(data)
    out = encpath[:-4] if encpath.endswith('.enc') else encpath + '.dec'
    with open(out, 'wb') as f:
        f.write(dec)
    return out

# ---------- NEW FEATURE: Secure Delete ----------
def secure_delete(path, passes=3):
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found")
    length = os.path.getsize(path)
    with open(path, 'rb+') as f:
        for _ in range(passes):
            f.seek(0)
            chunk_size = 8192
            remaining = length
            while remaining > 0:
                write_len = min(chunk_size, remaining)
                f.write(os.urandom(write_len))
                remaining -= write_len
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)
    return True

# ---------- NEW FEATURE: Change Password (Re-encrypt) ----------
def reencrypt_file(encpath, old_password, new_password, derive_key_fn, decrypt_fn, encrypt_fn):
    key_old, salt_old = derive_key_fn(old_password, None)
    try:
        decpath = decrypt_fn(encpath, key_old)
    except Exception as e:
        raise e

    key_new, salt_new = derive_key_fn(new_password, None)
    new_encpath = encrypt_fn(decpath, key_new)

    try:
        secure_delete(decpath, passes=1)
    except Exception:
        if os.path.exists(decpath):
            os.remove(decpath)

    return new_encpath, salt_new
