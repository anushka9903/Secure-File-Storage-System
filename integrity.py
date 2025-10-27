# integrity.py
import hashlib, json, os, time

METADATA_FILE = 'metadata.json'

def sha256_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def load_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    else:
        return {'files': []}

def save_metadata(md):
    with open(METADATA_FILE, 'w') as f:
        json.dump(md, f, indent=2)

def add_metadata_entry(filename, original_hash, encrypted_path, salt_b64, username):
    md = load_metadata()
    md['files'].append({
        'filename': filename,
        'original_hash': original_hash,
        'encrypted_path': encrypted_path,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'salt': salt_b64,
        'user': username
    })
    save_metadata(md)

# ---------- NEW: Metadata Helpers ----------
def find_entry_by_encpath(encpath):
    md = load_metadata()
    for i, e in enumerate(md.get('files', [])):
        if os.path.basename(e.get('encrypted_path', '')) == os.path.basename(encpath) or e.get('encrypted_path') == encpath:
            return i, e
    return None, None

def update_metadata_entry(encpath, new_encrypted_path=None, new_salt_b64=None):
    md = load_metadata()
    idx, entry = find_entry_by_encpath(encpath)
    if entry is None:
        return False
    if new_encrypted_path:
        md['files'][idx]['encrypted_path'] = new_encrypted_path
    if new_salt_b64:
        md['files'][idx]['salt'] = new_salt_b64
    md['files'][idx]['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
    save_metadata(md)
    return True
