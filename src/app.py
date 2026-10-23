"""Secure educational REST API using Python's standard library."""
import base64
import binascii
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(os.environ.get('APP_DB', 'work1.sqlite3'))
SECRET = os.environ.get('JWT_SECRET', '')
MAX_BODY = 8192


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def issue_token(username):
    header = b64(b'{"alg":"HS256","typ":"JWT"}')
    now = int(time.time())
    payload = b64(json.dumps({'sub': username, 'iat': now, 'exp': now + 1800}, separators=(',', ':')).encode())
    message = (header + '.' + payload).encode()
    signature = b64(hmac.new(SECRET.encode(), message, hashlib.sha256).digest())
    return f'{header}.{payload}.{signature}'


def verify_token(token):
    try:
        header, payload, signature = token.split('.')
        expected = b64(hmac.new(SECRET.encode(), (header + '.' + payload).encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, signature):
            return None
        metadata = json.loads(unb64(header))
        claims = json.loads(unb64(payload))
        now = int(time.time())
        if metadata != {'alg': 'HS256', 'typ': 'JWT'}:
            return None
        if not isinstance(claims.get('sub'), str) or not isinstance(claims.get('exp'), int):
            return None
        if claims['exp'] <= now or claims.get('iat', now + 1) > now:
            return None
        return claims['sub']
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error, json.JSONDecodeError):
        return None


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return b64(salt) + '$' + b64(digest)


def password_verify(password, stored):
    try:
        salt_s, _ = stored.split('$', 1)
        return hmac.compare_digest(password_hash(password, unb64(salt_s)), stored)
    except (ValueError, TypeError, binascii.Error):
        return False


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, text TEXT NOT NULL)')
        if not db.execute('SELECT 1 FROM users WHERE username = ?', ('demo',)).fetchone():
            password = os.environ.get('DEMO_PASSWORD', '')
            if not password:
                raise RuntimeError('Set DEMO_PASSWORD before first initialization')
            db.execute('INSERT INTO users(username,password_hash) VALUES (?,?)', ('demo', password_hash(password)))
        if not db.execute('SELECT 1 FROM posts LIMIT 1').fetchone():
            db.execute('INSERT INTO posts(owner,text) VALUES (?,?)', ('demo', 'Welcome to the secure API'))


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, value):
        data = json.dumps(value, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'none'")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body_json(self):
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if length < 0 or length > MAX_BODY or self.headers.get_content_type() != 'application/json':
                return None
            obj = json.loads(self.rfile.read(length))
            return obj if isinstance(obj, dict) else None
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def authorized(self):
        value = self.headers.get('Authorization', '')
        if not value.startswith('Bearer '):
            return None
        return verify_token(value[7:])

    def do_POST(self):
        path = urlparse(self.path).path
        if path == '/auth/login':
            body = self.body_json()
            if not body or not isinstance(body.get('login'), str) or not isinstance(body.get('password'), str):
                return self.send_json(400, {'error': 'Invalid JSON credentials'})
            username, password = body['login'], body['password']
            with sqlite3.connect(DB_PATH) as db:
                row = db.execute('SELECT password_hash FROM users WHERE username = ?', (username,)).fetchone()
            if row is None or not password_verify(password, row[0]):
                return self.send_json(401, {'error': 'Invalid credentials'})
            return self.send_json(200, {'token': issue_token(username), 'token_type': 'Bearer', 'expires_in': 1800})
        if path == '/api/posts':
            username = self.authorized()
            if username is None:
                return self.send_json(401, {'error': 'Authentication required'})
            body = self.body_json()
            if not body or not isinstance(body.get('text'), str) or not 1 <= len(body['text']) <= 500:
                return self.send_json(400, {'error': 'text must contain 1-500 characters'})
            with sqlite3.connect(DB_PATH) as db:
                cur = db.execute('INSERT INTO posts(owner,text) VALUES (?,?)', (username, body['text']))
                post_id = cur.lastrowid
            return self.send_json(201, {'id': post_id, 'owner': html.escape(username, quote=True), 'text': html.escape(body['text'], quote=True)})
        self.send_json(404, {'error': 'Not found'})

    def do_GET(self):
        if urlparse(self.path).path != '/api/data':
            return self.send_json(404, {'error': 'Not found'})
        username = self.authorized()
        if username is None:
            return self.send_json(401, {'error': 'Authentication required'})
        with sqlite3.connect(DB_PATH) as db:
            rows = db.execute('SELECT id, owner, text FROM posts ORDER BY id LIMIT 100').fetchall()
        self.send_json(200, {'posts': [{'id': i, 'owner': html.escape(owner, quote=True), 'text': html.escape(text, quote=True)} for i, owner, text in rows]})


def main():
    if len(SECRET.encode()) < 32:
        raise RuntimeError('JWT_SECRET must contain at least 32 bytes')
    init_db()
    host = os.environ.get('APP_HOST', '127.0.0.1')
    port = int(os.environ.get('APP_PORT', '8000'))
    print(f'Listening on http://{host}:{port}', flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == '__main__':
    main()
