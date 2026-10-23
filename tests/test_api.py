import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]

class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.port = 18963
        env = dict(os.environ, APP_DB=str(Path(cls.tmp.name) / 'test.db'), APP_PORT=str(cls.port),
                   JWT_SECRET='S'*48, DEMO_PASSWORD='test-Password-123!')
        cls.proc = subprocess.Popen([sys.executable, str(ROOT/'src/app.py')], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                cls.request('GET', '/api/data')
                break
            except URLError:
                time.sleep(.1)
        else:
            raise RuntimeError('Server failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.tmp.cleanup()

    @classmethod
    def request(cls, method, path, data=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer '+token
        req = Request('http://127.0.0.1:'+str(cls.port)+path,
                      data=json.dumps(data).encode() if data is not None else None,
                      headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def login(self):
        status, data = self.request('POST', '/auth/login', {'login':'demo','password':'test-Password-123!'})
        self.assertEqual(status, 200)
        return data['token']

    def test_no_token_denied(self):
        self.assertEqual(self.request('GET', '/api/data')[0], 401)

    def test_login_and_data(self):
        token = self.login()
        self.assertEqual(self.request('GET', '/api/data', token=token)[0], 200)

    def test_sql_injection_rejected(self):
        status, _ = self.request('POST', '/auth/login', {'login':"demo' OR '1'='1",'password':'x'})
        self.assertEqual(status, 401)

    def test_xss_escaped(self):
        token = self.login()
        status, result = self.request('POST','/api/posts',{'text':'<script>alert(1)</script>'},token)
        self.assertEqual(status,201)
        self.assertIn('&lt;script&gt;',result['text'])
        status, result = self.request('GET','/api/data',token=token)
        self.assertIn('&lt;script&gt;',result['posts'][-1]['text'])

    def test_invalid_token_denied(self):
        self.assertEqual(self.request('GET','/api/data',token='not.a.jwt')[0],401)

    def test_bad_password_denied(self):
        self.assertEqual(self.request('POST','/auth/login',{'login':'demo','password':'wrong'})[0],401)

if __name__ == '__main__':
    unittest.main()
