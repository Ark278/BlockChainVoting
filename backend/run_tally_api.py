import urllib.request
import urllib.error
import json

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/tally/run',
    data=json.dumps({'election_id': 5}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    print("SUCCESS:", urllib.request.urlopen(req).read().decode())
except urllib.error.HTTPError as e:
    print("ERROR:", e.code, e.read().decode())
