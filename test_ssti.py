import requests

url = 'http://shape-facility.picoctf.net:54336/'
chars = ['_', '.', '[', ']', '"', "'", '+', '(', ')', '%', '{', '}', 'config', 'class', 'mro', 'subclasses', 'request', 'args', 'attr', 'lipsum', 'cycler', 'joiner', 'namespace']

print("--- Testing Filters ---")
for c in chars:
    r = requests.post(url, data={'content': f'TEST{c}TEST'})
    in_resp = c in r.text
    print(f"{c:15}: present? {in_resp}")
