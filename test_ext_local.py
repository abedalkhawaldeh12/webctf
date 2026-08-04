import sys, os, threading, http.server, socketserver
sys.path.insert(0, '/home/kali/Desktop/abed/webctf')
from modules.external_tools import ExternalTools

# Create a local test server with hidden directories
os.makedirs('/tmp/testweb/admin', exist_ok=True)
os.makedirs('/tmp/testweb/secret', exist_ok=True)
os.makedirs('/tmp/testweb/backup', exist_ok=True)
with open('/tmp/testweb/admin/index.html', 'w') as f:
    f.write('<html>ADMIN PAGE flag{admin_secret}</html>')
with open('/tmp/testweb/secret/flag.txt', 'w') as f:
    f.write('flag{hidden_secret}')
with open('/tmp/testweb/backup/config.php', 'w') as f:
    f.write('<?php $db_password = "secret123"; ?>')
with open('/tmp/testweb/index.html', 'w') as f:
    f.write('<html>Home</html>')

os.chdir('/tmp/testweb')
handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(('127.0.0.1', 8899), handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print('Test server started on http://127.0.0.1:8899')

t = ExternalTools()
print()
print('=== TEST: ffuf on local server ===')
hits = t.run_ffuf('http://127.0.0.1:8899/', max_time=30)
print('ffuf hits:', len(hits))
for h in hits:
    print('  ', h.get('path'), '->', h.get('status'))

print()
print('=== TEST: gobuster on local server ===')
hits2 = t.run_gobuster('http://127.0.0.1:8899/', max_time=30)
print('gobuster hits:', len(hits2))
for h in hits2:
    print('  ', h.get('path'), '->', h.get('status'))

httpd.shutdown()
print()
print('=== DONE ===')
