#!/usr/bin/env python3
import subprocess
import time

server = subprocess.Popen(['bin/acmems', 'configs/integration.ini'])
time.sleep(2)

try:
    subprocess.check_call('tests/integration/gencert.sh')
finally:
    server.terminate()
    server.wait(10)
    if not server.poll():
        server.kill()

subprocess.check_call(['openssl', 'x509', '-in', 'tests/integration/work/domain-201512.pem', '-noout', '-text'])
