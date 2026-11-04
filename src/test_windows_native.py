"""Real native hooks on disposable x86/x64 localhost helpers. Never attaches to ProvestK."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import frida

root = Path(__file__).resolve().parent
csc = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework/v4.0.30319/csc.exe'
server = socket.socket()
server.bind(('127.0.0.1', 0)); server.listen()
port = server.getsockname()[1]
def echo():
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        with conn:
            data = conn.recv(256)
            conn.sendall(b'ECHO:' + data)
threading.Thread(target=echo, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='socket-inspector-native-') as tmp:
        for arch in ('x86', 'x64'):
            exe = Path(tmp) / ('helper-' + arch + '.exe')
            subprocess.run([str(csc), '/nologo', '/platform:' + arch, '/out:' + str(exe),
                            str(root / 'windows-test-helper.cs')], check=True, capture_output=True)
            child = subprocess.Popen([str(exe), str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            session = None
            try:
                assert child.stdout.readline().strip() == 'READY ' + arch
                session = frida.get_local_device().attach(child.pid)
                script = session.create_script('const BOOT_CONFIG = {capture:true,pcSource:"socket"};\n' +
                                               (root / 'agent-windows.js').read_text(encoding='utf-8'))
                packets, errors, logs = [], [], []
                def message(m, data):
                    if m['type'] == 'error': errors.append(m)
                    elif m['type'] == 'send':
                        payload = m['payload']
                        if payload.get('kind') == 'packet': packets.append((payload, bytes(data)))
                        if payload.get('kind') == 'log': logs.append(payload['text'])
                script.on('message', message); script.load()
                child.stdin.write('go\n'); child.stdin.flush()
                out, err = child.communicate(timeout=20)
                time.sleep(.2)
                assert child.returncode == 0, (out, err)
                assert not errors, errors
                for label in ('SYNC-', 'GATHER-', 'OVERLAPPED-', 'IOCP-'):
                    tx = (label + arch).encode(); rx = b'ECHO:' + tx
                    assert any(m['direction']=='TX' and data==tx for m,data in packets), (arch,label,'missing TX',packets,logs)
                    assert any(m['direction']=='RX' and data==rx for m,data in packets), (arch,label,'missing RX',packets,logs)
                for label in ('OVERLAPPED-', 'IOCP-'):
                    expected = ('ECHO:' + label + arch).encode()
                    assert sum(data==expected for m,data in packets)==1, ('duplicate async',packets)
                print('PASS:', arch, 'native send/recv, scatter/gather, async event and IOCP; exact echo bytes; no duplicates/errors.')
            finally:
                if session:
                    try: session.detach()
                    except frida.InvalidOperationError: pass
                if child.poll() is None: child.kill(); child.wait()
finally:
    server.close()
