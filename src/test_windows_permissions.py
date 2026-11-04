"""Read-only native inventory and simulated elevated-target failure; no HTS attach."""
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from PySide6.QtCore import QCoreApplication
from backend import Backend, connection_error
from windows_processes import pc_processes, elevated, PC_TARGETS

for p in pc_processes():
    assert p.name.lower() in PC_TARGETS and isinstance(p.pid, int) and p.pid > 0
assert elevated() in (True, False, None)
app = QCoreApplication([])
b = Backend(); b.configure(dict(profile='provest', compatibility=False, intercept=False, rules=False))
lists, logs, states = [], [], []
b.applications.connect(lists.append); b.log.connect(logs.append); b.connection.connect(states.append)
def pump(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate(): return
        time.sleep(.01)
    raise AssertionError('Timed out')
class Device:
    def enumerate_processes(self): raise AssertionError('Frida enumeration must not hide elevated HTS')
    def attach(self, pid): raise AssertionError('Do not attach with known insufficient permissions')
with patch('backend.frida.get_local_device', return_value=Device()), \
     patch('backend.pc_processes', return_value=[SimpleNamespace(pid=12345,name='provestkrun.exe')]), \
     patch('backend.elevated', side_effect=lambda pid=None: pid is not None), \
     patch('backend.needs_elevation', return_value=True):
    b.list_applications('LOCAL')
    pump(lambda: bool(lists))
    assert lists[0] == [('12345','provestkrun.exe [관리자]',12345)]
    b.connect_device('LOCAL','12345',False,Path(__file__).with_name('agent-windows.js'))
    pump(lambda: 'disconnected' in states)
assert any('HTS는 실행 중입니다(PID 12345)' in s and '관리자' in s for s in logs), logs
assert not any('찾지 못했거나' in s for s in logs)
with patch('backend.elevated', return_value=True):
    error=connection_error('unexpected error allocating memory in target process (VirtualAlloc returned 0x00000005)',True)
    assert '뷰어 권한: 관리자' in error and '후크 설치 전' in error
    assert '정확한 차단 원인은 아직 확인되지 않았습니다' in error
assert connection_error('other error',True)=='other error'
assert connection_error('VirtualAlloc returned 0x00000005',False)=='VirtualAlloc returned 0x00000005'
print('PASS: native HTS inventory, elevated targets visible, explicit permission diagnosis before attach; no real HTS attach.')
