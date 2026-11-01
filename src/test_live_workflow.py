"""Real Frida + real Qt editor, local disposable process only. No Android access."""
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
import frida
from PySide6.QtWidgets import QApplication
from app import Window
from packet import visible

app=QApplication([])
window=Window(start_demo=False)
window.intercept.setChecked(True)
window.timeout.setValue(3)
process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
session=None

def pump(predicate,seconds=5):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        app.processEvents()
        if predicate():return
        time.sleep(.01)
    raise AssertionError('Timed out waiting for GUI/Frida event')

try:
    session=frida.attach(process.pid)
    backend=window.backend
    backend.buffered=True
    config=dict(backend.settings,testMode=True)
    script=session.create_script('const BOOT_CONFIG='+json.dumps(config)+';\n'+Path(__file__).with_name('agent.js').read_text(encoding='utf-8'))
    script.set_log_handler(lambda level,text:None)
    backend.script,backend.session=script,session
    generation=backend.generation
    script.on('message',lambda m,d:backend._message(generation,script,m,d))
    script.load()
    backend.connection.emit('live')
    before=b'field=ORIGINAL|mode=test'
    after=b'field=MODIFIED|mode=test'
    for edit in (True,False):
        result=[]
        worker=threading.Thread(target=lambda:result.append(bytes(script.exports_sync.inspect(list(before)))),daemon=True)
        worker.start()
        pump(lambda:window.current is not None and window.current.pending)
        packet=window.current
        assert not result, 'Target completed before the GUI decision'
        assert window.apply_button.text()=='수정본 보내기'
        if edit:
            window.edited_text.setPlainText(visible(after))
            window.apply_button.click()
        else:
            window.pass_button.click()
        pump(lambda:bool(result) and not packet.pending)
        assert result[0]==(after if edit else before)
        assert packet.final==result[0]
        worker.join(timeout=1)
    print('PASS: actual Frida target waits; Qt Raw edit/send changes bytes before completion; original pass preserves bytes.')
finally:
    window.session_dirty=False
    window.backend.disconnect()
    window.close()
    if session:
        try:session.detach()
        except frida.InvalidOperationError:pass
    process.terminate()
    process.wait(timeout=5)
