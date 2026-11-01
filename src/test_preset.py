"""Run standalone: python test_preset.py. No device connection is performed."""
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication
from app import Window

app=QApplication([])
window=Window(start_demo=False)
calls=[]
window.backend.connect_device=lambda address,target,spawn,agent:calls.append((address,target,spawn,dict(window.backend.settings)))
window.target.setEditText('kr.com.wink')
window.intercept.setChecked(True)
window.compatibility.setChecked(False)
window.spawn.setChecked(False)
window.connect_button.defaultAction().trigger()
assert len(calls)==1
assert calls[0][1:3]==('kr.com.wink',True)
assert calls[0][3]['compatibility'] is True
assert calls[0][3]['intercept'] is False
assert calls[0][3]['rules'] is False
assert window.compatibility.isChecked() and window.spawn.isChecked()
assert not window.intercept.isChecked()
window.backend.disconnect()
print('PASS: one-button preset enables compatibility/spawn and disables pause/rules without device access.')
