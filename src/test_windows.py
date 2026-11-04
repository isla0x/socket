"""No target-app launch. Checks profile wiring, read-only enforcement and log metadata."""
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import time
from pathlib import Path
from PySide6.QtWidgets import QApplication
from app import Window
from backend import Backend, agent_source

app = QApplication([])
w = Window(start_demo=False)
w.profile.setCurrentIndex(w.profile.findData('provest'))
assert w.target.currentText() == 'provestkrun.exe'
assert not w.address.isEnabled() and not w.spawn.isEnabled()
assert not w.intercept.isEnabled() and not w.inline_rules.isEnabled()
assert not w.pc_info.isHidden() and w.inline_rules.isHidden()
w.auto_rules.setChecked(True)
w.intercept.setChecked(True)
w.configure()
assert not w.backend.settings['rules'] and not w.backend.settings['intercept']
assert not w.backend.settings['compatibility']
assert not w.auto_rules.isChecked()
b = Backend()
b.configure(dict(profile='provest', rules=True, intercept=True, compatibility=True, compiledRules=[{}]))
assert not b.settings['rules'] and not b.settings['intercept'] and not b.settings['compiledRules']
source = agent_source(dict(profile='provest', compatibility=True), Path(__file__).with_name('agent-windows.js'))
assert 'Java.use' not in source and 'Java.perform' not in source
calls = []
w.backend.connect_device = lambda *args: calls.append(args)
w.apps_loaded([('23456', 'provestkrun.exe', 23456)])
w.connect_recommended()
assert calls[-1][:3] == ('LOCAL', '23456', False)
assert calls[-1][3].name == 'agent-windows.js'
w.receive(dict(id='pc-test', direction='RX', stage='PC · recv · socket=0x10',
               timestamp=time.time(), pending=False, note='truncated test note'), b'test response')
assert w.current.note == 'truncated test note' and not w.current.pending
assert w.edited_text.isReadOnly()
assert 'PC 조회 전용' in w.manual_banner.text()
w.connection_changed('live')
assert not w.profile.isEnabled()
w.connection_changed('disconnected')
assert not w.address.isEnabled() and not w.spawn.isEnabled()
w.profile.setCurrentIndex(w.profile.findData('kyobo'))
assert w.target.currentText() == 'kr.com.wink' and w.address.isEnabled()
assert w.intercept.isEnabled() and not w.inline_rules.isHidden()
w.timer.stop(); w.display_timer.stop()
print('PASS: PC selection, PID attach, no mobile prelude, read-only backend/UI, metadata, return to Android.')
