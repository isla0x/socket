import os,sys
os.environ['QT_QPA_PLATFORM']='offscreen'
from PySide6.QtWidgets import QApplication,QDialogButtonBox
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from app import Window
app=QApplication([])
w=Window(start_demo=False);w.show();app.processEvents()
d=w.inline_rules
d.codes.setText('TEST001');d.before.setText('abc');d.after.setText('xyz');d.add_quick()
buttons=d.findChild(QDialogButtonBox)
save=buttons.button(QDialogButtonBox.StandardButton.Save)
signals=[]
buttons.accepted.connect(lambda:signals.append('buttonbox'))
d.accepted.connect(lambda:signals.append('dialog'))
d.saved.connect(lambda rules:signals.append('saved'))
d.save_started.connect(lambda:signals.append('started'))
QTest.mouseClick(save,Qt.MouseButton.LeftButton)
app.processEvents()
print('signals:',signals,'enabled:',w.auto_rules.isEnabled(),'checked:',w.auto_rules.isChecked(),'message:',d.error.text())
assert w.auto_rules.isChecked() and w.backend.settings['rules']
assert signals.count('saved')==1 and signals.count('started')==1
w.auto_rules.setChecked(False)
QTest.mouseClick(save,Qt.MouseButton.LeftButton);app.processEvents()
assert w.auto_rules.isChecked() and w.backend.settings['rules']
assert signals.count('saved')==2
calls=[]
w.backend.connect_device=lambda address,target,spawn,agent:calls.append(dict(w.backend.settings))
w.connect_recommended()
assert calls[-1]['rules'] and w.auto_rules.isChecked()
# Invalid input must emit a failure, rather than displaying stale success.
failures=[];d.save_failed.connect(failures.append)
d.table.item(0,3).setText('')
QTest.mouseClick(save,Qt.MouseButton.LeftButton);app.processEvents()
assert failures and signals.count('saved')==2
w.timer.stop();w.display_timer.stop()
print('PASS: actual save clicks enable OFF rules once per click; reconnect preserves ON; validation failure reported.')
