import os, sys, time
os.environ['QT_QPA_PLATFORM']='offscreen'
sys.excepthook=lambda *args: os._exit(1)
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFontDatabase
from app import Window, STYLE
app=QApplication([])
for name in ('segoeui.ttf','malgun.ttf','consola.ttf'):
    QFontDatabase.addApplicationFont('C:/Windows/Fonts/'+name)
app.setStyleSheet(STYLE)
w=Window(start_demo=False)
w.show();app.processEvents()
d=w.inline_rules
d.overwrite.setChecked(False)
d.direction.setCurrentIndex(d.direction.findData('TX'))
d.codes.setText('DEMO001Q1')
d.before.setText('user01');d.after.setText('user002')
d.add_quick();d.save()
assert w.rules[0]['find_text']=='user01' and w.auto_rules.isChecked()
assert not d.isHidden() and w.allow_resize.isChecked()
original=b'DEMO001Q1|00user01|user01'
changed=b'DEMO001Q1|00user002|user002'
w.receive(dict(id='inline-test',direction='TX',stage='DEMO / local test',timestamp=time.time(),pending=False),original)
w.prepared(dict(id='inline-test',names=['test']),changed)
w.settled(dict(id='inline-test',action='replace'),changed)
assert w.edited_text.toPlainText()==changed.decode()
assert w.original_text.isHidden() and w.edited_text.isReadOnly()
assert '치환 적용 결과' in w.raw_title.text()
assert w.original_hex.toPlainText().find('70 6d')>=0
assert w.current.original==original and w.current.final==changed
if len(sys.argv)>1:
    app.processEvents();assert w.grab().save(sys.argv[1])
w.timer.stop();w.display_timer.stop()
print('PASS: inline rules save/enable without JSON; single readonly actual result; original bytes preserved.')
