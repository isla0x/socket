import os,sys
os.environ['QT_QPA_PLATFORM']='offscreen'
sys.excepthook=lambda *args:os._exit(1)
from PySide6.QtWidgets import QApplication
from app import Window
from rules_ui import RulesDialog
app=QApplication([])
w=Window()
for row,code,label,color in [(0,'TX','요청','#167044'),(1,'RX','응답','#1f5fae')]:
    w.table.selectRow(row)
    assert w.current.direction==code
    assert label in w.table.item(row,2).text()
    assert label in w.detail_title.text() and code not in w.detail_title.text()
    assert label in w.raw_title.text()
    assert color in w.edited_text.styleSheet() and color in w.original_hex.styleSheet()
    assert w.table.item(row,2).foreground().color().name()==color
d=RulesDialog([])
for code,label in [('TX','요청'),('RX','응답'),('ANY','요청 + 응답')]:
    d.direction.setCurrentIndex(d.direction.findData(code))
    assert d.direction.currentText()==label
d.direction.setCurrentIndex(d.direction.findData('TX'))
d.codes.setText('TEST001');d.before.setText('abc');d.after.setText('def');d.add_quick()
assert d.checked_rules()[0]['direction']=='TX'
assert d.table.cellWidget(0,1).currentText()=='요청'
d.populate(d.checked_rules());assert d.checked_rules()[0]['direction']=='TX'
w.timer.stop();w.display_timer.stop()
print('PASS: Korean request/response labels, request green/response blue body and Hex, internal rule directions preserved.')
