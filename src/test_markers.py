import os,sys,tempfile,time,json
os.environ['QT_QPA_PLATFORM']='offscreen'
sys.excepthook=lambda *args:os._exit(1)
from pathlib import Path
from PySide6.QtWidgets import QApplication,QDialog,QLineEdit
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from app import Window,MARKERS
from packet import save_session,load_session
app=QApplication([])
w=Window();w.show();app.processEvents()
w.table.selectRow(0);w.table.setFocus()
for n in range(1,6):
    QTest.keyClick(w.table,Qt.Key.Key_0+n,Qt.KeyboardModifier.ControlModifier)
    assert w.current.marker==n
    assert w.table.item(0,3).background().color().name()==MARKERS[n][0]
    assert not w.table.item(0,0).icon().isNull()
QTest.keyClick(w.table,Qt.Key.Key_5,Qt.KeyboardModifier.ControlModifier)
assert w.current.marker==0 and w.table.item(0,0).icon().isNull()
for row,n in enumerate([1,2,3,4]):
    w.table.selectRow(row);w.mark_current(n)
w.table.selectRow(0)
w.update_row(w.current)
assert w.current.marker==1
with tempfile.TemporaryDirectory() as temp:
    path=Path(temp)/'session.json'
    save_session(path,w.packets)
    assert [p.marker for p in load_session(path)]==[1,2,3,4]
    doc=json.loads(path.read_text(encoding='utf8'))
    for p in doc['packets']:p.pop('marker')
    path.write_text(json.dumps(doc),encoding='utf8')
    assert all(p.marker==0 for p in load_session(path))
dialog=QDialog(w);edit=QLineEdit(dialog);dialog.show();edit.setFocus();app.processEvents()
QTest.keyClick(edit,Qt.Key.Key_2,Qt.KeyboardModifier.ControlModifier)
assert w.current.marker==1
dialog.close();w.timer.stop();w.display_timer.stop()
print('PASS: all 5 shortcuts, toggle off, row color/icon survives refresh, save/load and old sessions, modal isolation.')
