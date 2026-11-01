"""UI-only regression: no Android or network connection."""
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from app import Window
from packet import visible

app=QApplication([])
window=Window()
window.show()
app.processEvents()
assert not window.current.pending
assert window.apply_button.text()=='다음 요청 잡기'
window.apply_button.click()
p=window.current
assert p.pending and p.direction=='TX'
assert '대기 중' in window.manual_banner.text()
assert window.apply_button.text()=='수정본 보내기'
window.edited_text.setPlainText(visible(p.original).replace('0001250000','0002250000'))
window.apply_button.click()
assert not p.pending and p.final==p.draft and p.final!=p.original
assert '이미 처리' in window.manual_banner.text()

# Browse with normal arrows from the list and readonly original inspector.
window.table.selectRow(0)
window.table.setFocus()
QTest.keyClick(window.table,Qt.Key.Key_Down)
assert window.table.currentRow()==1
window.original_text.setFocus()
QTest.keyClick(window.original_text,Qt.Key.Key_Up)
assert window.table.currentRow()==0

# Skip hidden rows and preserve drafts while switching.
window.table.setRowHidden(1,True)
QTest.keyClick(window.original_text,Qt.Key.Key_Down)
assert window.table.currentRow()==2
current=window.current
window.edited_text.setFocus()
QTest.keyClick(window.edited_text,Qt.Key.Key_Down)
assert window.table.currentRow()==3
QTest.keyClick(window.edited_text,Qt.Key.Key_Up,Qt.KeyboardModifier.AltModifier)
assert window.table.currentRow()==2
window.table.selectRow(0)
window.table.setFocus()
QTest.keyClick(window.table,Qt.Key.Key_Up)
assert window.table.currentRow()==0

# Pending requests preempt history selection, survive filters, and are editable.
window.search.setText('not-a-real-packet')
window.arm_manual()
pending=window.current
assert pending.pending and not window.table.isRowHidden(window.table.currentRow())
window.table.selectRow(0)
assert window.apply_button.text().startswith('대기 패킷 보기')
window.apply_button.click()
assert window.current is pending
window.pass_button.click()
assert not pending.pending and pending.final==pending.original

# Stopping capture releases waits and disables mutation controls.
window.arm_manual()
pending=window.current
assert pending.pending
window.capture_enabled.setChecked(False)
assert not window.intercept.isChecked() and not pending.pending
assert window.backend.settings['capture'] is False
window.session_dirty=False
window.backend.disconnect()
window.close()
print('PASS: Fiddler-style pending/edit/send, original pass, arrows/Alt arrows, filters, capture stop.')
