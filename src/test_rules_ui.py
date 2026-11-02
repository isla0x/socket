"""No phone access: batch editing, ordering, validation and app integration."""
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from PySide6.QtWidgets import QApplication, QDialog
from unittest.mock import patch
from rules_ui import RulesDialog
from packet import apply_rules
from app import Window

app = QApplication([])
d = RulesDialog([])
d.overwrite.setChecked(False)
d.codes.setText('DDAZ00032, DDAZ80028, DDAD20008, DEZF_9901')
d.direction.setCurrentIndex(d.direction.findData('TX'))
d.before.setText('user01')
d.after.setText('user0003')
d.add_quick()
rules = d.checked_rules()
assert len(rules) == 4 and all(r['allow_resize'] for r in rules)
for code in ('DDAZ00032', 'DDAZ80028', 'DDAD20008', 'DEZF_9901'):
    raw = (code + '|00user01|user01').encode()
    out, names = apply_rules(raw, 'TX', rules, 'cp949', True)
    assert out == (code + '|00user0003|user0003').encode() and len(names) == 1
    assert apply_rules(raw, 'RX', rules, 'cp949', True)[0] == raw
d.table.selectRow(3)
d.move(-1)
assert d.collect()[2]['contains'] == 'DEZF_9901'
d.delete_selected()
assert len(d.collect()) == 3
saved = d.checked_rules()
d.populate(saved)
assert d.checked_rules() == saved
d.table.item(0, 3).setText('')
d.save()
assert d.result_value is None and d.error.text()
d.populate(saved)
d.save()
assert d.result_value == saved
window = Window()
with patch('app.RulesDialog.exec', return_value=QDialog.DialogCode.Accepted), patch('app.RulesDialog.__init__', lambda self, *args, **kw: (QDialog.__init__(self), setattr(self, 'result_value', saved))[-1]):
    window.edit_rules()
assert window.rules == saved and window.auto_rules.isChecked() and window.allow_resize.isChecked()
assert not window.intercept.isChecked()
window.timer.stop()
window.display_timer.stop()
print('PASS: multiple codes, exact RX/TX scope, all occurrences, resize, reorder/delete, validation, save enables rules.')
