import os,sys
os.environ['QT_QPA_PLATFORM']='offscreen'
sys.excepthook=lambda *args:os._exit(1)
from PySide6.QtWidgets import QApplication
from app import Window
from rules_ui import RulesDialog
from packet import validate_rules
app=QApplication([])
w=Window()
rules=validate_rules({'rules':[dict(name=code,kind='text',direction='TX',contains=code,find_text='test01',replace_text='test02') for code in ('TEST001','TEST002')]})
w.apply_rule_list(rules)
d=w.inline_rules
d.table.selectRow(0);d.delete_selected()
assert len(w.rules)==1 and w.rules[0]['contains']=='TEST002'
assert len(w.backend.settings['compiledRules'])==1 and w.auto_rules.isChecked()
advanced=RulesDialog(w.rules,w)
assert advanced.table.rowCount()==1 and advanced.checked_rules()==w.rules
d.table.selectRow(0);d.delete_selected()
assert not w.rules and not w.backend.settings['compiledRules'] and not w.auto_rules.isChecked()
assert RulesDialog(w.rules,w).table.rowCount()==0
# Deleting while disabled must not unexpectedly enable mutation.
w.apply_rule_list(rules);w.auto_rules.setChecked(False)
d.table.selectRow(0);d.delete_selected()
assert len(w.rules)==1 and not w.auto_rules.isChecked() and not w.backend.settings['rules']
# A modal edit remains cancellable.
modal=RulesDialog(w.rules,w);modal.table.selectRow(0);modal.delete_selected();modal.reject()
assert len(w.rules)==1
# Invalid remaining rows leave both model and table unchanged.
w.apply_rule_list(rules);d.table.item(1,3).setText('')
d.table.selectRow(0);d.delete_selected()
assert len(w.rules)==2 and d.table.rowCount()==2 and '삭제를 적용하지' in d.error.text()
w.timer.stop();w.display_timer.stop()
print('PASS: inline delete updates advanced/backend, last deletion disables rules, OFF preserved, modal cancellation and invalid-edit guard.')
