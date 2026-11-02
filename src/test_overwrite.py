import os,sys
os.environ['QT_QPA_PLATFORM']='offscreen'
from packet import replace_bytes,validate_rules,apply_rules,compile_rules
before=b'00user01';after=b'00user0001'
raw=b'TRTEST|00user01    |NEXT|00user01'
expected=b'TRTEST|00user0001  |NEXT|00user01'
out,count=replace_bytes(raw,before,after,True,False,'overwrite')
assert out==expected and len(out)==len(raw) and out.index(b'NEXT')==raw.index(b'NEXT') and count==1
assert replace_bytes(b'abcdef|NEXT',b'abcdef',b'xy',True,False,'overwrite')[0]==b'xy    |NEXT'
try:replace_bytes(b'abc',b'abc',b'abcdef',mode='overwrite')
except ValueError:pass
else:raise AssertionError('boundary not checked')
r=validate_rules({'rules':[dict(name='legacy',direction='TX',contains='TRTEST',kind='text',find_text=before.decode(),replace_text=after.decode(),mode='overwrite',all=True)]})
assert r[0]['mode']=='overwrite' and not r[0]['all'] and not r[0]['allow_resize']
assert apply_rules(raw,'TX',r)[0]==expected
assert compile_rules(r,'cp949')[0]['mode']=='overwrite'
from PySide6.QtWidgets import QApplication
from rules_ui import RulesDialog
app=QApplication([])
d=RulesDialog(r)
assert d.checked_rules()==r
old=validate_rules({'rules':[dict(name='old',direction='TX',kind='text',find_text='abcdef',replace_text='xy',all=True,allow_resize=True)]})
assert old[0]['mode']=='replace'
d.populate(old);d.convert_overwrite();d.save()
assert d.result_value[0]['mode']=='overwrite'
d=RulesDialog([]);d.codes.setText('TRTEST');d.before.setText('00user01');d.after.setText('00user0001');d.add_quick()
assert d.checked_rules()[0]['mode']=='overwrite'
print('PASS: first match, pad/overwrite without shifting, boundaries, rule compile/export/import, conversion and new-rule default.')
