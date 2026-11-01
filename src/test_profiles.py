import os
import sys
sys.excepthook=lambda *args: os._exit(1)
os.environ['QT_QPA_PLATFORM']='offscreen'
from PySide6.QtWidgets import QApplication
from app import Window
from packet import validate_rules
app=QApplication([])
w=Window()
rule=validate_rules({'rules':[dict(name='kyobo',kind='text',find_text='a',replace_text='b',contains='KY',direction='TX')]})
w.rules=rule
w.profile.setCurrentIndex(1)
assert w.target.currentText()=='com.shinyoung.mts' and not w.rules
assert not w.compatibility.isEnabled() and not w.intercept.isEnabled()
assert not w.spawn.isChecked()
w.rules=validate_rules({'rules':[dict(name='shinyoung',kind='text',find_text='a',replace_text='b',contains='SY',direction='RX')]})
w.profile.setCurrentIndex(0)
assert w.rules==rule and w.target.currentText()=='kr.com.wink'
assert w.compatibility.isEnabled() and w.intercept.isEnabled()
w.profile.setCurrentIndex(1)
assert w.rules[0]['name']=='shinyoung'
w.connection_changed('live')
assert not w.profile.isEnabled()
w.connection_changed('disconnected')
assert w.profile.isEnabled()
w.timer.stop();w.display_timer.stop()
print('PASS: separate profiles/rules, package selection, unsupported controls disabled, connection locks profile.')
