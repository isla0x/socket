"""Run: python -m unittest -v test_app; optional real Frida transport: --transport."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from packet import (Packet, apply_rules, edit_field, field_value, load_session, parse_hex,
                    parse_visible, save_session, validate_fields, validate_rules, visible,
                    replace_bytes,compile_rules,validate_lengths,update_lengths)


class ByteTests(unittest.TestCase):
    def test_all_bytes_roundtrip(self):
        for encoding in ('cp949', 'utf-8', 'ascii'):
            raw = bytes(range(256)) + b'\\x41\r\n\x00\tend'
            self.assertEqual(parse_visible(visible(raw, encoding), encoding), raw)
        raw = '\u2028\u2029한글\r\n\\x00'.encode('utf-8')
        self.assertEqual(parse_visible(visible(raw,'utf-8'),'utf-8'),raw)

    def test_korean_and_invalid_inputs(self):
        self.assertEqual(parse_visible('테스트'), '테스트'.encode('cp949'))
        for bad in ('\\q', '\\xGG', '\\x1', '\\u123'):
            with self.assertRaises(ValueError):
                parse_visible(bad)
        with self.assertRaises(UnicodeEncodeError):
            parse_visible('🙂')
        for bad in ('0', '0x41', 'aa zz'):
            with self.assertRaises(ValueError):
                parse_hex(bad)

    def test_fixed_fields(self):
        f = validate_fields({'fields':[{'name':'이름','offset':1,'length':6}]})[0]
        raw = b'|' + '테스트'.encode('cp949') + b'|'
        edited = edit_field(raw,f,'가','cp949')
        self.assertEqual(len(raw),len(edited))
        self.assertEqual(edited,b'|'+'가'.encode('cp949')+b'    |')
        self.assertEqual(field_value(edited,f,'cp949'),'가    ')
        with self.assertRaises(ValueError):
            edit_field(raw,f,'너무긴한글','cp949')
        with self.assertRaises(ValueError):
            edit_field(b'',f,'x','cp949')

    def test_numeric_fields(self):
        f = validate_fields({'fields':[{'name':'n','offset':0,'length':2,'type':'uintle'}]})[0]
        self.assertEqual(edit_field(b'\0\0',f,'513','cp949'),b'\x01\x02')
        with self.assertRaises(OverflowError):
            edit_field(b'\0\0',f,'65536','cp949')

    def test_rules(self):
        rules = validate_rules({'rules':[dict(direction='RX', contains='DEMO',find_hex='30 30', replace_hex='30 31', all=True)]})
        raw=b'DEMO|00|00'
        self.assertEqual(apply_rules(raw,'RX',rules)[0],b'DEMO|01|01')
        self.assertEqual(apply_rules(raw,'TX',rules)[0],raw)
        with self.assertRaises(ValueError):
            validate_rules({'rules':[dict(find_hex='00',replace_hex='00 00')]})

    def test_session_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'session.json'
            p=Packet('x','TX','stage',time.time(),b'\x00\xffabc',pending=True)
            p.draft=b'\x00\xffABC'
            p.final=p.draft
            save_session(path,[p])
            loaded=load_session(path)[0]
            self.assertEqual((loaded.original,loaded.draft,loaded.final),(p.original,p.draft,p.final))
            self.assertFalse(loaded.pending)
            self.assertEqual(loaded.origin,'import')
            doc=json.loads(path.read_text(encoding='utf-8'))
            doc['packets'][0]['original']='###'
            path.write_text(json.dumps(doc),encoding='utf-8')
            with self.assertRaises(ValueError):
                load_session(path)

    def test_schema_validation(self):
        for f in ({'name':'bad','offset':-1,'length':2}, {'name':'bad','offset':True,'length':2}, {'name':'bad','offset':0,'length':9,'type':'uintbe'}):
            with self.assertRaises(ValueError):
                validate_fields({'fields':[f]})

    def test_variable_text_replacement(self):
        raw=b'user=user01|user=user01'
        with self.assertRaises(ValueError):
            replace_bytes(raw,b'user01',b'user002')
        result,count=replace_bytes(raw,b'user01',b'user002',True,True)
        self.assertEqual(result,b'user=user002|user=user002')
        self.assertEqual((count,len(result)-len(raw)),(2,2))
        rules=validate_rules({'rules':[dict(kind='text',find_text='user01',replace_text='user002',allow_resize=True)]})
        self.assertEqual(apply_rules(raw,'TX',rules,allow_resize=True)[0],b'user=user002|user=user01')
        self.assertEqual(compile_rules(rules,'cp949')[0]['after'],list(b'user002'))
        with self.assertRaises(ValueError):
            replace_bytes(b'a'*1000,b'a',b'x'*10000,True,True)

    def test_length_fields(self):
        fields=validate_lengths({'length_fields':[dict(offset=0,width=4,type='ascii',adjust=-4,direction='TX')]})
        self.assertEqual(update_lengths(b'0000user01',fields,'TX','packet'),b'0006user01')
        self.assertEqual(update_lengths(b'0000user002',fields,'TX','packet'),b'0007user002')
        self.assertEqual(update_lengths(b'0000user002',fields,'RX','packet'),b'0000user002')
        with self.assertRaises(ValueError):
            update_lengths(b'x',fields,'TX','packet')


class BackendTests(unittest.TestCase):
    def test_bounded_display_queue(self):
        from backend import Backend
        backend=Backend()
        backend.buffered=True
        for i in range(2000):
            backend._display('packet',dict(id=str(i),pending=False),b'x'*4096)
        self.assertLessEqual(len(backend.display_queue),300)
        self.assertLessEqual(backend.queue_bytes,8*1024*1024)
        self.assertEqual(backend.dropped,1700)
        self.assertEqual(len(backend.drain_display()),100)
        backend.clear_display()
        self.assertEqual(backend.queue_bytes,0)
    def test_exactly_once_and_disconnect(self):
        from PySide6.QtCore import QCoreApplication
        from backend import Backend
        application = QCoreApplication.instance() or QCoreApplication([])
        class Script:
            def __init__(self): self.posts=[]
            def post(self,*args): self.posts.append(args)
        script=Script()
        backend=Backend()
        backend._register(dict(id='one',pending=True,timeout=3),b'abc',script)
        with self.assertRaises(ValueError):
            backend.decide('one','replace',b'x')
        self.assertTrue(backend.decide('one','replace',b'ABC'))
        self.assertFalse(backend.decide('one','original'))
        self.assertEqual(len(script.posts),1)
        self.assertIn('one',backend.pending)  # Wait for authoritative agent acknowledgment.
        backend._message(backend.generation,script,dict(type='send',payload=dict(kind='settled',id='one',action='replace')),b'ABC')
        self.assertNotIn('one',backend.pending)
        backend._register(dict(id='two',pending=True,timeout=3),b'abc',script)
        backend.disconnect()
        self.assertFalse(backend.pending)
        self.assertEqual(script.posts[-1][0]['action'],'original')

    def test_expiry_wins_over_late_edit(self):
        from backend import Backend
        class Script:
            def __init__(self): self.posts=[]
            def post(self,*args): self.posts.append(args)
        script=Script()
        backend=Backend()
        backend._register(dict(id='late',pending=True,timeout=3),b'abc',script)
        backend.pending['late']['deadline']=time.monotonic()-1
        self.assertTrue(backend.decide('late','replace',b'ABC'))
        self.assertEqual(script.posts[-1][0]['action'],'timeout')
        backend.disconnect()


def transport_check():
    """Exercise the shipped agent and Backend with a real local Frida session."""
    import frida
    from PySide6.QtCore import QCoreApplication, Qt
    from backend import Backend
    application=QCoreApplication.instance() or QCoreApplication([])
    process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    session=None
    try:
        session=frida.attach(process.pid)
        backend=Backend()
        config=dict(testMode=True,intercept=True,timeout=3)
        source='const BOOT_CONFIG='+json.dumps(config)+';\n'+Path(__file__).with_name('agent.js').read_text(encoding='utf-8')
        script=session.create_script(source)
        backend.script,backend.session=script,session
        script.on('message',lambda m,d:backend._message(backend.generation,script,m,d))
        choice=['replace']
        settlements=[]
        def choose(meta,data):
            if choice[0]=='replace':
                backend.decide(meta['id'],'replace',bytes([0,127,255,128,67,68]))
            elif choice[0]=='invalid':
                script.post({'type':'decision:'+meta['id'],'action':'replace'},b'x')
            elif choice[0]=='resize':
                backend.decide(meta['id'],'replace',b'user002')
        backend.packet_received.connect(choose,Qt.ConnectionType.DirectConnection)
        backend.settled.connect(lambda m,d:settlements.append((m,d)),Qt.ConnectionType.DirectConnection)
        script.load()
        original=[0,127,128,255,65,66]
        assert script.exports_sync.inspect(original)==[0,127,255,128,67,68]
        assert settlements[-1][0]['action']=='replace'
        choice[0]='invalid'
        assert script.exports_sync.inspect(original)==original
        assert settlements[-1][0]['action']=='rejected'
        choice[0]='resize'
        backend.configure(dict(backend.settings,intercept=True,allowResize=True))
        assert script.exports_sync.inspect(list(b'user01'))==list(b'user002')
        # UI-thread calls must never wait for a decision, even with interception enabled.
        choice[0]='observe'
        started=time.monotonic()
        assert script.exports_sync.inspect(original,True)==original
        assert time.monotonic()-started<1
        rules=validate_rules({'rules':[dict(kind='text',find_text='user01',replace_text='user002',allow_resize=True)]})
        backend.configure(dict(backend.settings,intercept=True,rules=True,compiledRules=compile_rules(rules,'cp949')))
        started=time.monotonic()
        assert script.exports_sync.inspect(list(b'user01'),True)==list(b'user002')
        assert time.monotonic()-started<1
        assert not backend.pending
        backend.configure(dict(backend.settings,intercept=True,rules=False,timeout=3))
        choice[0]='timeout'
        started=time.monotonic()
        assert script.exports_sync.inspect(original)==original
        assert 2.5 <= time.monotonic()-started < 10
        assert settlements[-1][0]['action']=='timeout'
        assert not backend.pending
        print('REAL FRIDA TRANSPORT PASS: fixed/variable bytes, length rejection, UI-thread no wait, inline text rule, timeout -> original.',flush=True)
    finally:
        if session:
            session.detach()
        process.terminate()
        process.wait(timeout=5)


if __name__=='__main__':
    if '--transport' in sys.argv:
        transport_check()
    else:
        unittest.main()
