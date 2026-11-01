"""Frida I/O and deadlines run independently of the GUI event loop."""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import deque
from pathlib import Path

import frida
from PySide6.QtCore import QObject, Signal


def agent_source(config, agent_path):
    mode = config.get('diagnostic', 'capture') if config.get('profile') == 'shinyoung' else 'capture'
    if mode in ('attach', 'java'):
        source = "send({kind:'log',text:'진단 시작: 패킷 후크·치환·보호 설정 변경 없음'});\n"
        if mode == 'java':
            source += "Java.perform(function(){send({kind:'log',text:'진단: Java bridge 실행됨 · 메서드 후크 없음'});});\n"
        source += "setTimeout(function(){send({kind:'log',text:'진단: 스크립트 로드 후 10초 유지됨 · 패킷 캡처 없음'});},10000);"
        return source
    prelude_path = Path(agent_path).with_name('compat-prelude.js')
    prelude = prelude_path.read_text(encoding='utf-8') if config.get('compatibility') and config.get('profile') != 'shinyoung' else ''
    return 'const BOOT_CONFIG = ' + json.dumps(config) + ';\n' + prelude + '\n' + Path(agent_path).read_text(encoding='utf-8')


class Backend(QObject):
    packet_received = Signal(object, bytes)
    settled = Signal(object, bytes)
    log = Signal(str)
    connection = Signal(str)
    applications = Signal(object)
    prepared = Signal(object, bytes)

    def __init__(self):
        super().__init__()
        self.lock = threading.RLock()
        self.pending = {}
        self.session = self.script = None
        self.generation = 0
        self.mode = 'demo'
        self.settings = dict(intercept=False, rules=False, tx=True, rx=True, filter='', timeout=15, requestSource='packet', allowResize=False)
        self.demo_counter = 0
        self.buffered = False
        self.display_queue = deque()
        self.queue_bytes = 0
        self.dropped = 0
        self.capture_count = 0
        self.thread_stats = {}

    def configure(self, settings):
        with self.lock:
            self.settings = dict(settings)
            script = self.script
        if script:
            try:
                script.post(dict(type='configure', settings=settings))
            except Exception as e:
                self.log.emit(f'설정 전달 실패: {e}')

    @staticmethod
    def device(address):
        if address.strip().upper() == 'USB':
            return frida.get_usb_device(timeout=5)
        return frida.get_device_manager().add_remote_device(address.strip())

    def list_applications(self, address):
        def run():
            try:
                apps = self.device(address).enumerate_applications()
                self.applications.emit([(a.identifier, a.name, a.pid) for a in apps])
            except Exception as e:
                self.log.emit(f'앱 목록 조회 실패: {e}')
                self.applications.emit([])
        threading.Thread(target=run, daemon=True).start()

    def connect_device(self, address, target, spawn, agent_path):
        self.disconnect()
        with self.lock:
            self.mode = 'live'
            self.buffered = True
            generation = self.generation
            config = dict(self.settings)
            if config.get('profile') == 'shinyoung':
                config['compatibility'] = False
                config['intercept'] = False
            self.capture_count = 0
            self.thread_stats = {}
        self.connection.emit('connecting')
        self.log.emit(f'연결 설정: 사전 설정={bool(config.get("compatibility"))}, 시작하며 연결={bool(spawn)}, 가로채기={bool(config.get("intercept"))}')
        if config.get('profile') == 'shinyoung':
            self.log.emit('신영 연결 모드: ' + config.get('diagnostic','capture'))

        def run():
            device = session = script = spawned_pid = None
            try:
                if frida.__version__.split('.')[0] != '16':
                    raise RuntimeError('이 agent는 Frida 16.x용입니다. requirements.txt의 버전을 사용하세요.')
                device = self.device(address)
                if spawn:
                    spawned_pid = device.spawn([target])
                    attach_target = spawned_pid
                elif target.isdecimal():
                    attach_target = int(target)
                else:
                    app = next((a for a in device.enumerate_applications() if a.identifier == target), None)
                    if app is not None and not app.pid:
                        raise RuntimeError('앱을 먼저 실행하거나 「시작하며 연결」을 선택하세요.')
                    attach_target = app.pid if app else target
                session = device.attach(attach_target)
                session.on('detached', lambda reason, *args: self._detached(generation, str(reason)))
                source = agent_source(config, agent_path)
                script = session.create_script(source)
                script.on('message', lambda m, d: self._message(generation, script, m, d))
                with self.lock:
                    if generation != self.generation:
                        session.detach()
                        return
                    self.session, self.script = session, script
                script.load()
                with self.lock:
                    if generation != self.generation:
                        return
                # Settings may have changed while device.attach was in progress.
                self.configure(self.settings)
                self.connection.emit('live')
                self.log.emit(f'Frida {frida.__version__} 연결됨 · {target}')
            except Exception as e:
                if generation == self.generation:
                    self.log.emit(f'연결 실패: {e}')
                    self.connection.emit('disconnected')
                if session:
                    try:
                        session.detach()
                    except Exception:
                        pass
                with self.lock:
                    if generation == self.generation:
                        self.session = self.script = None
            finally:
                if spawned_pid is not None:
                    try:
                        device.resume(spawned_pid)
                    except Exception as e:
                        self.log.emit(f'앱 재개 실패: {e}')
        threading.Thread(target=run, daemon=True).start()

    def _message(self, generation, script, message, data):
        if generation != self.generation:
            return
        if message.get('type') == 'error':
            self.log.emit('Agent 오류: ' + str(message.get('stack', message.get('description', ''))))
            return
        if message.get('type') != 'send':
            return
        meta = message.get('payload', {})
        if not isinstance(meta, dict):
            return
        kind = meta.get('kind')
        if kind == 'log':
            self.log.emit(str(meta.get('text', '')))
        elif kind == 'packet':
            self.capture_count += 1
            if self.capture_count <= 3:
                self.log.emit(f'수집 확인 #{self.capture_count}: {meta.get("direction")} · {meta.get("stage")} · {len(data or b"")} B · main={meta.get("mainThread")} · thread={meta.get("thread")}')
            self._register(meta, bytes(data or b''), script)
        elif kind == 'settled':
            # Agent acknowledgment is authoritative about bytes actually returned by the hook.
            with self.lock:
                entry = self.pending.pop(meta['id'], None)
                if entry:
                    entry['timer'].cancel()
            self._display('settled', meta, bytes(data or b''))
        elif kind == 'prepared':
            self._display('prepared', meta, bytes(data or b''))
        elif kind == 'stats':
            with self.lock:
                self.dropped += int(meta.get('suppressed', 0))
        elif kind == 'threadinfo':
            stage=str(meta.get('stage',''))
            info=self.thread_stats.setdefault(stage,{'main':False,'worker':False})
            field='main' if meta.get('mainThread') else 'worker'
            info[field]=True
            self.log.emit(f'수집 지점 스레드: {stage} · {"메인" if field=="main" else "작업"} · {meta.get("thread")}')

    def _display(self, kind, meta, data):
        if not self.buffered:
            {'packet': self.packet_received, 'settled': self.settled, 'prepared': self.prepared}[kind].emit(meta, data)
            return
        with self.lock:
            while self.display_queue and (len(self.display_queue) >= 300 or self.queue_bytes + len(data) > 8*1024*1024):
                old_kind, old_meta, old_data = self.display_queue.popleft()
                self.queue_bytes -= len(old_data)
                if old_kind == 'packet':
                    self.dropped += 1
                    if old_meta.get('pending'):
                        self.decide(old_meta['id'], 'original')
            self.display_queue.append((kind, meta, data))
            self.queue_bytes += len(data)

    def drain_display(self, maximum=100):
        with self.lock:
            events = []
            while self.display_queue and len(events) < maximum:
                event = self.display_queue.popleft()
                self.queue_bytes -= len(event[2])
                events.append(event)
        return events

    def clear_display(self):
        with self.lock:
            self.display_queue.clear()
            self.queue_bytes = 0
            self.dropped = 0

    def _register(self, meta, data, script=None):
        meta = dict(meta)
        if meta['pending']:
            timeout = max(3, min(300, int(meta.get('timeout', 60))))
            deadline = time.monotonic() + timeout
            timer = threading.Timer(timeout, lambda: self.decide(meta['id'], 'timeout'))
            timer.daemon = True
            with self.lock:
                if len(self.pending) >= 32:
                    if script:
                        script.post(dict(type='decision:' + meta['id'], action='original'))
                    meta['pending'] = False
                    meta['overflow'] = True
                else:
                    self.pending[meta['id']] = dict(original=data, deadline=deadline, timer=timer, script=script)
                    meta['deadline'] = deadline
                    timer.start()
        self._display('packet', meta, data)

    def decide(self, packet_id, action, replacement=None):
        with self.lock:
            entry = self.pending.get(packet_id)
            if entry is None or entry.get('decided'):
                return False
            if time.monotonic() >= entry['deadline']:
                action, replacement = 'timeout', None
            allow_resize = bool(self.settings.get('allowResize', False))
            if action == 'replace':
                if replacement is None or len(replacement) > 1_048_576:
                    raise ValueError('수정본은 최대 1 MiB의 바이트 데이터여야 합니다.')
                if len(replacement) != len(entry['original']) and not allow_resize:
                    raise ValueError('길이가 다릅니다. 「가변 길이 허용」을 켜세요.')
            entry['decided'] = True
            entry['timer'].cancel()
        script = entry['script']
        if script:
            try:
                script.post(dict(type='decision:' + packet_id, action=action, allowResize=allow_resize), replacement if action == 'replace' else None)
            except Exception as e:
                with self.lock:
                    self.pending.pop(packet_id, None)
                self._display('settled',dict(id=packet_id, action='cancelled', error=str(e)), entry['original'])
        else:
            with self.lock:
                self.pending.pop(packet_id, None)
            self._display('settled',dict(id=packet_id, action=action, error=''), replacement if action == 'replace' else entry['original'])
        return True

    def release_all(self):
        with self.lock:
            ids = list(self.pending)
        for packet_id in ids:
            self.decide(packet_id, 'original')

    def _detached(self, generation, reason):
        with self.lock:
            if generation != self.generation:
                return
            entries = self.pending
            self.pending = {}
            self.session = self.script = None
            self.generation += 1
        for packet_id, entry in entries.items():
            entry['timer'].cancel()
            self._display('settled',dict(id=packet_id, action='cancelled', error='연결 종료'), entry['original'])
        self.connection.emit('disconnected')
        self.log.emit('연결 종료: ' + reason)

    def disconnect(self):
        self.release_all()
        with self.lock:
            self.generation += 1
            session, self.session, self.script = self.session, None, None
            entries, self.pending = self.pending, {}
        for packet_id, entry in entries.items():
            entry['timer'].cancel()
            self._display('settled',dict(id=packet_id, action='cancelled', error='연결 종료 · 후크 적용 미확인'), entry['original'])
        if session:
            def detach():
                try:
                    session.detach()
                except Exception:
                    pass
            threading.Thread(target=detach, daemon=True).start()
        self.connection.emit('disconnected')

    def demo(self, direction=None):
        self.demo_counter += 1
        n = self.demo_counter
        direction = direction or ('TX' if n % 2 else 'RX')
        data = (f'DEMO001Q1|{n:04d}|0000|' + '테스트'.ljust(7) + '|0001250000|').encode('cp949')
        config = self.settings
        manual = config['intercept'] and config['tx' if direction == 'TX' else 'rx'] and config['filter'] in data.decode('cp949')
        meta = dict(id='demo-' + uuid.uuid4().hex[:10], direction=direction,
                    stage='DEMO / 가상 데이터', timestamp=time.time(), demo=True,
                    pending=bool(manual or config['rules']), manual=bool(manual), timeout=config['timeout'],mainThread=False,thread=100)
        self._register(meta, data)
