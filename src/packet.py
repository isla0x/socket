"""Byte-preserving editing, bounded field schemas and portable session files."""
from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

MAX_PACKET = 1_048_576
MAX_EVENTS = 500


def visible(data: bytes, encoding: str = 'cp949') -> str:
    text = data.decode(encoding, errors='surrogateescape')
    # Some code pages have noncanonical mappings; preserve those bytes explicitly.
    if text.encode(encoding, errors='surrogateescape') != data:
        return ''.join(f'\\x{b:02x}' for b in data)
    out = []
    for c in text:
        n = ord(c)
        if c == '\\':
            out.append('\\\\')
        elif c == '\r':
            out.append('\\r')
        elif 0xDC80 <= n <= 0xDCFF:
            out.append(f'\\x{n - 0xDC00:02x}')
        elif n < 32 and c not in '\n\t':
            out.append(f'\\x{n:02x}')
        elif n in (0x2028, 0x2029):
            out.append(f'\\u{n:04x}')
        else:
            out.append(c)
    return ''.join(out)


def parse_visible(text: str, encoding: str = 'cp949') -> bytes:
    chunks = re.split(r'(\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[\\rnt]))', text)
    out = bytearray()
    for chunk in chunks:
        if not chunk:
            continue
        if chunk.startswith('\\x') and len(chunk) == 4:
            out.append(int(chunk[2:], 16))
        elif chunk.startswith('\\u') and len(chunk) == 6:
            out.extend(chr(int(chunk[2:], 16)).encode(encoding))
        elif chunk in ('\\\\', '\\r', '\\n', '\\t'):
            out.extend({'\\\\': '\\', '\\r': '\r', '\\n': '\n', '\\t': '\t'}[chunk].encode(encoding))
        else:
            if '\\' in chunk:
                raise ValueError('알 수 없는 이스케이프입니다. 역슬래시는 \\\\, 바이트는 \\x00 형식을 사용하세요.')
            out.extend(chunk.encode(encoding, errors='strict'))
    if len(out) > MAX_PACKET:
        raise ValueError('편집 데이터는 최대 1 MiB입니다.')
    return bytes(out)


def parse_hex(text: str) -> bytes:
    if not re.fullmatch(r'[0-9a-fA-F\s]*', text):
        raise ValueError('Hex에는 두 자리 바이트와 공백만 입력하세요. 오프셋/0x 접두사는 제외합니다.')
    data = bytes.fromhex(text)
    if len(data) > MAX_PACKET:
        raise ValueError('편집 데이터는 최대 1 MiB입니다.')
    return data


def hexdump(data: bytes) -> str:
    return '\n'.join(f'{i:08x}  {data[i:i+16].hex(" "):<47}  |' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16]) + '|' for i in range(0, len(data), 16))


def transaction(data: bytes) -> str:
    m = re.search(rb'(?<![A-Z0-9])(?:S[A-Z0-9]{6}[QU][0-9]|DEMO[0-9]{3}[QU][0-9])(?![A-Z0-9])', data)
    return m.group().decode('ascii') if m else '미해석'


def validate_fields(value) -> list[dict]:
    fields = value.get('fields') if isinstance(value, dict) else None
    if not isinstance(fields, list) or len(fields) > 200:
        raise ValueError('fields 배열이 필요합니다. 최대 200개입니다.')
    clean = []
    for f in fields:
        if not isinstance(f, dict):
            raise ValueError('필드 정의는 객체여야 합니다.')
        name, offset, length, kind = f.get('name'), f.get('offset'), f.get('length'), f.get('type', 'text')
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise ValueError('필드 이름은 1~80자입니다.')
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 1 or offset + length > MAX_PACKET:
            raise ValueError(f'{name}: offset과 length 범위를 확인하세요.')
        if kind not in ('text', 'hex', 'uintbe', 'uintle'):
            raise ValueError(f'{name}: 지원하지 않는 type입니다.')
        if kind.startswith('uint') and length > 8:
            raise ValueError('정수 필드는 최대 8바이트입니다.')
        pad = f.get('pad', 32)
        if type(pad) is not int or not 0 <= pad <= 255:
            raise ValueError('pad는 0~255의 바이트 값입니다.')
        clean.append(dict(name=name, offset=offset, length=length, type=kind, pad=pad))
    return clean


def field_value(data: bytes, f: dict, encoding: str) -> str:
    start, length = f['offset'], f['length']
    if start + length > len(data):
        raise ValueError('패킷 범위를 벗어납니다.')
    part = data[start:start+length]
    if f['type'] == 'text':
        return visible(part, encoding)
    if f['type'] == 'hex':
        return part.hex(' ')
    return str(int.from_bytes(part, 'big' if f['type'] == 'uintbe' else 'little'))


def edit_field(data: bytes, f: dict, value: str, encoding: str) -> bytes:
    start, length = f['offset'], f['length']
    if start + length > len(data):
        raise ValueError('패킷 범위를 벗어납니다.')
    if f['type'] == 'text':
        raw = parse_visible(value, encoding)
        if len(raw) > length:
            raise ValueError(f'{length} B 필드에 {len(raw)} B를 넣을 수 없습니다.')
        raw = raw.ljust(length, bytes([f['pad']]))
    elif f['type'] == 'hex':
        raw = parse_hex(value)
        if len(raw) != length:
            raise ValueError(f'정확히 {length} B를 입력하세요.')
    else:
        raw = int(value, 10).to_bytes(length, 'big' if f['type'] == 'uintbe' else 'little', signed=False)
    return data[:start] + raw + data[start+length:]


def validate_rules(value) -> list[dict]:
    rules = value.get('rules') if isinstance(value, dict) else None
    if not isinstance(rules, list) or len(rules) > 100:
        raise ValueError('rules 배열이 필요합니다. 최대 100개입니다.')
    clean = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError('규칙은 객체여야 합니다.')
        direction = rule.get('direction', 'ANY')
        kind = rule.get('kind', 'hex')
        encoding = rule.get('encoding', 'cp949')
        if kind not in ('hex', 'text') or encoding not in ('cp949', 'utf-8', 'ascii'):
            raise ValueError('kind는 hex/text, encoding은 cp949/utf-8/ascii입니다.')
        if kind == 'text':
            if not isinstance(rule.get('find_text'), str) or not isinstance(rule.get('replace_text'), str):
                raise ValueError('문자열 규칙에는 find_text와 replace_text가 필요합니다.')
            before, after = rule['find_text'].encode(encoding), rule['replace_text'].encode(encoding)
        else:
            before, after = parse_hex(rule.get('find_hex', '')), parse_hex(rule.get('replace_hex', ''))
        allow_resize = rule.get('allow_resize', False)
        if type(allow_resize) is not bool:
            raise ValueError('allow_resize는 true/false입니다.')
        if direction not in ('ANY', 'TX', 'RX') or not before:
            raise ValueError('규칙 방향은 ANY/TX/RX이며 찾기는 비어 있을 수 없습니다.')
        if len(before) != len(after) and not allow_resize:
            raise ValueError('길이가 다른 규칙은 allow_resize: true를 설정하세요.')
        if max(len(before), len(after)) > MAX_PACKET:
            raise ValueError('규칙 바이트는 최대 1 MiB입니다.')
        contains = rule.get('contains', '')
        if not isinstance(contains, str) or len(contains) > 500:
            raise ValueError('contains는 500자 이하 문자열입니다.')
        if type(rule.get('enabled', True)) is not bool or type(rule.get('all', False)) is not bool:
            raise ValueError('enabled와 all은 true/false입니다.')
        normalized = dict(name=str(rule.get('name', '치환'))[:80], direction=direction, contains=contains,
                          kind=kind, encoding=encoding, allow_resize=allow_resize,
                          enabled=rule.get('enabled', True), all=rule.get('all', False))
        if kind == 'text':
            normalized.update(find_text=rule['find_text'], replace_text=rule['replace_text'])
        else:
            normalized.update(find_hex=before.hex(), replace_hex=after.hex())
        clean.append(normalized)
    return clean


def replace_bytes(data: bytes, before: bytes, after: bytes, replace_all=False, allow_resize=False) -> tuple[bytes, int]:
    if not before:
        raise ValueError('찾을 값은 비워 둘 수 없습니다.')
    count = data.count(before) if replace_all else int(before in data)
    if count and len(before) != len(after) and not allow_resize:
        raise ValueError('길이가 다릅니다. 「가변 길이 허용」을 켜거나 고정 폭 필드 편집을 사용하세요.')
    size = len(data) + count * (len(after) - len(before))
    if size > MAX_PACKET:
        raise ValueError('치환 결과가 최대 1 MiB를 넘습니다.')
    return data.replace(before, after, -1 if replace_all else 1), count


def apply_rules(data: bytes, direction: str, rules: list[dict], encoding: str = 'cp949', allow_resize=False) -> tuple[bytes, list[str]]:
    names = []
    for rule in rules:
        if not rule['enabled'] or rule['direction'] not in ('ANY', direction):
            continue
        if rule['contains'] not in data.decode(encoding, errors='replace'):
            continue
        if rule.get('kind') == 'text':
            before, after = rule['find_text'].encode(rule['encoding']), rule['replace_text'].encode(rule['encoding'])
        else:
            before, after = bytes.fromhex(rule['find_hex']), bytes.fromhex(rule['replace_hex'])
        if before in data:
            updated, _ = replace_bytes(data, before, after, rule['all'], allow_resize and rule.get('allow_resize', False))
            if updated != data:
                names.append(rule['name'])
            data = updated
    return data, names


def compile_rules(rules: list[dict], encoding: str) -> list[dict]:
    compiled = []
    total = 0
    for rule in rules:
        if not rule['enabled']:
            continue
        if rule.get('kind') == 'text':
            before, after = rule['find_text'].encode(rule['encoding']), rule['replace_text'].encode(rule['encoding'])
        else:
            before, after = bytes.fromhex(rule['find_hex']), bytes.fromhex(rule['replace_hex'])
        contains = rule['contains'].encode(encoding)
        total += len(before) + len(after) + len(contains)
        if total > 65_536:
            raise ValueError('활성 규칙의 찾기·바꾸기 바이트 합계는 최대 64 KiB입니다.')
        compiled.append(dict(name=rule['name'], direction=rule['direction'], before=list(before), after=list(after),
                             contains=list(contains), all=rule['all'], allowResize=rule.get('allow_resize', False)))
    return compiled


def validate_lengths(value) -> list[dict]:
    fields = value.get('length_fields') if isinstance(value, dict) else None
    if not isinstance(fields, list) or len(fields) > 20:
        raise ValueError('length_fields 배열이 필요합니다. 최대 20개입니다.')
    clean = []
    for f in fields:
        if not isinstance(f, dict):
            raise ValueError('길이 정의는 객체여야 합니다.')
        offset, width = f.get('offset'), f.get('width')
        kind, adjust = f.get('type', 'ascii'), f.get('adjust', 0)
        direction, stage = f.get('direction', 'ANY'), f.get('stage_contains', '')
        if type(offset) is not int or type(width) is not int or offset < 0 or not 1 <= width <= 10 or offset+width > MAX_PACKET:
            raise ValueError('길이 정보의 offset/width 범위를 확인하세요.')
        if kind not in ('ascii', 'uintbe', 'uintle') or (kind != 'ascii' and width > 8):
            raise ValueError('type은 ascii/uintbe/uintle이며 이진 정수는 최대 8바이트입니다.')
        if type(adjust) is not int or abs(adjust) > MAX_PACKET or direction not in ('ANY','TX','RX') or not isinstance(stage, str):
            raise ValueError('adjust, direction, stage_contains를 확인하세요.')
        clean.append(dict(offset=offset,width=width,type=kind,adjust=adjust,direction=direction,stage_contains=stage[:300]))
    return clean


def update_lengths(data: bytes, fields: list[dict], direction: str, stage: str) -> bytes:
    active = [f for f in fields if f['direction'] in ('ANY', direction) and f['stage_contains'] in stage]
    ranges = []
    for f in active:
        start, end = f['offset'], f['offset']+f['width']
        if end > len(data) or any(start < b and a < end for a,b in ranges):
            raise ValueError('길이 정보가 패킷 범위를 벗어나거나 서로 겹칩니다.')
        ranges.append((start,end))
        value = len(data) + f['adjust']
        if value < 0:
            raise ValueError('계산된 길이가 음수입니다.')
        if f['type'] == 'ascii':
            raw = str(value).zfill(f['width']).encode('ascii')
            if len(raw) != f['width']:
                raise ValueError('길이 정보가 정의된 자릿수를 넘습니다.')
        else:
            raw = value.to_bytes(f['width'], 'big' if f['type'] == 'uintbe' else 'little')
        data = data[:start] + raw + data[end:]
    return data


@dataclass
class Packet:
    id: str
    direction: str
    stage: str
    timestamp: float
    original: bytes
    origin: str = 'live'
    pending: bool = False
    status: str = '캡처'
    deadline: float = 0
    draft: bytes = field(default=b'')
    final: bytes | None = None
    error: str = ''
    note: str = ''
    demo_profile: bool = False
    invalid_text: str | None = None
    invalid_hex: str | None = None
    repeats: int = 1
    last_seen: float = 0
    sequence: int = 0
    main_thread: bool | None = None
    thread_id: int | None = None
    marker: int = 0

    def __post_init__(self):
        self.draft = self.original
        self.last_seen = self.timestamp


def save_session(path: Path, packets: list[Packet]):
    rows = []
    for p in packets:
        row = {k: getattr(p, k) for k in ('id', 'direction', 'stage', 'timestamp', 'origin', 'status', 'note', 'demo_profile','repeats','last_seen','main_thread','thread_id','marker')}
        row.update(original=base64.b64encode(p.original).decode(), draft=base64.b64encode(p.draft).decode(),
                   final=None if p.final is None else base64.b64encode(p.final).decode())
        rows.append(row)
    document = json.dumps(dict(format='socket-inspector', version=1, packets=rows), ensure_ascii=False, indent=2)
    if len(document.encode('utf-8')) > 25_000_000:
        raise ValueError('세션 파일 한도 25 MB를 넘습니다. 캡처를 나누어 저장하세요.')
    fd, temporary = tempfile.mkstemp(prefix='.inspector-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(document)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_session(path: Path) -> list[Packet]:
    if path.stat().st_size > 25_000_000:
        raise ValueError('세션 파일은 최대 25 MB입니다.')
    doc = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict) or doc.get('format') != 'socket-inspector' or doc.get('version') != 1:
        raise ValueError('Socket Inspector v1 세션 파일이 아닙니다.')
    rows = doc.get('packets')
    if not isinstance(rows, list) or len(rows) > MAX_EVENTS:
        raise ValueError(f'세션은 최대 {MAX_EVENTS}건입니다.')
    packets = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or row.get('direction') not in ('TX', 'RX'):
            raise ValueError('잘못된 이벤트 형식입니다.')
        def blob(key):
            value = base64.b64decode(row[key], validate=True)
            if len(value) > MAX_PACKET:
                raise ValueError('패킷은 최대 1 MiB입니다.')
            return value
        timestamp = float(row['timestamp'])
        datetime.fromtimestamp(timestamp)  # Reject NaN, infinity and out-of-range timestamps before touching the UI.
        p = Packet(f'import-{i}', row['direction'], str(row.get('stage', ''))[:300], timestamp, blob('original'),
                   origin='import', status='가져옴', note=str(row.get('note', ''))[:1000], demo_profile=row.get('demo_profile') is True)
        p.draft = blob('draft')
        p.main_thread = row.get('main_thread') if type(row.get('main_thread')) is bool else None
        p.thread_id = row.get('thread_id') if type(row.get('thread_id')) is int else None
        marker = row.get('marker', 0)
        if type(marker) is not int or not 0 <= marker <= 5:
            raise ValueError('패킷 색상 번호는 0~5 정수여야 합니다.')
        p.marker = marker
        if row.get('final') is not None:
            p.final = blob('final')
        repeats = row.get('repeats',1)
        if type(repeats) is int and repeats>=1:
            p.repeats = repeats
        packets.append(p)
    return packets


DEMO_FIELDS = validate_fields({'fields': [
    {'name': '거래 코드', 'offset': 0, 'length': 9},
    {'name': '요청 번호', 'offset': 10, 'length': 4},
    {'name': '결과 코드', 'offset': 15, 'length': 4},
    {'name': '표시 이름', 'offset': 20, 'length': 10},
    {'name': '금액', 'offset': 31, 'length': 10},
]})
