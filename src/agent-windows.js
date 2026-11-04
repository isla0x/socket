/* Windows observation only. No replace(), writes, waits or application patches. */
'use strict';
let config = Object.assign({capture: true, pcSource: 'both'}, BOOT_CONFIG);
const LIMIT = 65536, MAX_PENDING = 256;
const installed = new Set(), pending = new Map();
let serial = 0, count = 0, bytes = 0, suppressed = 0, epoch = Date.now();
function log(text) { send({kind: 'log', text: text}); }
function settings() {
    recv('configure', function (m) { config = Object.assign({}, config, m.settings); settings(); });
}
settings();
function wanted(layer) { return config.capture && (config.pcSource === 'both' || config.pcSource === layer); }
function eligible(layer) {
    if (!wanted(layer)) return false;
    if (Date.now() - epoch >= 1000) {
        if (suppressed) send({kind: 'stats', suppressed: suppressed});
        count = bytes = suppressed = 0; epoch = Date.now();
    }
    if (count >= 100 || bytes >= 1048576) { suppressed++; return false; }
    return true;
}
function publish(direction, stage, data, total, note) {
    if (!data || !data.byteLength) return;
    const now = Date.now();
    if (now - epoch >= 1000) {
        if (suppressed) send({kind: 'stats', suppressed: suppressed});
        count = bytes = suppressed = 0; epoch = now;
    }
    if (count >= 100 || bytes + data.byteLength > 1048576) { suppressed++; return; }
    count++; bytes += data.byteLength;
    send({kind: 'packet', id: 'win-' + Process.id + '-' + (++serial), direction: direction,
        stage: stage, timestamp: now / 1000, pending: false, thread: Process.getCurrentThreadId(),
        note: note + (total > data.byteLength ? ' · 앞 ' + data.byteLength + '/' + total + ' B만 표시' : '')}, data);
}
function descriptors(p, n) {
    if (n < 1 || n > 64) throw new Error('WSABUF count out of bounds');
    const result = [], stride = Process.pointerSize === 8 ? 16 : 8;
    for (let i = 0; i < n; i++) {
        const item = p.add(i * stride), length = item.readU32();
        result.push({pointer: item.add(Process.pointerSize === 8 ? 8 : 4).readPointer(), length: length});
    }
    return result;
}
function gather(parts, total) {
    let remaining = Math.min(LIMIT, total), offset = 0;
    if (remaining <= 0) return null;
    const result = new Uint8Array(remaining);
    for (const part of parts) {
        const n = Math.min(remaining, part.length);
        if (n) result.set(new Uint8Array(part.pointer.readByteArray(n)), offset);
        offset += n; remaining -= n;
        if (!remaining) break;
    }
    return result.buffer.slice(0, offset);
}
function capacity(parts) { return parts.reduce((n, p) => n + p.length, 0); }
function report(entry, n) {
    if (!wanted('socket') || n <= 0 || n > capacity(entry.parts)) return;
    const data = entry.snapshot ? entry.snapshot.slice(0, Math.min(n, entry.snapshot.byteLength)) : gather(entry.parts, n);
    publish(entry.direction, 'PC · ' + entry.api + ' · socket=' + entry.socket, data, n,
        '소켓 I/O 조각 · 전문 경계/암호화 여부 미확인');
}
function finish(overlapped, n, error) {
    const key = overlapped.toString(), entry = pending.get(key);
    if (!entry) return;
    pending.delete(key);
    if (!error) report(entry, n);
}
function attach(moduleName, name, callbacks) {
    const address = Module.findExportByName(moduleName, name);
    if (!address || installed.has(address.toString())) return;
    Interceptor.attach(address, callbacks);
    installed.add(address.toString());
    log('Hook ready: PC · ' + moduleName + '!' + name);
}
function callbackAt(address) {
    if (address.isNull() || installed.has(address.toString())) return;
    Interceptor.attach(address, {onEnter(args) {
        try { finish(args[2], args[1].toUInt32(), args[0].toUInt32()); } catch (_) {}
    }});
    installed.add(address.toString());
}
function installSockets() {
    ['send', 'recv', 'sendto', 'recvfrom'].forEach(function (api) {
        const direction = api.indexOf('send') === 0 ? 'TX' : 'RX';
        attach('ws2_32.dll', api, {
            onEnter(args) {
                this.entry = null;
                try {
                    if (!eligible('socket')) return;
                    const length = args[2].toInt32();
                    if (length <= 0) return;
                    this.entry = {api: api, direction: direction, socket: args[0].toString(),
                        parts: [{pointer: args[1], length: length}]};
                    if (direction === 'TX') this.entry.snapshot = gather(this.entry.parts, length);
                } catch (_) { this.entry = null; }
            },
            onLeave(ret) { try { if (this.entry) report(this.entry, ret.toInt32()); } catch (_) {} }
        });
    });
    ['WSASend', 'WSARecv'].forEach(function (api) {
        attach('ws2_32.dll', api, {
            onEnter(args) {
                this.entry = null; this.key = null;
                try {
                    if (!eligible('socket')) return;
                    const entry = {api: api, direction: api === 'WSASend' ? 'TX' : 'RX', socket: args[0].toString(),
                        parts: descriptors(args[1], args[2].toUInt32())};
                    if (entry.direction === 'TX') entry.snapshot = gather(entry.parts, capacity(entry.parts));
                    this.entry = entry; this.result = args[3]; this.overlapped = args[5];
                    if (!args[5].isNull()) {
                        if (pending.size >= MAX_PENDING) {
                            suppressed++; this.entry = null; return;
                        }
                        callbackAt(args[6]);
                        this.key = args[5].toString(); pending.set(this.key, entry);
                    }
                } catch (_) { this.entry = null; }
            },
            onLeave(ret) {
                try {
                    if (!this.entry) return;
                    if (ret.toInt32() === 0 && !this.result.isNull()) {
                        const n = this.result.readU32();
                        if (this.key) finish(this.overlapped, n, 0); else report(this.entry, n);
                    } else if (ret.toInt32() !== 0 && this.lastError !== 997 && this.key) {
                        pending.delete(this.key);
                    }
                } catch (_) { if (this.key) pending.delete(this.key); }
            }
        });
    });
    attach('ws2_32.dll', 'WSAGetOverlappedResult', {
        onEnter(args) { this.ov = args[1]; this.result = args[2]; },
        onLeave(ret) { try { if (ret.toInt32()) finish(this.ov, this.result.readU32(), 0); } catch (_) {} }
    });
    attach('kernel32.dll', 'GetQueuedCompletionStatus', {
        onEnter(args) { this.result = args[1]; this.ov = args[3]; },
        onLeave(ret) { try { finish(this.ov.readPointer(), ret.toInt32() ? this.result.readU32() : 0, ret.toInt32() ? 0 : 1); } catch (_) {} }
    });
    attach('kernel32.dll', 'GetQueuedCompletionStatusEx', {
        onEnter(args) { this.entries = args[1]; this.maximum = args[2].toUInt32(); this.count = args[3]; },
        onLeave(ret) {
            try {
                if (!ret.toInt32()) return;
                const n = Math.min(this.count.readU32(), this.maximum, 256), stride = Process.pointerSize * 4;
                for (let i = 0; i < n; i++) {
                    const p = this.entries.add(i * stride);
                    finish(p.add(Process.pointerSize).readPointer(), p.add(Process.pointerSize * 3).readU32(),
                        p.add(Process.pointerSize * 2).readPointer().isNull() ? 0 : 1);
                }
            } catch (_) {}
        }
    });
    attach('ws2_32.dll', 'closesocket', {
        onEnter(args) { this.socket = args[0].toString(); },
        onLeave(ret) {
            if (ret.toInt32() === 0) for (const [key, e] of pending) if (e.socket === this.socket) pending.delete(key);
        }
    });
}
function cString(pointer) {
    if (pointer.isNull()) return null;
    const range = Process.findRangeByAddress(pointer);
    if (!range || range.protection.indexOf('r') < 0) return null;
    const available = Math.min(1024, range.base.add(range.size).sub(pointer).toUInt32());
    const bytes = new Uint8Array(pointer.readByteArray(available));
    const end = bytes.indexOf(0);
    // These exports take C strings, not a length. Never guess a binary buffer length.
    return end < 0 ? null : bytes.buffer.slice(0, end);
}
function installStrings() {
    if (Process.arch !== 'ia32') return;
    [
        {name: '?KSLink_KBEncryptData@@YAXHPAD0@Z', encryptMode: 0},
        {name: '?KSLink_KBEncryptSeed128String@@YAXHPAD0@Z', encryptMode: 1}
    ].forEach(function (spec) {
        attach('LinkInfoMng.dll', spec.name, {
            onEnter(args) {
                this.output = null;
                try {
                    if (!eligible('strings')) return;
                    const mode = args[0].toInt32();
                    if (mode !== 0 && mode !== 1) return;
                    if (mode === spec.encryptMode) {
                        const data = cString(args[1]);
                        publish('TX', 'PC · 평문 후보 · ' + spec.name.split('@@')[0].slice(1), data, data ? data.byteLength : 0,
                            '문자열 변환 입력 · 요청 추정 · 전체 송신 전문 아님');
                    } else this.output = args[2];
                } catch (_) {}
            },
            onLeave() {
                try {
                    if (!this.output || !wanted('strings')) return;
                    const data = cString(this.output);
                    publish('RX', 'PC · 평문 후보 · ' + spec.name.split('@@')[0].slice(1), data, data ? data.byteLength : 0,
                        '문자열 변환 출력 · 응답 추정 · 전체 수신 전문 아님');
                } catch (_) {}
            }
        });
    });
}
function scan() {
    try { installSockets(); installStrings(); } catch (e) { log('PC 후크 설치 실패: ' + e); }
}
if (Process.platform !== 'windows') throw new Error('Windows 전용 수집기입니다.');
log('PC 조회 전용 · PID ' + Process.id + ' · ' + Process.arch + ' · 데이터 변경/전송 중단 없음');
scan();
setInterval(scan, 1000);
