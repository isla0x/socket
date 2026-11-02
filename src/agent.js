'use strict';
// Frida 16.x: no protection bypasses or hardcoded data replacements.
const settings = Object.assign({intercept: false, rules: false, tx: true, rx: true,
    filter: '', timeout: 15, requestSource: 'packet', testMode: false,
    compiledRules: [], lengthFields: [], allowResize: false, capture: true},
    typeof BOOT_CONFIG === 'undefined' ? {} : BOOT_CONFIG);
let counter = 0;
const packetHookReadyAt = Date.now() + 2000;
const prefix = Date.now().toString(36) + '-';
function log(text) { send({kind: 'log', text: String(text)}); }
log('Agent build 3.0: manual packet inspector; original-call style and delayed packet hook retained.');
function listenConfig() {
    recv('configure', function (message) {
        Object.assign(settings, message.settings || {});
        listenConfig();
    });
}
listenConfig();
let budgetTime = Date.now(), budgetCount = 0, budgetBytes = 0, suppressed = 0;
const warned = new Set();
const activeCalls = new Set();
const traceCounts = new Map();
const threadKinds = new Set();
function recordThread(stage) {
    const thread=Process.getCurrentThreadId();
    const main=thread===Process.id; // Android's main thread is the Linux thread-group leader.
    const key=stage+':'+main;
    if (!threadKinds.has(key)) {
        threadKinds.add(key);
        send({kind:'threadinfo',stage,mainThread:main,thread});
    }
}
function exclusive(name, body, original) {
    const key = Process.getCurrentThreadId() + ':' + name;
    if (activeCalls.has(key)) {
        if (!warned.has(key)) { warned.add(key); log('HookTrace REENTRY ' + name + ' thread=' + Process.getCurrentThreadId()); }
        return original();
    }
    const count = (traceCounts.get(name) || 0) + 1;
    traceCounts.set(name,count);
    if (count <= 3) log('HookTrace ' + name + ' enter #' + count);
    activeCalls.add(key);
    try {
        const result=body();
        if (count <= 3) log('HookTrace ' + name + ' return #' + count);
        return result;
    } finally { activeCalls.delete(key); }
}
setInterval(function () {
    if (suppressed) { send({kind: 'stats', suppressed}); suppressed = 0; }
}, 500);
function recordBudget(size) {
    const now = Date.now();
    if (now - budgetTime >= 1000) { budgetTime = now; budgetCount = 0; budgetBytes = 0; }
    if (budgetCount >= 200 || budgetBytes + size > 2097152) { suppressed++; return false; }
    budgetCount++; budgetBytes += size; return true;
}
function findBytes(data, needle, from) {
    for (let i = from || 0; i <= data.length - needle.length; i++) {
        if (data[i] !== needle[0]) continue;
        let j = 1;
        while (j < needle.length && data[i+j] === needle[j]) j++;
        if (j === needle.length) return i;
    }
    return -1;
}
function rewrite(data, before, after, all, allowResize, mode) {
    if (!before.length) throw new Error('Empty find pattern');
    if (mode === 'overwrite') {
        const at=findBytes(data,before,0);
        if (at<0) return data;
        const width=Math.max(before.length,after.length);
        if (at+width>data.length) throw new Error('Overwrite exceeds packet boundary; original preserved');
        const output=data.slice();
        for (let i=0;i<width;i++) output[at+i]=i<after.length?after[i]:32;
        return output;
    }
    const positions = [];
    let position = findBytes(data, before, 0);
    while (position !== -1) {
        positions.push(position);
        if (!all) break;
        position = findBytes(data, before, position + before.length);
    }
    if (!positions.length) return data;
    if (before.length !== after.length && !allowResize) throw new Error('Enable variable length for this rule');
    const length = data.length + positions.length * (after.length - before.length);
    if (length > 1048576) throw new Error('Rule output exceeds 1 MiB');
    const output = new Uint8Array(length);
    let source = 0, destination = 0;
    positions.forEach(function (at) {
        output.set(data.subarray(source, at), destination);
        destination += at - source;
        output.set(after, destination); destination += after.length;
        source = at + before.length;
    });
    output.set(data.subarray(source), destination);
    return output;
}
function fixLengths(data, direction, stage) {
    (settings.lengthFields || []).forEach(function (f) {
        if (f.direction !== 'ANY' && f.direction !== direction || stage.indexOf(f.stage_contains) === -1) return;
        const value = data.length + f.adjust;
        if (f.offset + f.width > data.length || value < 0) throw new Error('Length-field range is invalid');
        const raw = new Uint8Array(f.width);
        if (f.type === 'ascii') {
            const text = String(value).padStart(f.width, '0');
            if (text.length !== f.width) throw new Error('Length-field overflow');
            for (let i = 0; i < raw.length; i++) raw[i] = text.charCodeAt(i);
        } else {
            let n = value;
            for (let i = 0; i < raw.length; i++) {
                raw[f.type === 'uintle' ? i : raw.length-i-1] = n % 256; n = Math.floor(n / 256);
            }
            if (n) throw new Error('Length-field overflow');
        }
        data.set(raw, f.offset);
    });
    return data;
}

function gate(bytes, direction, stage, text, mainThread) {
    const id = prefix + (++counter);
    const matches = settings.intercept && (direction === 'TX' ? settings.tx : settings.rx) &&
        (!settings.filter || text.indexOf(settings.filter) !== -1);
    // Never block Android's UI thread. Automatic rules run in-process with no PC round trip.
    const held = !!(matches && !mainThread);
    let prepared = bytes, names = [], ruleError = '', overwriteOnly = true;
    if (settings.rules) {
        try {
            (settings.compiledRules || []).forEach(function (r) {
                if (r.direction !== 'ANY' && r.direction !== direction) return;
                if (r.contains.length && findBytes(prepared, r.contains, 0) === -1) return;
                const next = rewrite(prepared, r.before, r.after, r.all, settings.allowResize && r.allowResize,r.mode);
                if (next !== prepared) { names.push(r.name); if(r.mode!=='overwrite') overwriteOnly=false; }
                prepared = next;
            });
            if (names.length && !overwriteOnly) prepared = fixLengths(prepared.slice(), direction, stage);
        } catch (e) {
            prepared = bytes; names = []; ruleError = String(e);
            if (!warned.has(ruleError)) { warned.add(ruleError); log('Rule kept original: ' + ruleError); }
        }
    }
    const changed = names.length > 0;
    const recorded = held || (settings.capture && recordBudget(bytes.length + (changed ? prepared.length : 0)));
    const meta = {kind: 'packet', id, direction, stage, timestamp: Date.now() / 1000,
        pending: held, manual: !!matches, timeout: settings.timeout,
        mainThread: !!mainThread, autoNames: names, autoChanged: changed, ruleError,
        thread: Process.getCurrentThreadId()};
    let action = changed ? 'replace' : 'original', result = prepared, error = '';
    const operation = held ? recv('decision:' + id, function (message, data) {
        action = message.action;
        if (action === 'replace') {
            if (data === null || data.byteLength > 1048576 || (data.byteLength !== bytes.byteLength && message.allowResize !== true)) {
                action = 'rejected';
                error = 'Length change requires allowResize; maximum 1 MiB.';
                result = bytes;
            } else {
                result = new Uint8Array(data);
            }
        } else result = bytes;
    }) : null;
    if (recorded) {
        send(meta, bytes.buffer);
        if (changed) send({kind: 'prepared', id, names}, prepared.buffer);
    }
    if (held) {
        try { operation.wait(); }
        catch (e) { action = 'cancelled'; error = String(e); result = bytes; }
    }
    return {id, held, recorded, changed, action, bytes: result, original: bytes, error,inPlace:changed && overwriteOnly && !held};
}
function finish(outcome, applied, failure) {
    if (!outcome || !outcome.recorded || (!outcome.held && !outcome.changed)) return;
    send({kind: 'settled', id: outcome.id,
        action: failure ? 'rejected' : outcome.action,
        error: failure || outcome.error}, (applied ? outcome.bytes : outcome.original).buffer);
}

if (settings.testMode) {
    // Test the real blocking transport without requiring Android/Java.
    rpc.exports = { inspect: function (values, mainThread) {
        const outcome = gate(new Uint8Array(values), 'TX', 'transport-test', 'TEST', !!mainThread);
        finish(outcome, true, '');
        return Array.from(outcome.bytes);
    }};
} else if (typeof Java === 'undefined' || !Java.available) {
    log('Java bridge unavailable. This build requires Frida 16.x and an Android Java process.');
} else {
    const installed = {packet: false, encrypt: false, decrypt: false};
    let attempts = 0;
    let JString = null;
    function inspect(javaBytes, direction, stage) {
        if (!settings.capture && !settings.intercept && !settings.rules) return null;
        if (javaBytes === null || javaBytes.length > 1048576) return null;
        // Preserve the byte-array access used by the user's working script.
        const array = Java.array('byte',javaBytes);
        const bytes = new Uint8Array(array.length);
        for (let i = 0; i < bytes.length; i++) bytes[i] = array[i] & 255;
        let text = '';
        if (settings.filter) {
            try { text = JString.$new(javaBytes, 'MS949').toString(); }
            catch (_) { text = ''; }
        }
        return gate(bytes, direction, stage, text, Java.isMainThread());
    }
    function replacement(outcome, original) {
        if(outcome.inPlace && original.length===outcome.bytes.length) {
            for(let i=0;i<original.length;i++) original[i]=outcome.bytes[i]>127?outcome.bytes[i]-256:outcome.bytes[i];
            return original;
        }
        return Java.array('byte', Array.from(outcome.bytes, b => b > 127 ? b - 256 : b));
    }
    function install() {
        Java.perform(function () {
            JString = Java.use('java.lang.String');
            attempts++;
            // Match the user's working script: do not resolve/hook this protected
            // packet class during the application's first two seconds.
            if (!installed.packet && Date.now() >= packetHookReadyAt) {
                try {
                    const C = Java.use('com.kyobo.android.corelib.net.packet.KyoboPacketMngr');
                    const methods = C.makePacketArray.overloads.filter(m => m.argumentTypes.length === 1);
                    if (!methods.length) throw new Error('No one-argument makePacketArray overload');
                    methods.forEach(function (method) {
                        method.implementation = function (info) {
                            recordThread('packet');
                            return exclusive('packet', () => {
                            let outcome = null;
                            if (settings.requestSource === 'packet') {
                                try {
                                    outcome = inspect(info.m_szData.value, 'TX', 'makePacketArray / header+body');
                                    if (outcome && outcome.action === 'replace') info.m_szData.value = replacement(outcome,info.m_szData.value);
                                    finish(outcome, true, '');
                                } catch (e) { finish(outcome, false, String(e)); log('Request capture: ' + e); }
                            }
                            return this.makePacketArray(info);
                            }, () => this.makePacketArray(info));
                        };
                    });
                    installed.packet = true;
                    log('Hook ready: makePacketArray');
                } catch (e) { if (attempts === 1 || attempts === 30) log('makePacketArray not ready: ' + e); }
            }
            let C;
            try { C = Java.use('com.raonsecure.ksw.RSKSWChannelEncrypt'); }
            catch (e) { if (attempts === 1 || attempts === 30) log('RSKSWChannelEncrypt not ready: ' + e); return; }
            ['encrypt', 'decrypt'].forEach(function (name) {
                if (installed[name]) return;
                try {
                    const methods = C[name].overloads.filter(m => m.argumentTypes.length && m.argumentTypes[0].className === '[B' && (name !== 'decrypt' || m.returnType.className === '[B'));
                    if (!methods.length) throw new Error('No byte-array overload');
                    methods.forEach(function (method) {
                        method.implementation = function () {
                            recordThread(name);
                            const args = Array.from(arguments);
                            return exclusive('channel/' + name, () => {
                            // Invoke the original method exactly once; do not swallow app exceptions.
                            if (name === 'encrypt') {
                                if (settings.requestSource === 'encrypt') {
                                    let outcome = null;
                                    try {
                                        outcome = inspect(args[0], 'TX', 'encrypt / body');
                                        if (outcome && outcome.action === 'replace') args[0] = replacement(outcome,args[0]);
                                        finish(outcome, true, '');
                                    } catch (e) { finish(outcome, false, String(e)); log('Encrypt capture: ' + e); }
                                }
                                return this[name].apply(this, args);
                            }
                            const original = this[name].apply(this, args);
                            let result = original, outcome = null;
                            try {
                                outcome = inspect(original, 'RX', 'decrypt / plaintext');
                                if (outcome && outcome.action === 'replace') result = replacement(outcome,original);
                                finish(outcome, true, '');
                            } catch (e) { finish(outcome, false, String(e)); log('Response capture: ' + e); }
                            return result;
                            }, () => this[name].apply(this, args));
                        };
                    });
                    installed[name] = true;
                    log('Hook ready: ' + name);
                } catch (e) { if (attempts === 1 || attempts === 30) log(name + ' not ready: ' + e); }
            });
        });
    }
    install();
    const retry = setInterval(function () {
        if (Object.values(installed).every(Boolean) || attempts >= 60) { clearInterval(retry); return; }
        install();
    }, 1000);
}
