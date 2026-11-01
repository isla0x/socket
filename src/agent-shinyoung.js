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
log('Agent build 3.2: Shinyoung Cordova adapter; capture and inline rules only.');
function listenConfig() {
    recv('configure', function (message) {
        Object.assign(settings, message.settings || {}); settings.intercept = false;
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
function rewrite(data, before, after, all, allowResize) {
    if (!before.length) throw new Error('Empty find pattern');
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
    let prepared = bytes, names = [], ruleError = '';
    if (settings.rules) {
        try {
            (settings.compiledRules || []).forEach(function (r) {
                if (r.direction !== 'ANY' && r.direction !== direction) return;
                if (r.contains.length && findBytes(prepared, r.contains, 0) === -1) return;
                const next = rewrite(prepared, r.before, r.after, r.all, settings.allowResize && r.allowResize);
                if (next !== prepared) names.push(r.name);
                prepared = next;
            });
            if (names.length) prepared = fixLengths(prepared.slice(), direction, stage);
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
    return {id, held, recorded, changed, action, bytes: result, original: bytes, error};
}
function finish(outcome, applied, failure) {
    if (!outcome || !outcome.recorded || (!outcome.held && !outcome.changed)) return;
    send({kind: 'settled', id: outcome.id,
        action: failure ? 'rejected' : outcome.action,
        error: failure || outcome.error}, (applied ? outcome.bytes : outcome.original).buffer);
}

// Adapter for the supplied APK only. No protection patches or startup changes.
settings.intercept = false;
if (typeof Java === 'undefined' || !Java.available) {
    log('Java bridge unavailable: Shinyoung requires an Android Java process and Frida 16.x.');
} else {
    const installed = {tx:false,rx:false};
    let attempts = 0;
    function install() {
        Java.perform(function () {
            attempts++;
            const B64 = Java.use('android.util.Base64');
            const JSONArray = Java.use('org.json.JSONArray');
            function inspect(raw, length, direction, stage) {
                if (raw === null || length < 0 || length > raw.length || length > 1048576) return null;
                if (!settings.capture && !settings.rules) return null;
                const array = Java.array('byte',raw), bytes = new Uint8Array(length);
                for (let i=0;i<length;i++) bytes[i]=array[i]&255;
                // Inline rules only: neither UI nor worker calls wait for the PC.
                recordThread(direction === 'TX' ? 'SY TX' : 'SY RX');
                return gate(bytes,direction,stage,'',Process.getCurrentThreadId()===Process.id);
            }
            function javaBytes(bytes) {
                return Java.array('byte',Array.from(bytes,function (b) { return b>127?b-256:b; }));
            }
            if (!installed.tx) {
                try {
                    const Plugin = Java.use('org.apache.cordova.plugin.SocketManager');
                    const execute = Plugin.execute.overload('java.lang.String','org.json.JSONArray','org.apache.cordova.CallbackContext');
                    execute.implementation = function (action,args,callback) {
                        if (String(action)!=='requestSend') return execute.call(this,action,args,callback);
                        let outcome=null, actualArgs=args, applied=false;
                        try {
                            const raw=B64.decode(args.getString(1),0);
                            outcome=inspect(raw,raw.length,'TX','SY / Cordova requestSend / header+body');
                            if (outcome && outcome.changed) {
                                actualArgs=JSONArray.$new(args.toString());
                                actualArgs.put(1,B64.encodeToString(javaBytes(outcome.bytes),2));
                                applied=true;
                            }
                        } catch (e) {
                            finish(outcome,false,String(e)); outcome=null;
                            actualArgs=args; applied=false;
                            if (!warned.has('tx')) { warned.add('tx'); log('SY TX kept original: '+e); }
                        }
                        // Invoke application code exactly once, outside the conversion catch.
                        try {
                            const result=execute.call(this,action,actualArgs,callback);
                            finish(outcome,applied,'');
                            return result;
                        } catch (e) { finish(outcome,false,'Original send failed: '+e); throw e; }
                    };
                    installed.tx=true;
                    log('Hook ready: SY TX · SocketManager.requestSend · before compression/encryption');
                } catch (e) {
                    if (attempts===1) log('SY TX hook waiting: '+e);
                }
            }
            if (!installed.rx) {
                try {
                    // APK-specific callback to Cordova, after decrypt/inflate; bounded by explicit length.
                    const Worker=Java.use('o.bi.ma');
                    const deliver=Worker.IIiiIIIiII.overload('[B','int');
                    deliver.implementation=function (raw,length) {
                        let outcome=null, actual=raw, actualLength=length, applied=false;
                        try {
                            outcome=inspect(raw,length,'RX','SY / Cordova receive / header+body');
                            if (outcome && outcome.changed) {
                                actual=javaBytes(outcome.bytes); actualLength=actual.length; applied=true;
                            }
                        } catch (e) {
                            finish(outcome,false,String(e)); outcome=null;
                            actual=raw;actualLength=length;applied=false;
                            if (!warned.has('rx')) { warned.add('rx'); log('SY RX kept original: '+e); }
                        }
                        try {
                            const result=deliver.call(this,actual,actualLength);
                            finish(outcome,applied,'');
                            return result;
                        } catch (e) { finish(outcome,false,'Original receive failed: '+e); throw e; }
                    };
                    installed.rx=true;
                    log('Hook ready: SY RX · decoded response to Cordova · supplied APK layout');
                } catch (e) {
                    if (attempts===1) log('SY RX hook waiting: '+e);
                }
            }
            if ((!installed.tx || !installed.rx) && attempts<30) setTimeout(install,1000);
            else if (!installed.tx || !installed.rx) log('SY hook unavailable: verify supplied APK version; connection alone does not confirm capture.');
        });
    }
    install();
}
