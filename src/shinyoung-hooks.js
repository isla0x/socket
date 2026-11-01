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
