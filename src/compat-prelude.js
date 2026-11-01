// Optional prelude copied in scope from the user's working android.js.
// It installs NO makePacketArray/encrypt/decrypt hooks and changes NO packet data.
(function () {
    const patched = new Set();
    function patchLibrary(lib) {
        const base = Module.findBaseAddress(lib);
        if (base === null || patched.has(base.toString())) return;
        const address = base.add(0x3840);
        const range = Process.findRangeByAddress(address);
        if (range === null || range.protection.indexOf('x') === -1) {
            send({kind:'log',text:'Compatibility offset is not executable; skipped.'});
            return;
        }
        Interceptor.attach(address, {onEnter:function () { this.context.x0 = 1; }});
        patched.add(base.toString());
        send({kind:'log',text:'User compatibility prelude: libAppSuit offset installed.'});
    }
    const dlopen = Module.findExportByName(null,'android_dlopen_ext');
    if (dlopen !== null) Interceptor.attach(dlopen,{
        onEnter:function (args) { this.path = args[0].isNull() ? '' : args[0].readUtf8String(); },
        onLeave:function () { if (/libAppSuit.so/i.test(this.path || '')) patchLibrary(this.path.split('/').pop()); }
    });
    patchLibrary('libAppSuit.so');
    const fopen = Module.findExportByName('libc.so','fopen');
    if (fopen !== null) Interceptor.attach(fopen,{
        onEnter:function (args) {
            const path = args[0].isNull() ? '' : args[0].readUtf8String();
            if (path.indexOf('/proc/self/cmdline') !== -1) {
                this.path = Memory.allocUtf8String('/data/local/tmp/fake_cmdline');
                args[0] = this.path;
            }
        }
    });
    Java.perform(function () {
        try {
            const C = Java.use('kr.co.sdk.vguard2.VGuard');
            const method = C.RootedCheck.overload('int');
            method.implementation = function (value) { method.call(this,value); return false; };
            send({kind:'log',text:'User compatibility prelude: RootedCheck installed. Packet hooks are owned by this single agent.'});
        } catch (error) { send({kind:'log',text:'User compatibility prelude: '+String(error)}); }
    });
})();
