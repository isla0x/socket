// Boundary model only; this does not establish live HTS support.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const hooks = new Map(), events = [], buffers = new Map();
class Pointer {
    constructor(address) { this.value = address; }
    toString() { return '0x' + this.value.toString(16); }
    toInt32() { return this.value; }
    toUInt32() { return this.value; }
    isNull() { return !this.value; }
    add(n) { return new Pointer(this.value + n); }
    sub(p) { return new Pointer(this.value - p.value); }
    readByteArray(n) { return buffers.get(this.value).slice(0, n).buffer; }
}
const ptr = n => new Pointer(n);
function stringAt(n, text, terminated=true) {
    const data = new Uint8Array(1024); data.fill(terminated ? 0 : 65);
    data.set(Buffer.from(text)); buffers.set(n, data); return ptr(n);
}
const specs = ['?KSLink_KBEncryptData@@YAXHPAD0@Z','?KSLink_KBEncryptSeed128String@@YAXHPAD0@Z'];
const context = {
    BOOT_CONFIG:{capture:true,pcSource:'strings'}, Uint8Array, Map, Set, Date, Object, Error,
    Process:{id:1,arch:'ia32',platform:'windows',pointerSize:4,getCurrentThreadId:()=>42,
        findRangeByAddress:p=>({base:p,size:1024,protection:'r--'})},
    Module:{findExportByName:(dll,name)=>dll==='LinkInfoMng.dll'&&specs.includes(name)?ptr(specs.indexOf(name)+1):null},
    Interceptor:{attach:(address,callbacks)=>hooks.set(address.value,callbacks)},
    recv:()=>{},setInterval:()=>{},send:(meta,data)=>{if(meta.kind==='packet')events.push([meta,Buffer.from(data)]);}
};
vm.runInNewContext(fs.readFileSync(__dirname+'/agent-windows.js','utf8'),context);
assert.equal(hooks.size,2);
const input=stringAt(100,'ORIGINAL'),output=stringAt(200,'DECODED');
for (const [id,encryptMode] of [[1,0],[2,1]]) {
    for(const mode of [0,1]) {
        const local={}; hooks.get(id).onEnter.call(local,[ptr(mode),input,output]);hooks.get(id).onLeave.call(local);
        const [meta,bytes]=events.at(-1);
        assert.equal(meta.direction,mode===encryptMode?'TX':'RX');
        assert.equal(bytes.toString(),mode===encryptMode?'ORIGINAL':'DECODED');
        assert.equal(meta.pending,false);assert.match(meta.note,/추정/);
    }
}
assert.equal(Buffer.from(buffers.get(100)).subarray(0,8).toString(),'ORIGINAL');
assert.equal(Buffer.from(buffers.get(200)).subarray(0,7).toString(),'DECODED');
const count=events.length,local={};
hooks.get(1).onEnter.call(local,[ptr(0),stringAt(300,'A',false),output]);hooks.get(1).onLeave.call(local);
assert.equal(events.length,count,'unterminated buffers must be skipped');
console.log('PASS: both string mode mappings, unchanged buffers, no holds, candidate labels, unterminated input skipped (boundary model).');
