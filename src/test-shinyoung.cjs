const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(__dirname+'/agent-shinyoung.js','utf8');
function setup(rules=[],allowResize=false) {
  const events=[],calls={tx:0,rx:0},hooks={};
  const bytes=x=>Array.from(Buffer.from(x,'ascii'),b=>b>127?b-256:b);
  const B64={decode:s=>Array.from(Buffer.from(String(s),'base64'),b=>b>127?b-256:b),encodeToString:b=>Buffer.from(b).toString('base64')};
  class JSONArray { constructor(s){this.a=typeof s==='string'?JSON.parse(s):s;} getString(i){return this.a[i];} put(i,v){this.a[i]=v;return this;} toString(){return JSON.stringify(this.a);} }
  const tx={call(self,action,args){calls.tx++;self.actual=args; if(self.fail)throw Error('original fail');return true;}};
  const rx={call(self,raw,len){calls.rx++;self.actual=Buffer.from(raw).subarray(0,len);if(self.fail)throw Error('original fail');}};
  const Java={available:true,perform:f=>f(),array:(_,a)=>Array.from(a),use:name=>{
    if(name==='android.util.Base64')return B64;
    if(name==='org.json.JSONArray')return {$new:s=>new JSONArray(s)};
    if(name==='org.apache.cordova.plugin.SocketManager')return {execute:{overload:()=>hooks.tx=tx}};
    if(name==='o.bi.ma')return {IIiiIIIiII:{overload:()=>hooks.rx=rx}};
    throw Error(name);
  }};
  vm.runInNewContext(source,{BOOT_CONFIG:{rules:rules.length>0,compiledRules:rules,allowResize},Java,
    Process:{getCurrentThreadId:()=>1,id:1},send:(meta,data)=>events.push({meta,data:data?Buffer.from(data):null}),
    recv:()=>{},setInterval:()=>{},setTimeout:()=>{}});
  return {events,calls,hooks,bytes,JSONArray};
}
const rule=(direction,before,after)=>({name:'test',direction,contains:Array.from(Buffer.from('TRTEST')),
  before:Array.from(Buffer.from(before)),after:Array.from(Buffer.from(after)),all:true,allowResize:true});
let t=setup([rule('TX','user01','user002'),rule('RX','0001','0000')],true);
let tx={};
t.hooks.tx.implementation.call(tx,'requestSend',new t.JSONArray([3,Buffer.from('TRTEST|user01|00user01').toString('base64')]),null);
assert.equal(Buffer.from(tx.actual.getString(1),'base64').toString(),'TRTEST|user002|00user002',JSON.stringify(t.events.map(e=>e.meta)));
assert.equal(t.calls.tx,1);
let rx={};
t.hooks.rx.implementation.call(rx,t.bytes('TRTEST|0001PAD'),11);
assert.equal(rx.actual.toString(),'TRTEST|0000');
assert.equal(t.calls.rx,1);
assert(t.events.some(e=>e.meta.kind==='settled'&&e.meta.action==='replace'));
assert(t.events.filter(e=>e.meta.kind==='packet').every(e=>!e.meta.pending));
let fail={fail:true};
assert.throws(()=>t.hooks.tx.implementation.call(fail,'requestSend',new t.JSONArray([3,Buffer.from('TRTEST|user01').toString('base64')]),null),/original fail/);
assert.equal(t.calls.tx,2); // Never retries application calls after failure.
t=setup([rule('TX','user01','user0003')],false);tx={};
t.hooks.tx.implementation.call(tx,'requestSend',new t.JSONArray([1,Buffer.from('TRTEST|user01').toString('base64')]),null);
assert.equal(Buffer.from(tx.actual.getString(1),'base64').toString(),'TRTEST|user01');
t=setup([rule('RX','user01','user0003')],true);rx={};
t.hooks.rx.implementation.call(rx,t.bytes('TRTEST|user01'),13);
assert.equal(rx.actual.toString(),'TRTEST|user0003');
t=setup();rx={};t.hooks.rx.implementation.call(rx,t.bytes('abcd'),4);
assert.equal(rx.actual.toString(),'abcd');
console.log('PASS: native adapter TX/RX, Base64, valid RX length, rules off, resize guards, no wait and exactly-once original on errors.');
