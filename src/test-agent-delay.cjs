const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
let now=100000,packetResolutions=0;
const timers=[];
function method(args){const m=function(){};m.argumentTypes=args;m.returnType={className:'[B'};return m;}
const packet=method([{className:'PacketInfo'}]);
const encrypt=method([{className:'[B'},{className:'int'}]);
const decrypt=method([{className:'[B'},{className:'int'}]);
const context={
 Date:class extends Date{static now(){return now;}},
 BOOT_CONFIG:{intercept:false,rules:false},
 Java:{available:true,perform:fn=>fn(),use:name=>{
   if(name==='java.lang.String')return {};
   if(name.endsWith('KyoboPacketMngr')){packetResolutions++;assert.ok(now>=102000,'Protected class resolved too early');return {makePacketArray:{overloads:[packet]}};}
   return {encrypt:{overloads:[encrypt]},decrypt:{overloads:[decrypt]}};
 }},
 Process:{getCurrentThreadId:()=>1},send:()=>{},recv:()=>({wait(){throw new Error('unexpected wait')}}),
 setInterval:fn=>{const entry={fn,active:true};timers.push(entry);return entry;},clearInterval:entry=>entry.active=false,
 Uint8Array,Map,Set,Array,Object,String,Math
};
vm.runInNewContext(fs.readFileSync(__dirname+'/agent.js','utf8'),context);
assert.equal(packetResolutions,0);
assert.equal(typeof encrypt.implementation,'function');
now=101000;for(const timer of timers)if(timer.active)timer.fn();
assert.equal(packetResolutions,0);
now=102000;for(const timer of timers)if(timer.active)timer.fn();
assert.equal(packetResolutions,1);
assert.equal(typeof packet.implementation,'function');
console.log('PASS: protected packet class is not resolved or hooked before 2 seconds.');
