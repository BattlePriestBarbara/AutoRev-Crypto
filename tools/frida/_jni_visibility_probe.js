// _jni_visibility_probe.js - throwaway diagnostic.
//
// Question: is the host x86_64 ART JNIEnv function table (the one JNI_GetCreatedJavaVMs ->
// GetEnv hands us) actually the table that in-process native code calls through? If yes, a broad
// set of common slots must show hits while the app is doing ordinary UI work. If it stays at zero
// the guest ARM JNI calls are going somewhere else and the Tier A design needs rethinking.
//
// Count-only: nothing is replaced, no payload is read, nothing is written.
'use strict';

const PTR = Process.pointerSize;
const SLOTS = {
    FindClass: 6, Throw: 13, ExceptionOccurred: 15, GetObjectClass: 31, GetMethodID: 33,
    CallObjectMethod: 34, NewStringUTF: 167, GetStringUTFChars: 169, GetArrayLength: 171,
    NewByteArray: 176, GetByteArrayElements: 184, ReleaseByteArrayElements: 192,
    SetByteArrayRegion: 208, GetJavaVM: 219, RegisterNatives: 215,
};
const counts = {};
const hooked = [];
const moduleOf = {};
let inHook = false;

Object.keys(SLOTS).forEach(function (name) { counts[name] = 0; });

function getVm() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return null;
    let addr = null;
    try { addr = libart.getExportByName("JNI_GetCreatedJavaVMs"); } catch (e) { return null; }
    const vmBuf = Memory.alloc(PTR), n = Memory.alloc(4);
    const rc = new NativeFunction(addr, "int", ["pointer", "int", "pointer"])(vmBuf, 1, n);
    if (rc !== 0 || n.readInt() < 1) return null;
    return vmBuf.readPointer();
}

function attachEnv(jvm) {
    const invoke = jvm.readPointer();
    const envOut = Memory.alloc(PTR);
    const getEnv = new NativeFunction(invoke.add(7 * PTR).readPointer(), "int",
        ["pointer", "pointer", "int"]);
    let rc = getEnv(jvm, envOut, 0x00010006);
    if (rc !== 0) {
        const attach = new NativeFunction(invoke.add(4 * PTR).readPointer(), "int",
            ["pointer", "pointer", "pointer"]);
        rc = attach(jvm, envOut, ptr(0));
    }
    if (rc !== 0) return null;
    return envOut.readPointer();
}

function moduleFor(address) {
    const owner = Process.findModuleByAddress(address);
    return owner ? owner.name : "?";
}

const jvm = getVm();
if (!jvm) { send({ type: "probe-abort", reason: "no JavaVM" }); }
else {
    const env = attachEnv(jvm);
    if (!env) { send({ type: "probe-abort", reason: "no JNIEnv" }); }
    else {
        const table = env.readPointer();
        send({ type: "probe-table", table: table.toString(), arch: Process.arch,
               pid: Process.id });
        Object.keys(SLOTS).forEach(function (name) {
            const slot = SLOTS[name];
            const fn = table.add(slot * PTR).readPointer();
            if (fn.isNull()) return;
            moduleOf[name] = moduleFor(fn);
            try {
                Interceptor.attach(fn, {
                    onEnter() { if (!inHook) counts[name] += 1; }
                });
                hooked.push(name);
            } catch (e) { /* counted below as unhooked */ }
        });
        send({ type: "probe-armed", hooked: hooked, owners: moduleOf,
               unhooked: Object.keys(SLOTS).filter(function (n) { return hooked.indexOf(n) < 0; }) });
    }
}

setInterval(function () {
    let total = 0;
    Object.keys(counts).forEach(function (n) { total += counts[n]; });
    send({ type: "probe-heartbeat", total: total, counts: counts });
}, 5000);
