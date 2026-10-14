// frida_intercept_plaintext.js - Tier A: capture the app-layer plaintext/ciphertext at the
// ART x86_64 JNI boundary for com.hicorenational.antifraud.
//
// Why the ART boundary and not the app's own code
// ----------------------------------------------
// libmd.so / libtnet are arm64-v8a and execute inside libnb's ARM translation cache on this
// x86_64 emulator, so their ARM instruction bodies are not host-executable addresses and cannot
// be interceptor'd (a hook on such an address lands on "data"). What IS a real host-executable
// address is the ART x86_64 JNIEnv function table that every guest JNI call is forwarded to.
// Hooking there is therefore the only way to see the app's plaintext without touching translated
// code, and it is read-only with respect to the sample.
//
// What is watched, and why exactly these slots
// -------------------------------------------
// scripts/libmd_symbols.py decodes the slots out of libmd.so's own code (`ldr Xt,[functions,#imm]`)
// and names them with the char* literals that same code loads. For the shipped libmd.so
// (sha256 abca008ba600a9b1eee80660ef80aef0032dc341fead36cc2baea0443e452acc) it measured:
//   paramJsonEncode @0x112ff0 (11 slot calls, 6 indices)
//     GetStringLength 164, FindClass 6, GetMethodID 33, NewByteArray 176,
//     SetByteArrayRegion 208, NewStringUTF 167   (the constructor is applied by _JNIEnv::NewObject,
//     a C++ helper reached by `bl`, so it owns no table slot here)
//   jstringTostr @0x10f14 (the inbound read)
//     GetArrayLength 171, GetByteArrayElements 184, ReleaseByteArrayElements 192
//
// The decompilation says paramJsonEncode = Base64(aes_256_cbc_encode(shareKey, json)), and the
// json arrives as a jstring that jstringTostr turns into UTF-8 bytes via String.getBytes(). So:
//   * INBOUND plaintext   -> GetByteArrayElements (184); length from GetArrayLength (171)
//   * OUTBOUND ciphertext -> SetByteArrayRegion (208); its `const jbyte* buf` is the base64 text
// GetStringUTFChars (169) is never called by libmd (measured), so watching it alone would capture
// nothing; it is kept only for the self-proof round trip.
//
// Fail-closed: nothing is hooked until the indices are proven against the live process by
// on-thread round trips. If a proof fails, the script reports the failure and hooks nothing.
//
// Run (attach; the shell kills freshly spawned processes, see the project notes):
//   frida_run_hook(target="国家反诈中心", hook=".../frida_intercept_plaintext.js", mode="attach")

'use strict';

const PTR = Process.pointerSize;

// --- JNINativeInterface_ indices (fixed by the JNI ABI; the ones marked * are the ones this
//     tool measured from libmd.so's own code, the rest are proven live before use) -------------
const JNI = {
    GetVersion: 4,
    FindClass: 6,                 // *
    GetMethodID: 33,              // *
    GetStringLength: 164,         // *
    NewStringUTF: 167,            // *
    GetStringUTFChars: 169,
    ReleaseStringUTFChars: 170,
    GetArrayLength: 171,          // *
    NewByteArray: 176,            // *
    GetByteArrayElements: 184,    // *
    ReleaseByteArrayElements: 192,// *
    SetByteArrayRegion: 208,      // *
};

// JNIInvokeInterface_ (JavaVM): indices are part of the invocation API.
const VM = {
    DestroyJavaVM: 3, AttachCurrentThread: 4, DetachCurrentThread: 6, GetEnv: 7,
};
// The project's own hook reuses GetEnv=6/AttachCurrentThread=4; both spellings are tried so a
// mismatch is detected rather than silently mis-indexed.
const VM_ALT = { GetEnv: 6, AttachCurrentThread: 4 };

const JNI_VERSION_1_6 = 0x00010006;
const JNI_EDETACHED = -2;

const MAX_BYTES = 8192;      // per-record payload cap
const MAX_RECORDS = 20000;   // hard cap so a hot slot cannot flood the JSONL
const ASCII_CAP = 512;
const SELF_PROOF_NONCE = "mdcap-" + Date.now().toString(16);

let stage = "init";
let fatal = null;
let records = 0;
let suppressed = 0;
let inHook = false;          // reentrancy guard: our own JNI calls must not be re-captured
const hookStats = {};
const seen = new Set();      // dedup key -> suppress identical repeats (heartbeats still tick)

function log(line) { console.log("[mdcap] " + line); }

function emit(record) {
    record.t = Date.now();
    record.stage = stage;
    send(record);
}

function fail(reason) {
    fatal = reason;
    log("[!] FAIL-CLOSED: " + reason);
    emit({ type: "tier-a-abort", reason: reason });
}
// ---------------------------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------------------------
function bytesOf(ptrValue, length) {
    if (!ptrValue || ptrValue.isNull() || length <= 0) return null;
    const n = Math.min(length, MAX_BYTES);
    try { return new Uint8Array(ptrValue.readByteArray(n)); } catch (e) { return null; }
}

function hexOf(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return out;
}

function asciiOf(bytes) {
    let out = "";
    for (let i = 0; i < Math.min(bytes.length, ASCII_CAP); i++) {
        const b = bytes[i];
        out += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : (b === 0x0a ? "\\n"
            : (b === 0x0d ? "\\r" : (b === 0x09 ? "\\t" : ".")));
    }
    return out;
}

// A cheap shape summary so the downstream step can pick out JSON/ciphertext without the capture
// having to know what it is looking at.
function describe(bytes, expectedLen) {
    if (!bytes) return { captured: 0 };
    let printable = 0;
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) printable++;
    }
    const first = bytes.length ? bytes[0] : 0;
    const last = bytes.length ? bytes[bytes.length - 1] : 0;
    return {
        captured: bytes.length,
        declared_length: expectedLen,
        truncated: expectedLen > bytes.length,
        hex_prefix: hexOf(bytes.subarray(0, 64)),
        ascii_prefix: asciiOf(bytes),
        sha1: (function () {
            // FNV-1a over the captured bytes, not a security hash: only used to deduplicate.
            let h = 0x811c9dc5;
            for (let i = 0; i < bytes.length; i++) {
                h ^= bytes[i];
                h = (h * 0x01000193) >>> 0;
            }
            return h.toString(16);
        })(),
        printable_ratio: bytes.length ? +(printable / bytes.length).toFixed(3) : 0,
        looks_like_json: first === 0x7b || first === 0x5b,
        looks_like_base64: /^[A-Za-z0-9+/=]+$/.test(asciiOf(bytes).replace(/\\n|\\r|\\t/g, "")),
        last_byte: last,
    };
}

// ---------------------------------------------------------------------------------------------
// Reaching a live JNIEnv, and the table behind it
// ---------------------------------------------------------------------------------------------
function jniFn(env, index, retType, argTypes) {
    const fn = env.readPointer().add(index * PTR).readPointer();
    if (fn.isNull()) throw new Error("JNIEnv table slot " + index + " is null");
    return new NativeFunction(fn, retType, argTypes);
}

function getJavaVm() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) { fail("libart.so is not loaded, so the JNI invocation API is unavailable"); return null; }
    let addr = null;
    try { addr = libart.getExportByName("JNI_GetCreatedJavaVMs"); } catch (e) { }
    if (!addr) { fail("libart.so does not export JNI_GetCreatedJavaVMs"); return null; }
    const vmBuf = Memory.alloc(PTR);
    const nVms = Memory.alloc(4);
    const rc = new NativeFunction(addr, "int", ["pointer", "int", "pointer"])(vmBuf, 1, nVms);
    const count = nVms.readInt();
    log("JNI_GetCreatedJavaVMs rc=" + rc + " count=" + count);
    if (rc !== 0 || count < 1) { fail("JNI_GetCreatedJavaVMs reported no VM"); return null; }
    emit({ type: "tier-a-vm", count: count, vm: vmBuf.readPointer().toString() });
    return vmBuf.readPointer();
}

// GetEnv(7) then AttachCurrentThread(4). The Frida JS thread is not attached, so -2 is expected.
function attachEnv(jvm) {
    const invoke = jvm.readPointer();
    const attempts = [
        { label: "GetEnv=7/Attach=4", getEnv: VM.GetEnv, attach: VM.AttachCurrentThread },
        { label: "GetEnv=6/Attach=4", getEnv: VM_ALT.GetEnv, attach: VM_ALT.AttachCurrentThread },
    ];
    for (const plan of attempts) {
        try {
            const envOut = Memory.alloc(PTR);
            const getEnv = new NativeFunction(invoke.add(plan.getEnv * PTR).readPointer(),
                "int", ["pointer", "pointer", "int"]);
            let rc = getEnv(jvm, envOut, JNI_VERSION_1_6);
            if (rc !== 0) {
                const attach = new NativeFunction(invoke.add(plan.attach * PTR).readPointer(),
                    "int", ["pointer", "pointer", "pointer"]);
                rc = attach(jvm, envOut, ptr(0));
            }
            const env = envOut.readPointer();
            if (rc === 0 && !env.isNull()) {
                emit({ type: "tier-a-env", plan: plan.label, env: env.toString(),
                       table: env.readPointer().toString() });
                return env;
            }
            log("[i] " + plan.label + " gave rc=" + rc + " (JNI_EDETACHED=" + JNI_EDETACHED + ")");
        } catch (e) {
            log("[i] " + plan.label + " threw: " + e);
        }
    }
    fail("could not obtain a usable JNIEnv from the JavaVM");
    return null;
}
// ---------------------------------------------------------------------------------------------
// Self-proof: prove the indices against the live process before hooking anything
// ---------------------------------------------------------------------------------------------
function selfProof(env) {
    // (A) A wrong table base cannot answer GetVersion with a plausible JNI version.
    let version = null;
    try {
        version = jniFn(env, JNI.GetVersion, "int", ["pointer"])(env);
    } catch (e) {
        fail("GetVersion(4) threw, so the table base is wrong: " + e);
        return false;
    }
    const versionOk = (version >>> 0) === JNI_VERSION_1_6;
    emit({ type: "tier-a-selfproof", proof: "GetVersion", slot: JNI.GetVersion,
           observed: "0x" + (version >>> 0).toString(16), expected: "0x10006", ok: versionOk });
    if (!versionOk) {
        fail("GetVersion(4) returned 0x" + (version >>> 0).toString(16) + ", expected 0x10006");
        return false;
    }

    // (B) jstring round trip: NewStringUTF(167) -> GetStringUTFChars(169) -> Release(170). This
    // proves slot 167 (the one libmd uses to build its result string) and the UTF-8 path.
    let got = null;
    try {
        const newStringUTF = jniFn(env, JNI.NewStringUTF, "pointer", ["pointer", "pointer"]);
        const getUTF = jniFn(env, JNI.GetStringUTFChars, "pointer", ["pointer", "pointer", "pointer"]);
        const relUTF = jniFn(env, JNI.ReleaseStringUTFChars, "void", ["pointer", "pointer", "pointer"]);
        const js = newStringUTF(env, Memory.allocUtf8String(SELF_PROOF_NONCE));
        if (js.isNull()) {
            fail("NewStringUTF(167) returned null");
            return false;
        }
        const chars = getUTF(env, js, ptr(0));
        if (chars.isNull()) {
            fail("GetStringUTFChars(169) returned null");
            return false;
        }
        got = chars.readCString();
        relUTF(env, js, chars);
    } catch (e) {
        fail("jstring round trip threw: " + e);
        return false;
    }
    const stringOk = (got === SELF_PROOF_NONCE);
    emit({ type: "tier-a-selfproof", proof: "jstring-roundtrip", slots: [JNI.NewStringUTF,
           JNI.GetStringUTFChars, JNI.ReleaseStringUTFChars], expected: SELF_PROOF_NONCE,
           observed: got, ok: stringOk });
    if (!stringOk) {
        fail("jstring round trip gave " + JSON.stringify(got) + ", expected the nonce");
        return false;
    }

    // (C) byte[] round trip over exactly the slots the capture depends on: NewByteArray(176) ->
    // SetByteArrayRegion(208) -> GetArrayLength(171) -> GetByteArrayElements(184) -> Release(192).
    // If any of those were mis-indexed the bytes would not come back.
    const probe = [0x7b, 0x22, 0x6b, 0x22, 0x3a, 0x31, 0x7d];  // {"k":1}
    try {
        const newByteArray = jniFn(env, JNI.NewByteArray, "pointer", ["pointer", "int"]);
        const setRegion = jniFn(env, JNI.SetByteArrayRegion, "void",
            ["pointer", "pointer", "int", "int", "pointer"]);
        const getArrayLength = jniFn(env, JNI.GetArrayLength, "int", ["pointer", "pointer"]);
        const getElems = jniFn(env, JNI.GetByteArrayElements, "pointer",
            ["pointer", "pointer", "pointer"]);
        const relElems = jniFn(env, JNI.ReleaseByteArrayElements, "void",
            ["pointer", "pointer", "pointer", "int"]);
        const buffer = Memory.alloc(probe.length);
        buffer.writeByteArray(probe);
        const array = newByteArray(env, probe.length);
        if (array.isNull()) {
            fail("NewByteArray(176) returned null");
            return false;
        }
        setRegion(env, array, 0, probe.length, buffer);
        const length = getArrayLength(env, array);
        const elems = getElems(env, array, ptr(0));
        const back = bytesOf(elems, length);
        relElems(env, array, elems, 0);
        const arrayOk = length === probe.length && back !== null
            && hexOf(back) === hexOf(probe);
        emit({ type: "tier-a-selfproof", proof: "byte-array-roundtrip",
               slots: [JNI.NewByteArray, JNI.SetByteArrayRegion, JNI.GetArrayLength,
                       JNI.GetByteArrayElements, JNI.ReleaseByteArrayElements],
               length: length, observed_hex: back ? hexOf(back) : null,
               expected_hex: hexOf(probe), ok: arrayOk });
        if (!arrayOk) {
            fail("byte[] round trip gave " + (back ? hexOf(back) : "null") + " len=" + length);
            return false;
        }
    } catch (e) {
        fail("byte[] round trip threw: " + e);
        return false;
    }
    return true;
}
// ---------------------------------------------------------------------------------------------
// Capture hooks
// ---------------------------------------------------------------------------------------------
function note(name) { hookStats[name] = (hookStats[name] || 0) + 1; records++; }

function textLike(info) {
    return !!(info.looks_like_json || info.looks_like_base64 || info.printable_ratio >= 0.6);
}

function emitPayload(target, direction, role, length, info, extra, bytes) {
    if (records > MAX_RECORDS) { suppressed++; return; }
    const key = target.slot + ":" + length + ":" + info.sha1;
    if (seen.has(key)) { suppressed++; return; }
    seen.add(key);
    const record = {
        type: "tier-a-payload", slot: target.slot, name: target.name, direction: direction,
        role: role, pid: Process.id, tid: Process.getCurrentThreadId(), info: info,
        extra: extra || null,
    };
    // Full bytes only for text-shaped payloads: binary noise would bloat the JSONL with nothing
    // the decryptor can use.
    if (bytes && textLike(info)) record.bytes_hex = hexOf(bytes);
    emit(record);
}

function makeHandlers(env, target, lengthOf) {
    if (target.kind === "outbound") {
        // void SetByteArrayRegion(JNIEnv*, jbyteArray, jsize start, jsize len, const jbyte* buf)
        return {
            onEnter(args) {
                if (inHook || fatal) return;
                note(target.name);
                let length = 0, start = 0;
                try { length = args[3].toInt32(); start = args[2].toInt32(); } catch (e) { return; }
                if (length <= 0) return;
                const bytes = bytesOf(args[4], length);
                emitPayload(target, "native-to-java", "ciphertext-candidate", length,
                    describe(bytes, length), { start: start }, bytes);
            }
        };
    }
    if (target.kind === "inbound") {
        // jbyte* GetByteArrayElements(JNIEnv*, jarray, jboolean*)
        return {
            onEnter(args) { this.array = args[1]; },
            onLeave(retval) {
                if (inHook || fatal) return;
                note(target.name);
                const length = lengthOf(this.array);
                if (length <= 0) return;
                const bytes = bytesOf(retval, length);
                emitPayload(target, "java-to-native", "plaintext-candidate", length,
                    describe(bytes, length), { array: this.array.toString() }, bytes);
            }
        };
    }
    return { onEnter() { if (!inHook && !fatal) note(target.name); } };
}

function installCaptureHooks(env) {
    const table = env.readPointer();
    const getArrayLength = jniFn(env, JNI.GetArrayLength, "int", ["pointer", "pointer"]);
    function lengthOf(array) {
        inHook = true;                       // our own JNI call must not be re-captured
        try { return getArrayLength(env, array); }
        catch (e) { return 0; }
        finally { inHook = false; }
    }

    const targets = [
        { slot: JNI.SetByteArrayRegion, name: "SetByteArrayRegion", kind: "outbound",
          why: "its const jbyte* buf is the base64 ciphertext paramJsonEncode hands to Java" },
        { slot: JNI.GetByteArrayElements, name: "GetByteArrayElements", kind: "inbound",
          why: "jstringTostr reads the UTF-8 JSON bytes out of the getBytes() result here" },
        { slot: JNI.GetArrayLength, name: "GetArrayLength", kind: "count",
          why: "length companion of the inbound read; counted, not emitted" },
        { slot: JNI.ReleaseByteArrayElements, name: "ReleaseByteArrayElements", kind: "count",
          why: "closes the inbound read; counted so get/release pairing is visible" },
    ];
    let armed = 0;
    for (const target of targets) {
        const fn = table.add(target.slot * PTR).readPointer();
        if (fn.isNull()) { log("[!] slot " + target.slot + " is null, skipped"); continue; }
        try {
            Interceptor.attach(fn, makeHandlers(env, target, lengthOf));
            armed++;
            log("[+] slot " + target.slot + " " + target.name + " @" + fn);
            emit({ type: "tier-a-hook", slot: target.slot, name: target.name,
                   address: fn.toString(), kind: target.kind, why: target.why });
        } catch (e) {
            log("[!] cannot hook slot " + target.slot + ": " + e);
        }
    }
    return armed;
}

// ---------------------------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------------------------
const HEARTBEAT_MS = 10000;

function bootstrap() {
    log("arch=" + Process.arch + " pid=" + Process.id + " pointer_size=" + PTR);
    emit({ type: "tier-a-start", arch: Process.arch, pid: Process.id, pointer_size: PTR,
           nonce: SELF_PROOF_NONCE, script: "frida_intercept_plaintext.js",
           max_bytes: MAX_BYTES, max_records: MAX_RECORDS });

    stage = "vm";
    const jvm = getJavaVm();
    if (!jvm) { return; }

    stage = "env";
    const env = attachEnv(jvm);
    if (!env) { return; }

    stage = "selfproof";
    const module = Process.findModuleByName("libmd.so");
    emit({ type: "tier-a-modules", libmd_visible_to_host_agent: !!module,
           note: "libmd.so runs as arm64 code inside libnb's translation cache; it is not a host "
                 + "module, which is exactly why the capture lives at the ART boundary instead" });
    if (!selfProof(env)) { return; }

    stage = "armed";
    const armed = installCaptureHooks(env);
    emit({ type: "tier-a-armed", hooks: armed, records: records, stats: hookStats, fatal: fatal });
    log("armed with " + armed + " hooks; " + Object.keys(hookStats).length + " slots counting");
}

setInterval(function () {
    emit({ type: "tier-a-heartbeat", stage: stage, records: records, suppressed: suppressed,
           distinct: seen.size, stats: hookStats, fatal: fatal });
}, HEARTBEAT_MS);

bootstrap();



