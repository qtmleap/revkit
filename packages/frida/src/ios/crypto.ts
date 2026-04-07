import { logData } from "../common/utils";

export function hookCrypto(): void {
    // CCCrypt
    const ccCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    if (ccCrypt) {
        Interceptor.attach(ccCrypt, {
            onEnter: function (args) {
                this.op = args[0];
                this.alg = args[1];
                this.options = args[2];
                this.key = args[3];
                this.keyLength = args[4];
                this.iv = args[5];
                this.dataIn = args[6];
                this.dataInLength = args[7];
                this.dataOut = args[8];
                this.dataOutAvailable = args[9];
                this.dataOutMoved = args[10];

                const opName = this.op == 0 ? "encrypt" : "decrypt";
                const algName = (["AES", "DES", "3DES", "CAST", "RC4", "RC2", "Blowfish"] as string[])[this.alg.toInt32()] || "unknown";
                const keyLen = this.keyLength.toInt32();
                const dataLen = this.dataInLength.toInt32();

                console.log("CCCrypt(" + opName + " alg:" + algName + " keyLen:" + keyLen + " dataLen:" + dataLen + ")");

                const keyBytes = ptr(this.key).readByteArray(keyLen);
                const ivBytes = ptr(this.iv).readByteArray(keyLen);
                logData("CCCrypt." + opName, { alg: algName, keyLen: keyLen, dataLen: dataLen }, keyBytes!);
                logData("CCCrypt." + opName + ".iv", { alg: algName, size: keyLen }, ivBytes!);

                if (this.op == 0) {
                    const plainBytes = ptr(this.dataIn).readByteArray(Math.min(dataLen, 4096));
                    logData("CCCrypt.encrypt.plaintext", { size: dataLen }, plainBytes!);
                    console.log("key:");
                    console.log(hexdump(ptr(this.key), { length: keyLen, header: true, ansi: false }));
                    console.log("iv:");
                    console.log(hexdump(ptr(this.iv), { length: keyLen, header: true, ansi: false }));
                }
            },
            onLeave: function (retval) {
                const outLen = Memory.readUInt(this.dataOutMoved);
                if (this.op == 1) {
                    const decrypted = ptr(this.dataOut).readByteArray(Math.min(outLen, 4096));
                    logData("CCCrypt.decrypt.plaintext", { size: outLen }, decrypted!);
                    console.log("CCCrypt decrypt dataOut:");
                    console.log(hexdump(ptr(this.dataOut), { length: Math.min(outLen, 512), header: true, ansi: false }));
                } else {
                    console.log("CCCrypt encrypt dataOut (" + outLen + " bytes)");
                }
            }
        });
        console.log("[+] Hooked CCCrypt");
    }

    // SecKeyEncrypt
    const secKeyEnc = Module.findExportByName("Security", "SecKeyEncrypt");
    if (secKeyEnc) {
        Interceptor.attach(secKeyEnc, {
            onEnter: function (args) {
                console.log("SecKeyEncrypt()=" + args[2].readCString() + "=");
                console.log("SecKeyEncrypt called from:\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
            }
        });
        console.log("[+] Hooked SecKeyEncrypt");
    }

    // SecKeyRawSign
    const secKeySign = Module.findExportByName("Security", "SecKeyRawSign");
    if (secKeySign) {
        Interceptor.attach(secKeySign, {
            onEnter: function (args) {
                console.log("SecKeyRawSign()=" + args[2].readCString() + "=");
                console.log("SecKeyRawSign called from:\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
            }
        });
        console.log("[+] Hooked SecKeyRawSign");
    }
}
