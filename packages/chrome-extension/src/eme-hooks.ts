// ── EME (Encrypted Media Extensions) フック ──

import { captured } from "./state";
import { logCapture } from "./msl-processor";
import { bufToHex, bufToB64, formatKID } from "./utils";
import { parsePSSH } from "./pssh-parser";

const EME_PREFIX = "[EME-Capture]";

const _requestMKSA = navigator.requestMediaKeySystemAccess.bind(navigator);

function wrapSession(session: MediaKeySession, keySystem: string): MediaKeySession {
  const _generateRequest = session.generateRequest.bind(session);
  const _update = session.update.bind(session);
  const _close = session.close.bind(session);

  session.generateRequest = async function (initDataType: string, initData: BufferSource): Promise<void> {
    const initBytes = initData instanceof ArrayBuffer ? new Uint8Array(initData) : new Uint8Array((initData as Uint8Array).buffer);
    const parsed = parsePSSH(initBytes);
    const entry = logCapture("eme.generateRequest", {
      keySystem,
      initDataType,
      initDataSize: initBytes.byteLength,
      pssh: parsed,
    });
    captured.eme.sessions.push(entry);
    for (const box of parsed.boxes) {
      if (box.kids) {
        for (const kid of box.kids) {
          console.log(`${EME_PREFIX} KID: ${kid} (${box.systemName})`);
        }
      }
    }
    return _generateRequest(initDataType, initData);
  };

  session.addEventListener("message", (event: Event) => {
    const msgEvent = event as MediaKeyMessageEvent;
    const msgBytes = new Uint8Array(msgEvent.message);
    const entry = logCapture("eme.licenseRequest", {
      keySystem,
      sessionId: session.sessionId,
      messageType: msgEvent.messageType,
      messageSize: msgBytes.byteLength,
      message_b64: bufToB64(msgBytes),
    });
    captured.eme.licenseRequests.push(entry);
  });

  session.addEventListener("keystatuseschange", () => {
    const statuses: Array<{ kid: string; status: MediaKeyStatus }> = [];
    session.keyStatuses.forEach((status: MediaKeyStatus, keyId: BufferSource) => {
      const kidBytes = keyId instanceof ArrayBuffer ? new Uint8Array(keyId) : new Uint8Array((keyId as Uint8Array).buffer);
      const kid = formatKID(bufToHex(kidBytes));
      statuses.push({ kid, status });
      console.log(`${EME_PREFIX} Key status: ${kid} → ${status}`);
    });
    const entry = logCapture("eme.keyStatusChange", {
      keySystem,
      sessionId: session.sessionId,
      statuses,
    });
    captured.eme.keyStatuses.push(entry);
  });

  session.update = async function (response: BufferSource): Promise<void> {
    const respBytes = response instanceof ArrayBuffer ? new Uint8Array(response) : new Uint8Array((response as Uint8Array).buffer);
    const entry = logCapture("eme.licenseResponse", {
      keySystem,
      sessionId: session.sessionId,
      responseSize: respBytes.byteLength,
      response_b64: bufToB64(respBytes),
    });
    captured.eme.licenseResponses.push(entry);
    return _update(response);
  };

  session.close = async function (): Promise<void> {
    logCapture("eme.closeSession", { keySystem, sessionId: session.sessionId });
    return _close();
  };

  return session;
}

function wrapMediaKeys(mediaKeys: MediaKeys, keySystem: string): MediaKeys {
  const _createSession = mediaKeys.createSession.bind(mediaKeys);
  const _setServerCert = mediaKeys.setServerCertificate.bind(mediaKeys);

  mediaKeys.setServerCertificate = async function (cert: BufferSource): Promise<boolean> {
    const certBytes = cert instanceof ArrayBuffer ? new Uint8Array(cert) : new Uint8Array((cert as Uint8Array).buffer);
    logCapture("eme.setServerCertificate", {
      keySystem,
      certSize: certBytes.byteLength,
      cert_b64: bufToB64(certBytes),
    });
    return _setServerCert(cert);
  };

  mediaKeys.createSession = function (sessionType?: MediaKeySessionType): MediaKeySession {
    const session = _createSession(sessionType ?? "temporary");
    console.log(`${EME_PREFIX} Session created (${sessionType ?? "temporary"})`);
    return wrapSession(session, keySystem);
  };

  return mediaKeys;
}

function wrapMKSA(access: MediaKeySystemAccess, keySystem: string): MediaKeySystemAccess {
  const _createMediaKeys = access.createMediaKeys.bind(access);
  access.createMediaKeys = async function (): Promise<MediaKeys> {
    const mediaKeys = await _createMediaKeys();
    console.log(`${EME_PREFIX} MediaKeys created for ${keySystem}`);
    return wrapMediaKeys(mediaKeys, keySystem);
  };
  return access;
}

export function installEmeHooks(): void {
  navigator.requestMediaKeySystemAccess = async function (
    keySystem: string,
    supportedConfigurations: MediaKeySystemConfiguration[],
  ): Promise<MediaKeySystemAccess> {
    console.log(`${EME_PREFIX} requestMediaKeySystemAccess: ${keySystem}`);
    logCapture("eme.requestAccess", { keySystem, supportedConfigurations });
    const access = await _requestMKSA(keySystem, supportedConfigurations);
    return wrapMKSA(access, keySystem);
  };

  console.log(`${EME_PREFIX} EME hooks installed`);
}
