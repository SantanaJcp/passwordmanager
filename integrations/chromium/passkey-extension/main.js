// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

// This MAIN-world adapter deliberately implements only the WebAuthn response
// surface consumed by the fixed Keycloak profile. The page supplies public
// ceremony options; origin, RP, document and selected vault item are replaced
// by the isolated extension/native bridge before custody sees them.
(() => {
  const profile = PM_PASSKEY_PROFILE;
  if (window !== window.top || location.origin !== profile.origin ||
      !navigator.credentials || !window.PublicKeyCredential) return;
  if (globalThis.__PM_PASSKEY_ADAPTER_INSTALLED__ === true) return;

  const requestEvent = "pm-passkey-request-v1";
  const responseEvent = "pm-passkey-response-v1";
  const pending = new Map();
  const hex = value => Array.from(new Uint8Array(value), byte =>
    byte.toString(16).padStart(2, "0")).join("");
  const bytes = value => {
    if (typeof value !== "string" || value.length % 2 !== 0) throw new Error("NOT_ALLOWED");
    const output = new Uint8Array(value.length / 2);
    for (let at = 0; at < output.length; at += 1) {
      const byte = Number.parseInt(value.slice(at * 2, at * 2 + 2), 16);
      if (!Number.isInteger(byte)) throw new Error("NOT_ALLOWED");
      output[at] = byte;
    }
    return output;
  };
  const b64url = value => {
    let binary = "";
    for (const byte of value) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };
  const randomHex = length => {
    const value = new Uint8Array(length);
    crypto.getRandomValues(value);
    return hex(value);
  };
  const documentToken = randomHex(16);

  window.addEventListener(responseEvent, event => {
    const response = event instanceof CustomEvent ? event.detail : undefined;
    const waiter = response && pending.get(response.requestId);
    if (waiter) {
      pending.delete(response.requestId);
      waiter(response);
    }
  });

  const send = request => new Promise(resolve => {
    pending.set(request.requestId, resolve);
    window.dispatchEvent(new CustomEvent(requestEvent, {detail: request}));
  });
  const responseFor = async request => {
    let response = await send(request);
    while (response?.ok === true && response.state === "waiting") {
      document.documentElement.dataset.pmPasskeyState = "waiting";
      document.documentElement.dataset.pmPasskeyRequest = request.requestId;
      await new Promise(resolve => setTimeout(resolve, 50));
      response = await send({
        op: "response", requestId: request.requestId,
        documentId: documentToken, origin: profile.origin, rpId: profile.rpId
      });
    }
    delete document.documentElement.dataset.pmPasskeyState;
    delete document.documentElement.dataset.pmPasskeyRequest;
    if (!response || response.ok !== true) throw new DOMException("Custodial passkey unavailable", "NotAllowedError");
    return response;
  };
  const baseRequest = (op, publicKey) => ({
    op, requestId: randomHex(16), documentId: documentToken,
    origin: profile.origin, rpId: profile.rpId,
    challenge: hex(publicKey.challenge),
    credentialIds: [], uv: "preferred"
  });

  const custodialCreate = async options => {
    if (!options?.publicKey) throw new DOMException("Only the installed custodial WebAuthn profile is supported", "NotSupportedError");
    const pk = options.publicKey;
    const request = baseRequest("create", pk);
    request.userHandle = hex(pk.user?.id);
    request.userName = pk.user?.name ?? "";
    request.displayName = pk.user?.displayName ?? "";
    request.uv = pk.authenticatorSelection?.userVerification ?? "preferred";
    document.documentElement.dataset.pmPasskeyCalled = request.requestId;
    const response = await responseFor(request);
    if (response.state !== "registration") throw new DOMException("Invalid custody response", "NotAllowedError");
    const rawId = bytes(response.credentialId);
    return {
      id: b64url(rawId), rawId: rawId.buffer, type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: bytes(response.clientDataJSON).buffer,
        attestationObject: bytes(response.attestationObject).buffer,
        getTransports: () => []
      }
    };
  };
  const custodialGet = async options => {
    if (!options?.publicKey) throw new DOMException("Only the installed custodial WebAuthn profile is supported", "NotSupportedError");
    const pk = options.publicKey;
    if (!/^[0-9a-f]{32}$/.test(profile.itemId)) throw new DOMException("No selected passkey", "NotAllowedError");
    const request = baseRequest("get", pk);
    request.itemId = profile.itemId;
    request.issuedAt = Date.now() * 1000;
    request.nonce = randomHex(16);
    request.userHandle = "";
    request.userName = "";
    request.displayName = "";
    request.credentialIds = (pk.allowCredentials ?? []).map(value => hex(value.id));
    request.uv = pk.userVerification ?? "preferred";
    document.documentElement.dataset.pmPasskeyCalled = request.requestId;
    const response = await responseFor(request);
    if (response.state !== "assertion") throw new DOMException("Invalid custody response", "NotAllowedError");
    const rawId = bytes(response.credentialId);
    return {
      id: b64url(rawId), rawId: rawId.buffer, type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        authenticatorData: bytes(response.authenticatorData).buffer,
        clientDataJSON: bytes(response.clientDataJSON).buffer,
        signature: bytes(response.signature).buffer,
        userHandle: bytes(response.userHandle).buffer
      }
    };
  };
  // Chromium's CredentialsContainer instance is not extensible. Web-IDL
  // operations live on its per-realm prototype, whose descriptors are
  // configurable; replace those operations only in this exact origin's MAIN
  // world rather than silently falling back to a platform authenticator.
  Object.defineProperties(Object.getPrototypeOf(navigator.credentials), {
    create: {value: custodialCreate, configurable: false, writable: false},
    get: {value: custodialGet, configurable: false, writable: false}
  });
  Object.defineProperty(globalThis, "__PM_PASSKEY_ADAPTER_INSTALLED__", {
    value: true, writable: false, configurable: false
  });
})();
