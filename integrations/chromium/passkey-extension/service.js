// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

importScripts("config.js");
const EXACT_ORIGIN = PM_PASSKEY_PROFILE.origin;
const EXACT_RP = PM_PASSKEY_PROFILE.rpId;
const NATIVE_HOST = PM_PASSKEY_PROFILE.nativeHost;
const documents = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "install-passkey-adapter" && validSenderContext(sender)) {
    chrome.scripting.executeScript({
      target: {tabId: sender.tab.id, frameIds: [0]},
      files: ["config.js", "main.js"],
      world: "MAIN",
      injectImmediately: true
    }).then(() => sendResponse({ok: true})).catch(() => sendResponse({ok: false}));
    return true;
  }
  if (!validSender(message, sender)) {
    sendResponse({ok: false, error: "NOT_ALLOWED"});
    return false;
  }
  const request = message.request;
  const prior = documents.get(request.requestId);
  if (prior && prior !== sender.documentId) {
    sendResponse({ok: false, error: "DOCUMENT_CHANGED"});
    return false;
  }
  documents.set(request.requestId, sender.documentId);
  const bounded = {
    ...request,
    origin: EXACT_ORIGIN,
    rpId: EXACT_RP,
    topLevel: true,
    frameId: 0,
    senderOrigin: sender.origin,
    documentId: sender.documentId
  };
  chrome.runtime.sendNativeMessage(NATIVE_HOST, bounded, (response) => {
    if (chrome.runtime.lastError || !response) {
      sendResponse({ok: false, error: "CUSTODY_UNAVAILABLE", requestId: request.requestId});
    } else {
      sendResponse({...response, requestId: request.requestId});
    }
  });
  return true;
});

function validSender(message, sender) {
  return message && message.type === "passkey" && message.request &&
    validSenderContext(sender);
}

function validSenderContext(sender) {
  return sender &&
    sender.frameId === 0 && typeof sender.documentId === "string" &&
    sender.documentId.length > 0 && sender.origin === EXACT_ORIGIN &&
    sender.url?.startsWith(`${EXACT_ORIGIN}/`) &&
    sender.tab && sender.tab.id >= 0;
}
