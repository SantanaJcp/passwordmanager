// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const EXACT_ORIGIN = PM_PASSKEY_PROFILE.origin;
const REQUEST_EVENT = "pm-passkey-request-v1";
const RESPONSE_EVENT = "pm-passkey-response-v1";

if (window === window.top && location.origin === EXACT_ORIGIN) {
  window.addEventListener(REQUEST_EVENT, async (event) => {
    if (!(event instanceof CustomEvent) || event.target !== window || !event.detail) return;
    const request = structuredClone(event.detail);
    try {
      const response = await chrome.runtime.sendMessage({type: "passkey", request});
      window.dispatchEvent(new CustomEvent(RESPONSE_EVENT, {detail: response}));
    } catch (_error) {
      window.dispatchEvent(new CustomEvent(RESPONSE_EVENT, {
        detail: {ok: false, error: "NOT_ALLOWED"}
      }));
    }
  });
}
