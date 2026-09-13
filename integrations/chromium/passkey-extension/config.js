// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

// Packaged profile data, not page input. A production/profile build replaces
// this file and the single matching manifest host permission together.
Object.defineProperty(globalThis, "PM_PASSKEY_PROFILE", {
  value: Object.freeze({
    origin: "https://passkey.test:8443",
    rpId: "passkey.test",
    nativeHost: "org.passwordmanager.passkey"
  }),
  writable: false,
  configurable: false
});
