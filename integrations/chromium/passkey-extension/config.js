// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

// Packaged profile data, not page input. A production/profile build replaces
// this file and the single matching manifest host permission together.
if (!Object.prototype.hasOwnProperty.call(globalThis, "PM_PASSKEY_PROFILE")) {
  Object.defineProperty(globalThis, "PM_PASSKEY_PROFILE", {
    value: Object.freeze({
    origin: "https://passkey.test:8443",
    rpId: "passkey.test",
    nativeHost: "org.passwordmanager.passkey",
    // Opaque vault item selected by the installed browser profile. It is not
    // page input and is replaced together with origin/RP for a deployed profile.
    itemId: ""
    }),
    writable: false,
    configurable: false
  });
}
