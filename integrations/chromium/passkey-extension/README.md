# Custodial passkey MV3 bridge

This fixed-ID MV3 package is deliberately a transport only. It has no popup,
options/admin page, remote code, vault data, or signing key. The isolated
content script accepts requests only from the top-level
`https://passkey.test` document. The service worker replaces all sender fields
with Chromium's `MessageSender` values and uses the single Native Messaging
host `org.passwordmanager.passkey`.

The unpacked extension ID derived from the fixed manifest key is
`jeaiefhkopnahbmombchmbpjifdjjdai`. A laboratory Native Messaging manifest must
therefore use exactly
`chrome-extension://jeaiefhkopnahbmombchmbpjifdjjdai/` in `allowed_origins`.
