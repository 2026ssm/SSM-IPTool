# Hikvision SADP password reset — research notes (parked)

Status: PARKED until the official SADP SDK package is obtained. Nothing implemented.

## Decision

Bind Hikvision's official SADP SDK (`Sadp.dll` + bundled OpenSSL `libcrypto-1_1-x64.dll`
/ `libssl-1_1-x64.dll`) as a fourth native addon — the same pattern as the UNV/TVT/Dahua
addons. No reverse engineering of Hikvision's signing crypto needed: the SDK implements
the whole reset surface, documented in Hikvision's `SADPSDK_开发指南_V4.4_20231130.pdf`
(dev guide V4.4, 2023-11-30).

A working community map of the full C API: `github.com/luo703/pysadp` (ctypes bindings,
pysadp/client.py + pysadp/models.py — verified structures and reset enum from its source).

## The C API

- `SADP_Start_V40(PDEVICE_FIND_CALLBACK_V40)` / `SADP_Stop` / `SADP_SendInquiry` —
  discovery. The device callback struct `SADP_DEVICE_INFO_V40` reports serial number,
  MAC, IPs/ports/ports-over-TLS, `byActivated`, capability flags `bySupport*`,
  `bySupportPasswordResetType`, `bySupportCodeEncrypt` (AES128-ECB reset), Ezviz bind
  status, lockout info, and message type (`iResult`: 1 add / 2 update / 3 remove /
  4 restart / 5 update-fail).
- `SADP_GetDeviceConfig(serial, cmd, in, inSize, out, outSize)` with
  `cmd=1` (SADP_GET_DEVICE_CODE) → `SADP_SAFE_CODE.szDeviceCode` — the payload inside
  the exported DeviceKey.xml / the QR code SADP shows for support-requests;
  `cmd=2` (SADP_GET_ENCRYPT_STRING) → `SADP_ENCRYPT_STRING.szEncryptString`.
  (Legacy V31 firmware variants: cmds 30/31, wider structs.)
- `SADP_ResetPasswd_V50(serial, SADP_RESET_PARAM_V50*, SADP_DEV_LOCK_INFO*)` —
  preferred; `SADP_ResetPasswd_V40(serial, SADP_RESET_PARAM_V40*, SADP_RET_RESET_PARAM_V40*)`
  — fallback (no phone-QR type on V40). On failure check `SADP_GetLastError`; the
  lock-info out-params carry `byRetryTime` / `bySurplusLockTime` (remaining attempts
  and lock minutes) to surface in the dialog.
- `SADP_RESET_PARAM_V50` fields: `szPassword`, `szCode`, `szAuthFile` (path of the
  Hikvision-returned file), `szGUID`, `byResetType`, `byEnableSyncIPCPW`,
  `struSecurityQuestionCfg` (question ids + answers). Reset types:
  **2 = import Hikvision auth file**, 3 = QR content, 4 = GUID file, 5 = security
  questions, 6 = email verification code, 7 = phone QR scan (V50 only).
- Also available: `SADP_ActivateDevice(serial, password)` (activation of unactivated
  devices), `SADP_ModifyDeviceNetParam_V40(mac, password, SADP_DEV_NET_PARAM*,
  SADP_DEV_RET_NET_PARAM*, size)` (IP/mask/gateway/DHCP/ports incl. SDK-over-TLS port),
  `SADP_GetDeviceConfig`/`SADP_SetDeviceConfig` pass-through, `SADP_GetLastError`,
  `SADP_SetLogToFile`, `SADP_GetSadpVersion`.

Error codes worth mapping (community list): 2009 deny, 2011 timeout, 2018 locked,
2019 not activated, 2022 empty encrypted string, **2023 export file overdue** (the
Hikvision-returned file is valid 24 h), 2024 wrong password, 2026 invalid GUID,
2027 wrong security answer, 2033 illegal verification code.

## Known good context

- SDK user-environment variable convention on the test PC: add `HIK_SADP_SDK_DIR`
  (HIK_SDK_DIR there is the NET SDK — a different product, do not confuse).
- The app's `src/main/services/sadpDiscovery.ts` already speaks SADP UDP multicast
  (239.255.255.250:37020) and fills `passwordReset: { importFile, securityQuestion }`
  flags on rows (src/shared/types.ts) — the UI hook for this feature already exists
  ("Reset…" button, currently only launching the vendor SADP tool via
  ipc/device.ts's `device:openSadpTool`).
- Old-firmware (<5.3.0) local reset-code generation is separately documented
  (hiktools / cameronnewman/hikvision-tooling implementations) — out of scope here,
  those devices predate the PasswordResetAbility flags anyway.

## Integration plan (when SDK arrives)

1. `native/hik-sadp` node-gyp addon (`SADP_SDK_DIR` env, like the other three gyp
   files): exports start(cb)/stop/getCode/getEncryptString/resetPassword(...) as
   AsyncWorkers following the Dahua addon's session/worker patterns; copy the three
   runtime DLLs from the SDK dir into build/Release (the copy-runtime-deps pattern).
2. Discovery decision: the SDK's `SADP_Start_V40` binds UDP 37020, which the app's own
   sadpDiscovery also holds — when the DLL is present, migrate the Hikvision rows to
   the SDK callback (richer: serial + all reset flags + lockout) and keep the plain
   UDP path as fallback when it isn't. Do not run both simultaneously.
3. UI: extend the Hikvision "Reset…" flow (today's SadpResetDialog) into a full
   dialog: Export request file (compose DeviceKey.xml from SDK code + encrypt string
   + serial + time; open the containing folder for emailing to Hikvision support), and
   Import file (file picker → SDK reset type 2 + new password + strength feedback +
   lockout info from the out-struct). Security-question and GUID as secondary modes
   where the device's capability bits say so.
4. Bench-test end-to-end on a real locked device + a returned file from Hikvision
   support (via the user's distributor channel), including the 24 h expiry and the
   lockout countdown display.