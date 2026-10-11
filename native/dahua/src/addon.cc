// N-API bridge over Dahua's General NetSDK — discovery, the search-level
// "modify device IP" command, and a TCP login session for the
// factory-reset commands (CLIENT_ControlDevice's restore-default control
// and CLIENT_ResetSystem). Ported from SSM-VMS's own
// native/dahua/src/addon.cc, stripped of everything this tool doesn't need
// (live view, playback; the login itself is kept only for the resets).
#include <napi.h>
#include <windows.h>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "dhnetsdk.h"

namespace {

Napi::ThreadSafeFunction g_discoveryTsfn;
std::mutex g_discoveryMutex;
bool g_discoveryActive = false;
LLONG g_discoveryHandle = 0;

// Bounded, not 0/unbounded — same reasoning as Uniview's addon.cc (this
// whole family of native addons shares the lesson from SSM-VMS's own real
// 51GB memory leak).
constexpr size_t kDiscoveryQueueSize = 64;

// The full raw record of every device the last search saw, keyed by its
// szMac exactly as reported to JS. CLIENT_ModifyDeviceEx needs the whole
// DEVICE_NET_INFO_EX back (including the opaque verifyData ECC blob), not
// just the fields JS knows about — the SDK's own DevInit demo copies the
// searched record and edits it in place, and this follows that.
std::mutex g_lastSeenMutex;
std::map<std::string, DEVICE_NET_INFO_EX> g_lastSeen;

// CLIENT_ModifyDeviceEx is documented "not support multi-thread".
std::mutex g_modifyMutex;
constexpr int kModifyWaitMs = 5000;

std::string SafeFieldString(const char* field, size_t fieldSize) {
  return std::string(field, strnlen(field, fieldSize));
}

void CopyField(char* dest, size_t destSize, const std::string& value) {
  strncpy_s(dest, destSize, value.c_str(), _TRUNCATE);
}

// The fields JS gets for each searched device (broadcast or by IP).
Napi::Object DeviceToObject(Napi::Env env, const DEVICE_NET_INFO_EX& d) {
  Napi::Object obj = Napi::Object::New(env);
  obj.Set("host", SafeFieldString(d.szIP, sizeof(d.szIP)));
  obj.Set("port", Napi::Number::New(env, d.nPort));
  obj.Set("httpPort", Napi::Number::New(env, d.nHttpPort));
  obj.Set("mac", SafeFieldString(d.szMac, sizeof(d.szMac)));
  obj.Set("subnetMask", SafeFieldString(d.szSubmask, sizeof(d.szSubmask)));
  obj.Set("gateway", SafeFieldString(d.szGateway, sizeof(d.szGateway)));
  obj.Set("model", SafeFieldString(d.szDetailType, sizeof(d.szDetailType)));
  obj.Set("vendor", SafeFieldString(d.szVendor, sizeof(d.szVendor)));
  obj.Set("name", SafeFieldString(d.szDevName, sizeof(d.szDevName)));
  // byManuFactory (EM_IPC_TYPE) is the real "is this genuinely a
  // Dahua device" signal — DH_IPC_PRIVATE (0) means the device
  // speaks Dahua's own private protocol natively. szVendor is
  // documented as "OEM type" and confirmed live (in SSM-VMS) to be
  // blank on genuine Dahua-branded hardware, so it can't be used to
  // confirm the brand the way it first looked like it could.
  obj.Set("manuFactory", Napi::Number::New(env, static_cast<int>(d.byManuFactory)));
  obj.Set("deviceType", SafeFieldString(d.szDeviceType, sizeof(d.szDeviceType)));
  obj.Set("dhcp", Napi::Boolean::New(env, d.bDhcpEn));
  return obj;
}

void CALLBACK OnDeviceDiscovered(DEVICE_NET_INFO_EX* pDevNetInfo, void* /*pUserData*/) {
  if (!pDevNetInfo) return;

  // Temporary diagnostic - szDeviceType's exact string values for THIS
  // struct (the one CLIENT_StartSearchDevices actually fills) are
  // unconfirmed. A same-named-but-different field elsewhere in this SDK
  // (szDevClass) is documented as literally "IPC"/"DVR"/"NVR" strings,
  // which is why the TS side tries a string-match against those same
  // values, but this needs a real live scan to confirm it's actually
  // right for this specific struct before trusting it further.
  fprintf(stderr, "[dahua-devicetype-diag] ip=%s szDeviceType=%s\n", pDevNetInfo->szIP, pDevNetInfo->szDeviceType);
  fflush(stderr);

  // A dual-stack device answers the search broadcast twice — once with a
  // dotted-decimal IPv4 szIP, once with an IPv6-formatted one (confirmed
  // live in SSM-VMS's own copy of this discovery call: "2008::6/112"
  // alongside the real IPv4 address for the same physical device). Nothing
  // here handles non-IPv4 hosts, so the IPv6 response is dropped before it
  // can surface as a bogus duplicate "device" — or replace the device's
  // IPv4 record in g_lastSeen, which the modify command sends back (with
  // that reply's own DHCP flag). An IPv6 reply with no address comes as
  // just "/0" (seen live on an ECL-IP2TN), so anything without a dot goes.
  if (std::strchr(pDevNetInfo->szIP, ':') != nullptr || std::strchr(pDevNetInfo->szIP, '.') == nullptr) return;

  {
    std::lock_guard<std::mutex> seenLock(g_lastSeenMutex);
    g_lastSeen[SafeFieldString(pDevNetInfo->szMac, sizeof(pDevNetInfo->szMac))] = *pDevNetInfo;
  }

  std::lock_guard<std::mutex> lock(g_discoveryMutex);
  if (!g_discoveryActive) return;

  auto* info = new DEVICE_NET_INFO_EX(*pDevNetInfo);
  auto status = g_discoveryTsfn.NonBlockingCall(
      info, [](Napi::Env env, Napi::Function jsCallback, DEVICE_NET_INFO_EX* d) {
        jsCallback.Call({DeviceToObject(env, *d)});
        delete d;
      });
  if (status != napi_ok) delete info;
}

struct ModifyRequest {
  std::string mac;
  std::string ip;
  std::string subnetMask;
  std::string gateway;
  int port = 0;
  int httpPort = 0;
  bool setStatic = false;
  bool setDhcp = false;
  std::string username;
  std::string password;
  std::string localIp;
};

// Resolves { ok: true } or { ok: false, errorCode } (CLIENT_GetLastError
// with the 0x80000000 flag masked off, same as the SDK demo) rather than
// rejecting, so the TS side can map known codes to a readable message.
class ModifyDeviceWorker : public Napi::AsyncWorker {
 public:
  ModifyDeviceWorker(Napi::Env env, ModifyRequest request)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), request_(std::move(request)) {}

  void Execute() override {
    // NET_IN_MODIFY_IP embeds DEVICE_NET_INFO_EX2 (several KB) — heap, not
    // the worker thread's stack.
    auto in = std::make_unique<NET_IN_MODIFY_IP>();
    std::memset(in.get(), 0, sizeof(NET_IN_MODIFY_IP));
    in->dwSize = sizeof(NET_IN_MODIFY_IP);
    {
      std::lock_guard<std::mutex> seenLock(g_lastSeenMutex);
      auto it = g_lastSeen.find(request_.mac);
      if (it == g_lastSeen.end()) {
        notFound_ = true;
        SecureZeroMemory(&request_.password[0], request_.password.size());
        return;
      }
      in->stuDevNetInfo.stuDevInfo = it->second;
    }

    DEVICE_NET_INFO_EX& dev = in->stuDevNetInfo.stuDevInfo;
    CopyField(dev.szIP, sizeof(dev.szIP), request_.ip);
    CopyField(dev.szSubmask, sizeof(dev.szSubmask), request_.subnetMask);
    CopyField(dev.szGateway, sizeof(dev.szGateway), request_.gateway);
    if (request_.port > 0) dev.nPort = request_.port;
    if (request_.httpPort > 0) dev.nHttpPort = static_cast<unsigned short>(request_.httpPort);
    // A new address means a static one — the searched record keeps the
    // device's DHCP flag, and a device left in DHCP mode ignores the IP.
    if (request_.setStatic) dev.bDhcpEn = false;
    // DHCP the other way round: the device takes its address from the DHCP
    // server, and the address fields go back as searched.
    if (request_.setDhcp) dev.bDhcpEn = true;
    CopyField(dev.szUserName, sizeof(dev.szUserName), request_.username);
    CopyField(dev.szPassWord, sizeof(dev.szPassWord), request_.password);
    // szUserName/szPassWord are only 16 bytes; the SDK's longer
    // szNewUserName/szNewPassWord fields carry credentials that don't fit.
    if (request_.username.size() >= sizeof(dev.szUserName)) {
      dev.bNewUserName = TRUE;
      CopyField(dev.szNewUserName, sizeof(dev.szNewUserName), request_.username);
    }
    if (request_.password.size() >= sizeof(dev.szPassWord)) {
      dev.bNewWordLen = TRUE;
      CopyField(dev.szNewPassWord, sizeof(dev.szNewPassWord), request_.password);
    }
    CopyField(in->stuDevNetInfo.szLocalIP, sizeof(in->stuDevNetInfo.szLocalIP), request_.localIp);

    NET_OUT_MODIFY_IP out;
    std::memset(&out, 0, sizeof(out));
    out.dwSize = sizeof(out);
    {
      std::lock_guard<std::mutex> modifyLock(g_modifyMutex);
      ok_ = CLIENT_ModifyDeviceEx(in.get(), &out, kModifyWaitMs) == TRUE;
      if (!ok_) errorCode_ = CLIENT_GetLastError() & 0x7fffffff;
    }

    SecureZeroMemory(in.get(), sizeof(NET_IN_MODIFY_IP));
    SecureZeroMemory(&request_.password[0], request_.password.size());
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (notFound_) result.Set("notFound", Napi::Boolean::New(env, true));
    if (!ok_ && !notFound_) result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  ModifyRequest request_;
  bool ok_ = false;
  bool notFound_ = false;
  DWORD errorCode_ = 0;
};

// Search by IP — CLIENT_SearchDevicesByIPs ("search device ip cross VLAN"):
// each listed address is asked directly instead of by broadcast, for
// devices whose replies to the broadcast search never reach this PC. The
// call blocks for its wait time; replies are filtered and cached in
// g_lastSeen (for the modify command) exactly like the broadcast search's.
// They're collected through a global sink rather than the user-data
// pointer, so a reply the SDK delivers after the call has returned can't
// land in a worker that's already gone.
std::mutex g_ipSearchRunMutex;
std::mutex g_ipSearchSinkMutex;
std::vector<DEVICE_NET_INFO_EX>* g_ipSearchSink = nullptr;

void CALLBACK OnIpSearchReply(DEVICE_NET_INFO_EX* pDevNetInfo, void* /*pUserData*/) {
  if (!pDevNetInfo) return;
  if (std::strchr(pDevNetInfo->szIP, ':') != nullptr || std::strchr(pDevNetInfo->szIP, '.') == nullptr) return;
  {
    std::lock_guard<std::mutex> seenLock(g_lastSeenMutex);
    g_lastSeen[SafeFieldString(pDevNetInfo->szMac, sizeof(pDevNetInfo->szMac))] = *pDevNetInfo;
  }
  std::lock_guard<std::mutex> lock(g_ipSearchSinkMutex);
  if (g_ipSearchSink) g_ipSearchSink->push_back(*pDevNetInfo);
}

class SearchByIpsWorker : public Napi::AsyncWorker {
 public:
  SearchByIpsWorker(Napi::Env env, std::vector<std::string> ips, std::string localIp, int waitMs)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        ips_(std::move(ips)),
        localIp_(std::move(localIp)),
        waitMs_(waitMs) {}

  void Execute() override {
    std::lock_guard<std::mutex> runLock(g_ipSearchRunMutex);
    // DEVICE_IP_SEARCH_INFO holds 256 addresses of 64 bytes — heap, not the
    // worker thread's stack.
    auto info = std::make_unique<DEVICE_IP_SEARCH_INFO>();
    std::memset(info.get(), 0, sizeof(DEVICE_IP_SEARCH_INFO));
    info->dwSize = sizeof(DEVICE_IP_SEARCH_INFO);
    info->nIpNum = static_cast<int>(ips_.size() < DH_MAX_SAERCH_IP_NUM ? ips_.size() : DH_MAX_SAERCH_IP_NUM);
    for (int i = 0; i < info->nIpNum; ++i) CopyField(info->szIP[i], sizeof(info->szIP[i]), ips_[i]);
    {
      std::lock_guard<std::mutex> lock(g_ipSearchSinkMutex);
      g_ipSearchSink = &found_;
    }
    CLIENT_SearchDevicesByIPs(info.get(), OnIpSearchReply, 0, localIp_.empty() ? nullptr : &localIp_[0], static_cast<DWORD>(waitMs_));
    std::lock_guard<std::mutex> lock(g_ipSearchSinkMutex);
    g_ipSearchSink = nullptr;
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Array result = Napi::Array::New(env);
    for (size_t i = 0; i < found_.size(); ++i) result[static_cast<uint32_t>(i)] = DeviceToObject(env, found_[i]);
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  std::vector<std::string> ips_;
  std::string localIp_;
  int waitMs_;
  std::vector<DEVICE_NET_INFO_EX> found_;
};

std::string GetString(const Napi::Object& obj, const char* key) {
  Napi::Value v = obj.Get(key);
  return v.IsString() ? v.As<Napi::String>().Utf8Value() : std::string();
}

int GetInt(const Napi::Object& obj, const char* key) {
  Napi::Value v = obj.Get(key);
  return v.IsNumber() ? v.As<Napi::Number>().Int32Value() : 0;
}

// Logged-in SDK sessions, keyed by a small id handed to JS (the SDK's own
// login handle stays as the map's value, never exposed). Both reset
// commands run on a logged-in TCP session (EM_LOGIN_SPEC_CAP_TCP).
std::mutex g_sessionMutex;
std::map<int, LLONG> g_sessions;
int g_nextSessionId = 1;
constexpr int kResetWaitMs = 5000;

LLONG SessionLoginId(int sessionId) {
  std::lock_guard<std::mutex> lock(g_sessionMutex);
  auto it = g_sessions.find(sessionId);
  return it == g_sessions.end() ? 0 : it->second;
}

// CLIENT_LoginWithHighLevelSecurity (TCP login on the device port).
// Resolves { ok, sessionId } or { ok: false, errorCode } with the login's
// own nError (1 = wrong username or password, 5 = locked, ...), so the TS
// side can map known codes to readable messages.
class LoginWorker : public Napi::AsyncWorker {
 public:
  LoginWorker(Napi::Env env, std::string host, int port, std::string username, std::string password)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        host_(std::move(host)),
        port_(port),
        username_(std::move(username)),
        password_(std::move(password)) {}

  void Execute() override {
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY in;
    std::memset(&in, 0, sizeof(in));
    in.dwSize = sizeof(in);
    CopyField(in.szIP, sizeof(in.szIP), host_);
    in.nPort = port_;
    CopyField(in.szUserName, sizeof(in.szUserName), username_);
    CopyField(in.szPassword, sizeof(in.szPassword), password_);
    in.emSpecCap = EM_LOGIN_SPEC_CAP_TCP;
    NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY out;
    std::memset(&out, 0, sizeof(out));
    out.dwSize = sizeof(out);
    const LLONG loginId = CLIENT_LoginWithHighLevelSecurity(&in, &out);
    SecureZeroMemory(&in, sizeof(in));
    if (!password_.empty()) SecureZeroMemory(&password_[0], password_.size());
    if (!loginId) {
      errorCode_ = out.nError;
      return;
    }
    {
      std::lock_guard<std::mutex> lock(g_sessionMutex);
      sessionId_ = g_nextSessionId++;
      g_sessions[sessionId_] = loginId;
    }
    ok_ = true;
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (ok_) result.Set("sessionId", Napi::Number::New(env, sessionId_));
    else result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  std::string host_;
  int port_;
  std::string username_;
  std::string password_;
  bool ok_ = false;
  int sessionId_ = 0;
  DWORD errorCode_ = 0;
};

// CLIENT_ControlDevice's restore-default control: with the mask below the
// device restores every documented setting area EXCEPT the network one
// (DH_RESTORE_NETWORK is deliberately omitted — the header documents the
// value as an AND/OR-able mask), so the device keeps its IP settings and
// comes back at the same address with the same login, then reboots. The
// catch-all DH_RESTORE_ALL can't be used for that (it includes the
// network), so the individual areas are listed.
constexpr DWORD kRestoreDefaultKeepNetworkMask = DH_RESTORE_COMMON | DH_RESTORE_CODING | DH_RESTORE_VIDEO | DH_RESTORE_COMM |
                                                 DH_RESTORE_ALARM | DH_RESTORE_VIDEODETECT | DH_RESTORE_PTZ |
                                                 DH_RESTORE_OUTPUTMODE | DH_RESTORE_CHANNELNAME | DH_RESTORE_VIDEOINOPTIONS |
                                                 DH_RESTORE_CPS | DH_RESTORE_INTELLIGENT | DH_RESTORE_REMOTEDEVICE |
                                                 DH_RESTORE_DECODERVIDEOOUT | DH_RESTORE_LINKMODE | DH_RESTORE_COMPOSITE;

class RestoreDefaultWorker : public Napi::AsyncWorker {
 public:
  RestoreDefaultWorker(Napi::Env env, int sessionId)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), sessionId_(sessionId) {}

  void Execute() override {
    const LLONG loginId = SessionLoginId(sessionId_);
    if (!loginId) {
      missing_ = true;
      return;
    }
    DWORD mask = kRestoreDefaultKeepNetworkMask;
    {
      std::lock_guard<std::mutex> lock(g_modifyMutex);
      ok_ = CLIENT_ControlDevice(loginId, DH_CTRL_RESTOREDEFAULT, &mask, kResetWaitMs) == TRUE;
      if (!ok_) errorCode_ = CLIENT_GetLastError() & 0x7fffffff;
    }
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (missing_) result.Set("missing", Napi::Boolean::New(env, true));
    if (!ok_ && !missing_) result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  int sessionId_;
  bool ok_ = false;
  bool missing_ = false;
  DWORD errorCode_ = 0;
};

// CLIENT_ResetSystem: the full factory reset, network settings and login
// included. The device reboots (often before finishing its reply — a FALSE
// with "no response" is reported as unconfirmed rather than failed, and
// the TS side words its result accordingly).
class ResetSystemWorker : public Napi::AsyncWorker {
 public:
  ResetSystemWorker(Napi::Env env, int sessionId)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), sessionId_(sessionId) {}

  void Execute() override {
    const LLONG loginId = SessionLoginId(sessionId_);
    if (!loginId) {
      missing_ = true;
      return;
    }
    NET_IN_RESET_SYSTEM in;
    std::memset(&in, 0, sizeof(in));
    in.dwSize = sizeof(in);
    NET_OUT_RESET_SYSTEM out;
    std::memset(&out, 0, sizeof(out));
    out.dwSize = sizeof(out);
    {
      std::lock_guard<std::mutex> lock(g_modifyMutex);
      ok_ = CLIENT_ResetSystem(loginId, &in, &out, kResetWaitMs) == TRUE;
      if (!ok_) errorCode_ = CLIENT_GetLastError() & 0x7fffffff;
    }
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (missing_) result.Set("missing", Napi::Boolean::New(env, true));
    if (!ok_ && !missing_) result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  int sessionId_;
  bool ok_ = false;
  bool missing_ = false;
  DWORD errorCode_ = 0;
};

// login({ host, port, username, password }) → { ok, sessionId | errorCode }
Napi::Value Login(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object params = info[0].As<Napi::Object>();
  auto* worker = new LoginWorker(env, GetString(params, "host"), GetInt(params, "port"), GetString(params, "username"), GetString(params, "password"));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

// logout(sessionId) — best effort; the session is gone either way.
Napi::Value Logout(const Napi::CallbackInfo& info) {
  const int sessionId = info[0].IsNumber() ? info[0].As<Napi::Number>().Int32Value() : 0;
  std::lock_guard<std::mutex> lock(g_sessionMutex);
  auto it = g_sessions.find(sessionId);
  if (it != g_sessions.end()) {
    CLIENT_Logout(it->second);
    g_sessions.erase(it);
  }
  return info.Env().Undefined();
}

// restoreDefault(sessionId) → { ok | missing | errorCode }
Napi::Value RestoreDefault(const Napi::CallbackInfo& info) {
  const int sessionId = info[0].IsNumber() ? info[0].As<Napi::Number>().Int32Value() : 0;
  auto* worker = new RestoreDefaultWorker(info.Env(), sessionId);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

// resetSystem(sessionId) → { ok | missing | errorCode }
Napi::Value ResetSystem(const Napi::CallbackInfo& info) {
  const int sessionId = info[0].IsNumber() ? info[0].As<Napi::Number>().Int32Value() : 0;
  auto* worker = new ResetSystemWorker(info.Env(), sessionId);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

}  // namespace

Napi::Value ModifyDevice(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object params = info[0].As<Napi::Object>();
  ModifyRequest request;
  request.mac = GetString(params, "mac");
  request.ip = GetString(params, "ip");
  request.subnetMask = GetString(params, "subnetMask");
  request.gateway = GetString(params, "gateway");
  request.port = GetInt(params, "port");
  request.httpPort = GetInt(params, "httpPort");
  Napi::Value setStatic = params.Get("setStatic");
  request.setStatic = setStatic.IsBoolean() && setStatic.As<Napi::Boolean>().Value();
  Napi::Value setDhcp = params.Get("setDhcp");
  request.setDhcp = setDhcp.IsBoolean() && setDhcp.As<Napi::Boolean>().Value();
  request.username = GetString(params, "username");
  request.password = GetString(params, "password");
  request.localIp = GetString(params, "localIp");
  auto* worker = new ModifyDeviceWorker(env, std::move(request));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

// searchByIps(ips: string[], localIp: string, waitMs: number) → the devices
// that answered, in the same shape as the broadcast search's.
Napi::Value SearchByIps(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array list = info[0].As<Napi::Array>();
  std::vector<std::string> ips;
  for (uint32_t i = 0; i < list.Length(); ++i) {
    Napi::Value v = list[i];
    if (v.IsString()) ips.push_back(v.As<Napi::String>().Utf8Value());
  }
  std::string localIp = info[1].IsString() ? info[1].As<Napi::String>().Utf8Value() : std::string();
  int waitMs = info[2].IsNumber() ? info[2].As<Napi::Number>().Int32Value() : 3000;
  auto* worker = new SearchByIpsWorker(env, std::move(ips), std::move(localIp), waitMs);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value StartDiscovery(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Function onDevice = info[0].As<Napi::Function>();
  std::lock_guard<std::mutex> lock(g_discoveryMutex);
  if (g_discoveryActive) {
    CLIENT_StopSearchDevices(g_discoveryHandle);
    g_discoveryActive = false;
    g_discoveryTsfn.Release();
  }
  g_discoveryTsfn = Napi::ThreadSafeFunction::New(env, onDevice, "dahua-discovery-callback", kDiscoveryQueueSize, 1);
  g_discoveryActive = true;
  {
    std::lock_guard<std::mutex> seenLock(g_lastSeenMutex);
    g_lastSeen.clear();
  }
  g_discoveryHandle = CLIENT_StartSearchDevices(OnDeviceDiscovered, nullptr);
  return env.Undefined();
}

Napi::Value StopDiscovery(const Napi::CallbackInfo& info) {
  std::lock_guard<std::mutex> lock(g_discoveryMutex);
  if (g_discoveryActive) {
    CLIENT_StopSearchDevices(g_discoveryHandle);
    g_discoveryActive = false;
    g_discoveryTsfn.Release();
  }
  return info.Env().Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  CLIENT_Init(nullptr, 0);
  exports.Set("startDiscovery", Napi::Function::New(env, StartDiscovery));
  exports.Set("stopDiscovery", Napi::Function::New(env, StopDiscovery));
  exports.Set("modifyDevice", Napi::Function::New(env, ModifyDevice));
  exports.Set("searchByIps", Napi::Function::New(env, SearchByIps));
  exports.Set("login", Napi::Function::New(env, Login));
  exports.Set("logout", Napi::Function::New(env, Logout));
  exports.Set("restoreDefault", Napi::Function::New(env, RestoreDefault));
  exports.Set("resetSystem", Napi::Function::New(env, ResetSystem));
  return exports;
}

NODE_API_MODULE(dahua_native, Init)
