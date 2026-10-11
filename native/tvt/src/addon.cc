// N-API bridge over TVT's DVR_NET_SDK — discovery, the search-level "set
// device IP" command, and a login session for the NVMS-9000 API passthrough
// (used to change ports). Ported from
// SSM-VMS's own native/tvt/src/addon.cc, stripped of everything this tool
// doesn't need (login, live view, playback). NET_SDK_DiscoverDevice is a
// single blocking call with its own internal wait, unlike Uniview's/
// Dahua's callback-based discovery — runs on an AsyncWorker so a blocking
// SDK call doesn't freeze Electron's main thread, no manual start/stop
// needed.
//
// TVT's own multi-vendor SearchTypeMask-based discovery
// (NET_SDK_DiscoverDeviceStart, which SSM-VMS's own research found could
// in theory cover Dahua/Hikvision/Uniview through one call too) is NOT
// used here — confirmed in SSM-VMS via an actual compile failure that
// those functions are internal-only symbols, not exported in the
// redistributable SDK. Don't re-attempt that path unless TVT ships a
// different SDK package.
#include <napi.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "DVR_NET_SDK.h"

namespace {

constexpr int kDiscoveryMaxRecords = 256;
constexpr int kDiscoveryWaitSeconds = 3;

std::string SafeFieldString(const char* field, size_t fieldSize) {
  return std::string(field, strnlen(field, fieldSize));
}

std::string FormatMac(const unsigned char* mac) {
  char buf[24];
  snprintf(buf, sizeof(buf), "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

class DiscoverDevicesWorker : public Napi::AsyncWorker {
 public:
  explicit DiscoverDevicesWorker(Napi::Env env) : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)) {}

  void Execute() override {
    devices_.resize(kDiscoveryMaxRecords);
    const int count = NET_SDK_DiscoverDevice(devices_.data(), kDiscoveryMaxRecords, kDiscoveryWaitSeconds);
    devices_.resize(count > 0 ? static_cast<size_t>(count) : 0);
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Array result = Napi::Array::New(env);
    for (size_t i = 0; i < devices_.size(); ++i) {
      const auto& d = devices_[i];
      Napi::Object obj = Napi::Object::New(env);
      obj.Set("host", SafeFieldString(d.strIP, sizeof(d.strIP)));
      obj.Set("port", Napi::Number::New(env, d.netPort));
      obj.Set("httpPort", Napi::Number::New(env, d.httpPort));
      obj.Set("mac", FormatMac(d.byMac));
      obj.Set("subnetMask", SafeFieldString(d.strNetMask, sizeof(d.strNetMask)));
      obj.Set("gateway", SafeFieldString(d.strGateWay, sizeof(d.strGateWay)));
      obj.Set("model", SafeFieldString(d.productType, sizeof(d.productType)));
      obj.Set("name", SafeFieldString(d.devName, sizeof(d.devName)));
      // NET_SDK_DEVICE_TYPE - confirmed directly from DVR_NET_SDK.h's own
      // enum (DVR=0, DVS=1, IPCAMERA=2, NVR=3, SUPERDVR=4, DECODER=5,
      // N_DVR=6), mapped to a coarse DeviceCategory on the TS side.
      obj.Set("deviceType", Napi::Number::New(env, static_cast<int>(d.deviceType)));
      // ucIPMode: 0 static, 1 DHCP.
      obj.Set("dhcp", Napi::Boolean::New(env, d.ucIPMode == 1));
      result[static_cast<uint32_t>(i)] = obj;
    }
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  std::vector<NET_SDK_DEVICE_DISCOVERY_INFO> devices_;
};

struct SetIpRequest {
  std::string mac;
  std::string password;
  std::string ip;
  std::string subnetMask;
  std::string gateway;
  std::string dns1;
  std::string dns2;
  // -1: NET_SDK_SetDeviceIP (the address only); 0/1:
  // NET_SDK_ModifyDeviceNetInfo with that IP mode (static/DHCP).
  int ipMode = -1;
};

std::mutex g_setIpMutex;

// NET_SDK_SetDeviceIP matches the device by MAC — no login, which is what
// lets it reach a device outside the PC's subnet. The MAC string format
// is taken from the SDK's own demo ("58:5B:69:18:54:FB", colon-separated
// uppercase); the TS side passes it in that form. Switching between static
// and DHCP needs the IP mode, which only NET_SDK_ModifyDeviceNetInfo carries:
// the same MAC-matched, no-login change, which DVR_NET_SDK.h marks deprecated
// but the SDK's own modify_network demo still uses (with the device's current
// password in szPassword). Resolves { ok } or { ok: false, errorCode } from
// NET_SDK_GetLastError.
class SetDeviceIpWorker : public Napi::AsyncWorker {
 public:
  SetDeviceIpWorker(Napi::Env env, SetIpRequest request)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), request_(std::move(request)) {}

  void Execute() override {
    std::lock_guard<std::mutex> lock(g_setIpMutex);
    if (request_.ipMode < 0) {
      ok_ = NET_SDK_SetDeviceIP(request_.mac.c_str(), request_.password.c_str(), request_.ip.c_str(),
                                request_.subnetMask.c_str(), request_.gateway.c_str(), request_.dns1.c_str(),
                                request_.dns2.c_str()) == TRUE;
    } else {
      NET_SDK_DEVICE_IP_INFO info;
      std::memset(&info, 0, sizeof(info));
      strncpy_s(info.szMac, sizeof(info.szMac), request_.mac.c_str(), _TRUNCATE);
      strncpy_s(info.szIpAddr, sizeof(info.szIpAddr), request_.ip.c_str(), _TRUNCATE);
      strncpy_s(info.szMark, sizeof(info.szMark), request_.subnetMask.c_str(), _TRUNCATE);
      strncpy_s(info.szGateway, sizeof(info.szGateway), request_.gateway.c_str(), _TRUNCATE);
      strncpy_s(info.szPassword, sizeof(info.szPassword), request_.password.c_str(), _TRUNCATE);
      strncpy_s(info.szDdns1, sizeof(info.szDdns1), request_.dns1.c_str(), _TRUNCATE);
      strncpy_s(info.szDdns2, sizeof(info.szDdns2), request_.dns2.c_str(), _TRUNCATE);
      info.ucIPMode = static_cast<char>(request_.ipMode);
      ok_ = NET_SDK_ModifyDeviceNetInfo(&info) == TRUE;
      SecureZeroMemory(&info, sizeof(info));
    }
    if (!ok_) errorCode_ = NET_SDK_GetLastError();
    SecureZeroMemory(&request_.password[0], request_.password.size());
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (!ok_) result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  SetIpRequest request_;
  bool ok_ = false;
  DWORD errorCode_ = 0;
};

std::string GetString(const Napi::Object& obj, const char* key) {
  Napi::Value v = obj.Get(key);
  return v.IsString() ? v.As<Napi::String>().Utf8Value() : std::string();
}

// Logged-in sessions by a small id handed to JS, rather than exposing the
// SDK's LONG user ID directly.
std::mutex g_sessionMutex;
std::map<int, LONG> g_sessions;
int g_nextSessionId = 1;

LONG SessionUserId(int sessionId) {
  std::lock_guard<std::mutex> lock(g_sessionMutex);
  auto it = g_sessions.find(sessionId);
  return it == g_sessions.end() ? -1 : it->second;
}

// Same NET_SDK_Login call SSM-VMS uses against real TVT hardware (a
// negative user ID means failure). Resolves { ok, sessionId } or
// { ok: false, errorCode }.
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
    NET_SDK_DEVICEINFO deviceInfo = {};
    const LONG userId = NET_SDK_Login(&host_[0], static_cast<WORD>(port_), &username_[0], &password_[0], &deviceInfo);
    SecureZeroMemory(&password_[0], password_.size());
    if (userId < 0) {
      errorCode_ = NET_SDK_GetLastError();
      return;
    }
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    sessionId_ = g_nextSessionId++;
    g_sessions[sessionId_] = userId;
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, sessionId_ != 0));
    if (sessionId_ != 0) result.Set("sessionId", Napi::Number::New(env, sessionId_));
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
  int sessionId_ = 0;
  DWORD errorCode_ = 0;
};

// One NVMS-9000 API request through NET_SDK_TransparentConfig — the url is
// the API command name (e.g. "queryNetPortCfg"), the body its XML request.
// Resolves { ok, xml } or { ok: false, errorCode }.
class TransparentWorker : public Napi::AsyncWorker {
 public:
  TransparentWorker(Napi::Env env, int sessionId, std::string url, std::string xml)
      : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        sessionId_(sessionId),
        url_(std::move(url)),
        xml_(std::move(xml)) {}

  void Execute() override {
    const LONG userId = SessionUserId(sessionId_);
    if (userId < 0) {
      noSession_ = true;
      return;
    }
    std::vector<char> url(url_.begin(), url_.end());
    url.push_back('\0');
    std::vector<char> xml(xml_.begin(), xml_.end());
    xml.push_back('\0');
    std::vector<char> out(kTransparentBufferSize, 0);
    DWORD bytesReturned = 0;
    ok_ = NET_SDK_TransparentConfig(userId, xml.data(), url.data(), out.data(), static_cast<DWORD>(out.size() - 1),
                                    &bytesReturned) == TRUE;
    if (ok_) response_.assign(out.data(), strnlen(out.data(), out.size()));
    else errorCode_ = NET_SDK_GetLastError();
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (ok_) result.Set("xml", Napi::String::New(env, response_));
    else if (noSession_) result.Set("noSession", Napi::Boolean::New(env, true));
    else result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  static constexpr size_t kTransparentBufferSize = 256 * 1024;
  Napi::Promise::Deferred deferred_;
  int sessionId_;
  std::string url_;
  std::string xml_;
  bool ok_ = false;
  bool noSession_ = false;
  std::string response_;
  DWORD errorCode_ = 0;
};

class LogoutWorker : public Napi::AsyncWorker {
 public:
  LogoutWorker(Napi::Env env, int sessionId)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), sessionId_(sessionId) {}

  void Execute() override {
    LONG userId = -1;
    {
      std::lock_guard<std::mutex> lock(g_sessionMutex);
      auto it = g_sessions.find(sessionId_);
      if (it == g_sessions.end()) return;
      userId = it->second;
      g_sessions.erase(it);
    }
    NET_SDK_Logout(userId);
  }

  void OnOK() override { deferred_.Resolve(Env().Undefined()); }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  int sessionId_;
};

}  // namespace

Napi::Value Login(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object params = info[0].As<Napi::Object>();
  Napi::Value portValue = params.Get("port");
  const int port = portValue.IsNumber() ? portValue.As<Napi::Number>().Int32Value() : 0;
  auto* worker = new LoginWorker(env, GetString(params, "host"), port, GetString(params, "username"), GetString(params, "password"));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value Transparent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* worker = new TransparentWorker(env, info[0].As<Napi::Number>().Int32Value(), info[1].As<Napi::String>().Utf8Value(),
                                       info[2].As<Napi::String>().Utf8Value());
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

// NET_SDK_RebootDVR on a logged-in session (DVR_NET_SDK.h: NVR/DVR only, not
// IPCs). Resolves { ok } or { ok: false, errorCode }.
class RebootWorker : public Napi::AsyncWorker {
 public:
  RebootWorker(Napi::Env env, int sessionId) : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), sessionId_(sessionId) {}

  void Execute() override {
    const LONG userId = SessionUserId(sessionId_);
    if (userId < 0) return;
    ok_ = NET_SDK_RebootDVR(userId) == TRUE;
    if (!ok_) errorCode_ = NET_SDK_GetLastError();
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (!ok_) result.Set("errorCode", Napi::Number::New(env, static_cast<double>(errorCode_)));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  int sessionId_;
  bool ok_ = false;
  DWORD errorCode_ = 0;
};

Napi::Value Reboot(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* worker = new RebootWorker(env, info[0].As<Napi::Number>().Int32Value());
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value Logout(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* worker = new LogoutWorker(env, info[0].As<Napi::Number>().Int32Value());
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value SetDeviceIp(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object params = info[0].As<Napi::Object>();
  SetIpRequest request;
  request.mac = GetString(params, "mac");
  request.password = GetString(params, "password");
  request.ip = GetString(params, "ip");
  request.subnetMask = GetString(params, "subnetMask");
  request.gateway = GetString(params, "gateway");
  request.dns1 = GetString(params, "dns1");
  request.dns2 = GetString(params, "dns2");
  Napi::Value ipMode = params.Get("ipMode");
  if (ipMode.IsNumber()) request.ipMode = ipMode.As<Napi::Number>().Int32Value();
  auto* worker = new SetDeviceIpWorker(env, std::move(request));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value DiscoverDevices(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* worker = new DiscoverDevicesWorker(env);
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  NET_SDK_Init();
  exports.Set("discoverDevices", Napi::Function::New(env, DiscoverDevices));
  exports.Set("setDeviceIp", Napi::Function::New(env, SetDeviceIp));
  exports.Set("login", Napi::Function::New(env, Login));
  exports.Set("transparent", Napi::Function::New(env, Transparent));
  exports.Set("logout", Napi::Function::New(env, Logout));
  exports.Set("reboot", Napi::Function::New(env, Reboot));
  return exports;
}

NODE_API_MODULE(tvt_native, Init)
