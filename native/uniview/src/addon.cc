// N-API bridge over Uniview's NetDEVSDK — discovery plus the search-level
// "modify device address" command. Ported from
// SSM-VMS's own native/uniview/src/addon.cc (same mutex-guarded safety
// pattern, same bounded ThreadSafeFunction queue size), stripped of
// everything this tool doesn't need (login, live view, playback, backup).
#include <napi.h>
#include <windows.h>
#include <cstring>
#include <mutex>
#include <string>

#include "NetDEVSDK.h"

namespace {

// Global rather than per-call since NETDEV_SetDiscoveryCallBack itself is a
// single, SDK-wide registration, not a per-invocation handle — only one
// scan is ever expected to run at a time.
Napi::ThreadSafeFunction g_discoveryTsfn;
// Guards both g_discoveryTsfn and g_discoveryActive together — the SDK's
// discovery broadcast can keep delivering late responses after the JS side
// has already finished its collection window and called StopDiscovery(),
// and OnDeviceDiscovered fires on an SDK-internal thread, not the N-API
// call thread. Without this, a late callback could call NonBlockingCall on
// an already-Release()'d ThreadSafeFunction — undefined behavior, a
// confirmed real crash risk in SSM-VMS's own copy of this exact code.
std::mutex g_discoveryMutex;
bool g_discoveryActive = false;

// Bounded (not 0/unbounded) — SSM-VMS's own real 51GB memory leak was
// caused by exactly an unbounded queue elsewhere in that project. A real
// LAN scan turning up more than a few dozen devices in one window is an
// unrealistic edge case, so 64 is generous headroom, not a practical limit.
constexpr size_t kDiscoveryQueueSize = 64;

std::string SafeFieldString(const char* field, size_t fieldSize) {
  return std::string(field, strnlen(field, fieldSize));
}

void STDCALL OnDeviceDiscovered(LPNETDEV_DISCOVERY_DEVINFO_S pstDevInfo, LPVOID /*lpUserData*/) {
  if (!pstDevInfo) return;

  std::lock_guard<std::mutex> lock(g_discoveryMutex);
  if (!g_discoveryActive) return;
  auto* info = new NETDEV_DISCOVERY_DEVINFO_S(*pstDevInfo);
  auto status = g_discoveryTsfn.NonBlockingCall(
      info, [](Napi::Env env, Napi::Function jsCallback, NETDEV_DISCOVERY_DEVINFO_S* d) {
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("host", SafeFieldString(d->szDevAddr, sizeof(d->szDevAddr)));
        obj.Set("port", Napi::Number::New(env, d->dwDevPort));
        obj.Set("model", SafeFieldString(d->szDevModule, sizeof(d->szDevModule)));
        obj.Set("serialNumber", SafeFieldString(d->szDevSerailNum, sizeof(d->szDevSerailNum)));
        obj.Set("mac", SafeFieldString(d->szDevMac, sizeof(d->szDevMac)));
        obj.Set("name", SafeFieldString(d->szDevName, sizeof(d->szDevName)));
        obj.Set("manufacturer", SafeFieldString(d->szManuFacturer, sizeof(d->szManuFacturer)));
        // NETDEV_DEVICE_TYPE_E - confirmed directly from NetDEVSDK.h's own
        // enum (NETDEV_DTYPE_IPC*=1-4, NETDEV_DTYPE_NVR*=101-103, etc.),
        // mapped to a coarse DeviceCategory on the TS side.
        obj.Set("deviceType", Napi::Number::New(env, static_cast<int>(d->enDevType)));
        jsCallback.Call({obj});
        delete d;
      });
  if (status != napi_ok) delete info;
}

struct ModifyAddrRequest {
  std::string username;
  std::string password;
  std::string ip;
  std::string gateway;
  std::string subnetMask;
  std::string serialNumber;
  std::string mac;
};

std::mutex g_modifyMutex;

void CopyField(char* dest, size_t destSize, const std::string& value) {
  strncpy_s(dest, destSize, value.c_str(), _TRUNCATE);
}

// NETDEV_ModifyDeviceAddr takes no login handle — the device is identified
// by the serial number + MAC its own discovery response reported (passed
// back exactly as NETDEV_Discovery gave them, e.g. "48ea63655bbc"), same
// as the SDK's own Java demo fills it from its discovery table. The SDK
// demo also requires gateway and mask to be non-empty. Resolves { ok } or
// { ok: false, errorCode } from NETDEV_GetLastError.
class ModifyAddrWorker : public Napi::AsyncWorker {
 public:
  ModifyAddrWorker(Napi::Env env, ModifyAddrRequest request)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), request_(std::move(request)) {}

  void Execute() override {
    NETDEV_DEV_ADDR_INFO_S addr;
    std::memset(&addr, 0, sizeof(addr));
    CopyField(addr.szUserName, sizeof(addr.szUserName), request_.username);
    CopyField(addr.szPassword, sizeof(addr.szPassword), request_.password);
    CopyField(addr.szIPv4Address, sizeof(addr.szIPv4Address), request_.ip);
    CopyField(addr.szIPv4GateWay, sizeof(addr.szIPv4GateWay), request_.gateway);
    CopyField(addr.szIPv4SubnetMask, sizeof(addr.szIPv4SubnetMask), request_.subnetMask);
    CopyField(addr.szDevSerailNum, sizeof(addr.szDevSerailNum), request_.serialNumber);
    CopyField(addr.szDevMac, sizeof(addr.szDevMac), request_.mac);
    {
      std::lock_guard<std::mutex> lock(g_modifyMutex);
      ok_ = NETDEV_ModifyDeviceAddr(&addr) == TRUE;
      if (!ok_) errorCode_ = NETDEV_GetLastError();
    }
    SecureZeroMemory(&addr, sizeof(addr));
    SecureZeroMemory(&request_.password[0], request_.password.size());
  }

  void OnOK() override {
    Napi::Env env = Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, ok_));
    if (!ok_) result.Set("errorCode", Napi::Number::New(env, errorCode_));
    deferred_.Resolve(result);
  }

  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }

  Napi::Promise GetPromise() { return deferred_.Promise(); }

 private:
  Napi::Promise::Deferred deferred_;
  ModifyAddrRequest request_;
  bool ok_ = false;
  INT32 errorCode_ = 0;
};

std::string GetString(const Napi::Object& obj, const char* key) {
  Napi::Value v = obj.Get(key);
  return v.IsString() ? v.As<Napi::String>().Utf8Value() : std::string();
}

}  // namespace

Napi::Value ModifyDevice(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object params = info[0].As<Napi::Object>();
  ModifyAddrRequest request;
  request.username = GetString(params, "username");
  request.password = GetString(params, "password");
  request.ip = GetString(params, "ip");
  request.gateway = GetString(params, "gateway");
  request.subnetMask = GetString(params, "subnetMask");
  request.serialNumber = GetString(params, "serialNumber");
  request.mac = GetString(params, "mac");
  auto* worker = new ModifyAddrWorker(env, std::move(request));
  Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value StartDiscovery(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Function onDevice = info[0].As<Napi::Function>();
  {
    std::lock_guard<std::mutex> lock(g_discoveryMutex);
    if (g_discoveryActive) {
      g_discoveryActive = false;
      g_discoveryTsfn.Release();
    }
    g_discoveryTsfn = Napi::ThreadSafeFunction::New(env, onDevice, "uniview-discovery-callback", kDiscoveryQueueSize, 1);
    g_discoveryActive = true;
  }
  NETDEV_SetDiscoveryCallBack(OnDeviceDiscovered, nullptr);
  // The SDK's own doc comment: "0.0.0.0" for both begin and end IP
  // triggers a full local-network broadcast rather than a specific range.
  char beginIp[] = "0.0.0.0";
  char endIp[] = "0.0.0.0";
  NETDEV_Discovery(beginIp, endIp);
  return env.Undefined();
}

Napi::Value StopDiscovery(const Napi::CallbackInfo& info) {
  std::lock_guard<std::mutex> lock(g_discoveryMutex);
  if (g_discoveryActive) {
    g_discoveryActive = false;
    g_discoveryTsfn.Release();
  }
  return info.Env().Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  NETDEV_Init();
  exports.Set("startDiscovery", Napi::Function::New(env, StartDiscovery));
  exports.Set("stopDiscovery", Napi::Function::New(env, StopDiscovery));
  exports.Set("modifyDevice", Napi::Function::New(env, ModifyDevice));
  return exports;
}

NODE_API_MODULE(uniview_native, Init)
