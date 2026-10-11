import { createSocket, type RemoteInfo } from 'dgram';
import { randomUUID } from 'crypto';
import type { DiscoveredDevice } from '../../shared/types';
import { asPort, localIPv4Interfaces } from './networkInterfaces';

// SADP (Search Active Devices Protocol) - Hikvision's own proprietary
// discovery mechanism (the same one their SADP tool/iVMS-4200 use). Pure
// UDP/XML, no SDK needed. Ported from SSM-VMS's own services/sadp.ts —
// see that file's memory notes for the real-hardware field-mapping
// findings once this has been tested against genuine Hikvision hardware.
const MULTICAST_ADDRESS = '239.255.255.250';
const MULTICAST_PORT = 37020;
const SCAN_DURATION_MS = 3000;

function buildProbe(uuid: string): Buffer {
  return Buffer.from(
    `<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>${uuid}</Uuid><Types>inquiry</Types></Probe>`,
  );
}

function extractTag(xml: string, tag: string): string {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return match?.[1]?.trim() ?? '';
}

function modelFromSerial(serial: string): string | undefined {
  const match = serial.match(/^(.+?)-?20\d{6}/);
  const model = match?.[1]?.trim();
  return model && model.length > 0 ? model : undefined;
}

export function discoverHikvisionDevices(): Promise<DiscoveredDevice[]> {
  return new Promise((resolve) => {
    const found = new Map<string, DiscoveredDevice>();

    const onMessage = (msg: Buffer, rinfo: RemoteInfo): void => {
      const xml = msg.toString('utf-8');
      const deviceSn = extractTag(xml, 'DeviceSN');
      const commandPortStr = extractTag(xml, 'CommandPort');
      if (!deviceSn && !commandPortStr) return;
      if (found.has(rinfo.address)) return;

      // Temporary diagnostic — DeviceType is already used below as a model
      // fallback (real Hikvision SADP responses appear to put the model
      // number there, not a coarse category), so no deviceCategory is set
      // for Hikvision devices yet. Logging the full raw XML so a future
      // pass can check for any other tag that might carry a genuine
      // IPC/DVR/NVR classification before guessing at one.
      // eslint-disable-next-line no-console
      console.log(`[hik-sadp-devicetype-diag] ip=${rinfo.address} raw=${xml}`);

      const deviceType = extractTag(xml, 'DeviceType');
      const deviceDescription = extractTag(xml, 'DeviceDescription');
      const commandPort = asPort(commandPortStr);
      const httpPortStr = extractTag(xml, 'HttpPort');
      const httpPort = asPort(httpPortStr);
      const mac = extractTag(xml, 'MAC') || undefined;
      const activated = extractTag(xml, 'Activated').toLowerCase() !== 'false';
      const dhcp = extractTag(xml, 'DHCP').toLowerCase();
      // Which forgotten-admin-password resets the device says it supports
      // (SADP's own flags), for the reset-capable marker in the table. Only
      // meaningful once activated — before that there's no password to reset.
      const resetAbility = extractTag(xml, 'PasswordResetAbility').toLowerCase() === 'true';
      const resetModeSecond = extractTag(xml, 'PasswordResetModeSecond').toLowerCase() === 'true';
      const securityQuestion = extractTag(xml, 'SupportSecurityQuestion').toLowerCase() === 'true';
      // A live reply (CMIP1042-28 camera) carried a numeric type code in
      // DeviceType (140688) and the model in DeviceDescription, so a
      // purely numeric DeviceType isn't used as the model.
      const model = (/^\d+$/.test(deviceType) ? '' : deviceType) || deviceDescription || modelFromSerial(deviceSn);

      found.set(rinfo.address, {
        host: rinfo.address,
        port: commandPort,
        httpPort,
        model,
        manufacturer: 'Hikvision',
        guessedVendor: 'hikvision',
        mac,
        subnetMask: extractTag(xml, 'IPv4SubnetMask') || undefined,
        gateway: extractTag(xml, 'IPv4Gateway') || undefined,
        currentPorts: { http: httpPort, device: commandPort },
        dhcp: dhcp === 'true' ? true : dhcp === 'false' ? false : undefined,
        passwordReset: activated && resetAbility ? { importFile: resetModeSecond, securityQuestion } : undefined,
        discoveryMethod: 'Hikvision SADP',
        // A device that hasn't been activated has no admin password yet, so
        // nothing can log in to change it. Older firmware has no Activated
        // tag (it shipped with a default password).
        ...(activated
          ? { networkEdit: { ports: ['http', 'https', 'rtsp', 'device'], dns: false, username: true, dhcp: true, mayReboot: true, portsMayReboot: true } }
          : {
              editUnavailableReason:
                "This Hikvision device hasn't been activated yet (it has no admin password). Activate it from its web page or Hikvision's SADP tool, then rescan.",
            }),
      });
    };

    const ignoreErrors = (): void => {
      // A bad network interface shouldn't crash the scan - just resolve
      // with whatever (if anything) was already found.
    };
    const interfaces = localIPv4Interfaces();

    // Hikvision's own SADP tool listens on the SADP port itself, joined to
    // the multicast group — a device answers by multicasting its reply
    // there, which is the only way a device outside every local subnet
    // (e.g. still on its factory 192.168.1.64) can be heard at all, since
    // it has no route for a unicast reply. Not yet confirmed against real
    // Hikvision hardware (none on the test network); the per-interface
    // probe sockets below still catch any unicast replies either way. Our
    // own looped-back probes land here too and are dropped by the
    // DeviceSN/CommandPort check above.
    const listener = createSocket({ type: 'udp4', reuseAddr: true });
    listener.on('message', onMessage);
    listener.on('error', ignoreErrors);
    listener.bind(MULTICAST_PORT, () => {
      for (const iface of interfaces) {
        try {
          listener.addMembership(MULTICAST_ADDRESS, iface.address);
        } catch {
          // best-effort per interface
        }
      }
    });

    // One probe socket per local interface — see localIPv4Interfaces for
    // why the multicast interface has to be pinned explicitly.
    const probeSockets = interfaces.map((iface) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      socket.on('message', onMessage);
      socket.on('error', ignoreErrors);
      socket.bind({ port: 0, address: iface.address }, () => {
        try {
          socket.setMulticastInterface(iface.address);
          socket.setMulticastTTL(4);
        } catch {
          // best-effort - some network configurations reject these, the
          // probe can still go out without them
        }
        socket.send(buildProbe(randomUUID()), MULTICAST_PORT, MULTICAST_ADDRESS);
      });
      return socket;
    });

    setTimeout(() => {
      listener.close();
      for (const socket of probeSockets) socket.close();
      resolve(Array.from(found.values()));
    }, SCAN_DURATION_MS);
  });
}
