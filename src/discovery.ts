// Finding AV Line switches on the network. Two ways, both read-only and both started only by the
// operator (or by opening the Discover page):
//
// - NSDP, the Netgear Switch Discovery Protocol the Netgear tools use: a broadcast read request on
//   UDP 63322 (and 63324 for newer firmware); switches answer with model, name, MAC, IP and firmware.
//   Only switches in the same broadcast domain answer, as with Engage.
// - A scan of the unit's own subnets for hosts answering TLS on 8443, the REST API port. It only
//   connects and reads the certificate: no request and no password is sent to anything it finds.
//
// Whether every AV Line firmware answers NSDP is not confirmed yet, which is why the scan exists.

import dgram from 'node:dgram';
import net from 'node:net';
import os from 'node:os';
import tls from 'node:tls';

export interface Found {
  address: string;
  /** API port that answered TLS, 0 when only NSDP saw it. */
  apiPort: number;
  model: string;
  name: string;
  mac: string;
  firmware: string;
  via: ('nsdp' | 'scan')[];
}

const NSDP_TLVS = [0x0001, 0x0003, 0x0004, 0x0006, 0x000d];

/** A read request for model, name, MAC, IP and firmware, addressed to every device. */
export function nsdpRequest(hostMac: Buffer, seq: number): Buffer {
  const head = Buffer.alloc(32);
  head[0] = 1; // version
  head[1] = 1; // read request
  hostMac.copy(head, 8, 0, 6);
  head.writeUInt16BE(seq & 0xffff, 22);
  head.write('NSDP', 24, 'ascii');
  const tlvs = Buffer.alloc(NSDP_TLVS.length * 4 + 4);
  NSDP_TLVS.forEach((t, i) => tlvs.writeUInt16BE(t, i * 4));
  tlvs.writeUInt16BE(0xffff, NSDP_TLVS.length * 4);
  return Buffer.concat([head, tlvs]);
}

/** Reads a read response. Null when it is not one. */
export function parseNsdp(buf: Buffer): Omit<Found, 'apiPort' | 'via'> | null {
  if (buf.length < 32 || buf[0] !== 1 || buf[1] !== 2 || buf.toString('ascii', 24, 28) !== 'NSDP') return null;
  const out = { address: '', model: '', name: '', mac: '', firmware: '' };
  let i = 32;
  while (i + 4 <= buf.length) {
    const type = buf.readUInt16BE(i);
    const len = buf.readUInt16BE(i + 2);
    if (type === 0xffff || i + 4 + len > buf.length) break;
    const v = buf.subarray(i + 4, i + 4 + len);
    const text = () => v.toString('utf8').replace(/\0+$/, '').trim().slice(0, 64);
    if (type === 0x0001) out.model = text();
    else if (type === 0x0003) out.name = text();
    else if (type === 0x0004 && len === 6) out.mac = [...v].map((b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
    else if (type === 0x0006 && len === 4) out.address = [...v].join('.');
    else if (type === 0x000d) out.firmware = text();
    i += 4 + len;
  }
  return out.address ? out : null;
}

interface Iface {
  address: string;
  netmask: string;
  mac: string;
}

function ipv4Ifaces(): Iface[] {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((i): i is os.NetworkInterfaceInfoIPv4 => !!i && i.family === 'IPv4' && !i.internal)
    .map((i) => ({ address: i.address, netmask: i.netmask, mac: i.mac }));
}

const toInt = (ip: string) => ip.split('.').reduce((a, b) => (a << 8) + Number(b), 0) >>> 0;
const toIp = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

function broadcast(i: Iface): string {
  return toIp((toInt(i.address) | (~toInt(i.netmask) >>> 0)) >>> 0);
}

/** Every host address on the interface's subnet, for subnets of /22 or smaller. */
export function subnetHosts(address: string, netmask: string): string[] {
  const mask = toInt(netmask);
  const size = (~mask >>> 0) + 1;
  if (size > 1024 || size < 4) return [];
  const base = (toInt(address) & mask) >>> 0;
  const out: string[] = [];
  for (let n = 1; n < size - 1; n++) if (base + n !== toInt(address)) out.push(toIp(base + n));
  return out;
}

export interface NsdpOptions {
  /** Where to send; default every interface's broadcast address and 255.255.255.255. */
  targets?: string[];
  /** Request ports. Default 63322 and 63324. */
  ports?: number[];
  /** Local ports to listen on: answers go to 63321 and 63323. 0 = any. */
  localPorts?: number[];
  waitMs?: number;
}

/** Broadcasts an NSDP read request and collects the answers for a moment. */
export async function nsdpSearch(opts: NsdpOptions = {}): Promise<Omit<Found, 'apiPort' | 'via'>[]> {
  const ifaces = ipv4Ifaces();
  const targets = opts.targets ?? [...new Set([...ifaces.map(broadcast), '255.255.255.255'])];
  const ports = opts.ports ?? [63322, 63324];
  const locals = opts.localPorts ?? [63321, 63323];
  const mac = Buffer.from((ifaces[0]?.mac ?? '00:00:00:00:00:00').split(':').map((h) => parseInt(h, 16)));
  const found = new Map<string, Omit<Found, 'apiPort' | 'via'>>();
  const open = (local: number) =>
    new Promise<dgram.Socket | null>((resolve) => {
      const s = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      s.once('error', () => {
        s.close();
        resolve(null);
      });
      s.bind(local, () => {
        s.removeAllListeners('error');
        s.on('error', () => {});
        s.on('message', (msg) => {
          const f = parseNsdp(msg);
          if (f) found.set(f.address, f);
        });
        s.setBroadcast(true);
        resolve(s);
      });
    });
  const sockets: dgram.Socket[] = [];
  for (const [i, port] of ports.entries()) {
    // Older firmware answers on 63321/63323; when another Netgear tool holds that port, any port
    // will do for firmware that answers the sender.
    const s = (await open(locals[i] ?? 0)) ?? (await open(0));
    if (!s) continue;
    sockets.push(s);
    const req = nsdpRequest(mac, 1 + i);
    for (const t of targets) s.send(req, port, t, () => {});
  }
  await new Promise((r) => setTimeout(r, opts.waitMs ?? 2500));
  for (const s of sockets) s.close();
  return [...found.values()];
}

export interface ScanOptions {
  /** Hosts to try; default every host on the unit's subnets (each /22 or smaller). */
  hosts?: string[];
  port?: number;
  timeoutMs?: number;
  concurrency?: number;
}

/** Hosts that complete a TLS handshake on the API port. Sends nothing after the handshake. */
export async function scan(opts: ScanOptions = {}): Promise<{ address: string; port: number; subject: string }[]> {
  const port = opts.port ?? 8443;
  const hosts = opts.hosts ?? [...new Set(ipv4Ifaces().flatMap((i) => subnetHosts(i.address, i.netmask)))];
  const out: { address: string; port: number; subject: string }[] = [];
  let next = 0;
  const probe = (host: string) =>
    new Promise<void>((resolve) => {
      const s = tls.connect({ host, port, rejectUnauthorized: false, servername: net.isIP(host) ? undefined : host });
      const done = () => {
        clearTimeout(timer);
        s.destroy();
        resolve();
      };
      const timer = setTimeout(done, opts.timeoutMs ?? 800);
      s.once('secureConnect', () => {
        const c = s.getPeerCertificate();
        const subject = [c?.subject?.O, c?.subject?.CN].filter((x) => typeof x === 'string').join(' ');
        out.push({ address: host, port, subject: subject.slice(0, 80) });
        done();
      });
      s.once('error', done);
    });
  await Promise.all(
    Array.from({ length: Math.min(opts.concurrency ?? 64, hosts.length) }, async () => {
      while (next < hosts.length) await probe(hosts[next++]!);
    })
  );
  return out.sort((a, b) => toInt(a.address) - toInt(b.address));
}
