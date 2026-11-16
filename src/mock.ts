// A pretend Netgear AV Line switch for development and tests: the REST API on HTTPS with a
// self-signed certificate like the real thing, and an optional NSDP responder. It answers the reads
// the module polls, accepts VLAN, port, PoE and save changes, and records every request that is not
// a GET (other than login and logout) so tests can check that nothing changed without an operator.
//
// Response shapes follow the AV Line ConfigAgent API as Bitfocus Companion's netgear-avline module
// and the m4300-site-report project read it; real firmware varies, so the client reads tolerantly.

import dgram from 'node:dgram';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';

type Raw = Record<string, any>;

export interface MockModel {
  model: string;
  /** Total front-panel ports. */
  ports: number;
  /** Ports 1..poe have PoE. */
  poe: number;
  /** The last `sfp` ports are fibre cages. */
  sfp: number;
  /** Copper speed code (7 = 1G, 8 = 10G). */
  speed: number;
  /** PoE budget, mW. */
  budget: number;
}

export const MODELS: Record<string, MockModel> = {
  'M4250-26G4F-PoE+': { model: 'M4250-26G4F-PoE+', ports: 30, poe: 24, sfp: 4, speed: 7, budget: 480_000 },
  'M4250-10G2F-PoE+': { model: 'M4250-10G2F-PoE+', ports: 12, poe: 10, sfp: 2, speed: 7, budget: 125_000 },
  'M4350-24X4V': { model: 'M4350-24X4V', ports: 28, poe: 0, sfp: 4, speed: 8, budget: 0 }
};

export const VLANS: { id: number; name: string }[] = [
  { id: 1, name: 'default' },
  { id: 10, name: 'Mgmt' },
  { id: 20, name: 'Dante Pri' },
  { id: 21, name: 'Dante Sec' },
  { id: 30, name: 'NDI' },
  { id: 40, name: 'sACN' },
  { id: 50, name: 'Control' },
  { id: 60, name: 'LED' }
];

const DEVICES = ['Camera 1', 'Camera 2', 'PTZ 3', 'Stagebox A', 'Stagebox B', 'Mon world', 'Shure RX', 'Node DMX 1', 'Node DMX 2', 'Brompton S8', 'Intercom', 'NDI enc 1'];

export interface MockOptions {
  name?: string;
  model?: keyof typeof MODELS;
  username?: string;
  password?: string;
  /** Use the second test certificate, as if the switch had been replaced. */
  otherCertificate?: boolean;
  /** Answer swcfg_port?portid=ALL (some firmware only answers one port at a time). */
  bulkPortConfig?: boolean;
  mac?: string;
  ip?: string;
  /** Pattern of access VLANs to seed ports with, repeated. */
  seed?: readonly number[];
}

const certDir = new URL('../test/fixtures/', import.meta.url);

interface PortState {
  description: string;
  adminMode: boolean;
  pvid: number;
  up: boolean;
  poe: { enable: boolean; mw: number } | null;
}

export class MockSwitch {
  readonly name: string;
  readonly spec: MockModel;
  readonly mac: string;
  ip: string;
  /** Every request other than a GET, login and logout, in order. */
  readonly changes: { method: string; path: string; body: any }[] = [];
  readonly requests: string[] = [];
  /** VLAN id to its members: port to tagged. */
  readonly members = new Map<number, Map<number, boolean>>();
  readonly portState = new Map<number, PortState>();
  saved = 0;
  password: string;
  private readonly username: string;
  private tokens = new Set<string>();
  private server: https.Server | null = null;
  private udp: dgram.Socket | null = null;
  private tick = 0;
  private readonly opts: MockOptions;

  constructor(opts: MockOptions = {}) {
    this.opts = opts;
    this.name = opts.name ?? 'SW-FOH';
    this.spec = MODELS[opts.model ?? 'M4250-26G4F-PoE+']!;
    this.username = opts.username ?? 'admin';
    this.password = opts.password ?? 'password1';
    this.mac = opts.mac ?? '28:94:01:AA:00:01';
    this.ip = opts.ip ?? '127.0.0.1';
    const seed = opts.seed ?? [20, 20, 21, 21, 30, 30, 40, 40, 50, 60, 10, 1];
    for (const v of VLANS) this.members.set(v.id, new Map());
    for (let i = 1; i <= this.spec.ports; i++) {
      const fibre = i > this.spec.ports - this.spec.sfp;
      const pvid = fibre ? 1 : seed[(i - 1) % seed.length]!;
      const up = fibre ? i === this.spec.ports - this.spec.sfp + 1 : i % 7 !== 0;
      this.portState.set(i, {
        description: fibre ? (up ? 'Uplink core' : '') : up ? DEVICES[(i - 1) % DEVICES.length]! : '',
        adminMode: !(i === 14),
        pvid,
        up: up && i !== 14,
        poe: i <= this.spec.poe ? { enable: i % 9 !== 0, mw: up && i % 9 !== 0 ? 3000 + ((i * 1370) % 9000) : 0 } : null
      });
      this.members.get(pvid)!.set(i, false);
      if (fibre) for (const v of VLANS) if (v.id !== 1) this.members.get(v.id)!.set(i, true); // trunk
    }
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<number> {
    const which = this.opts.otherCertificate ? 'other' : 'mock';
    this.server = https.createServer({ key: readFileSync(new URL(`${which}-key.pem`, certDir)), cert: readFileSync(new URL(`${which}-cert.pem`, certDir)) }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let body: any;
        try {
          body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined;
        } catch {
          body = undefined;
        }
        const [status, json] = this.handle(req.method ?? 'GET', req.url ?? '/', String(req.headers.authorization ?? ''), body);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(json));
      });
    });
    await new Promise<void>((r) => this.server!.listen(port, host, r));
    return (this.server.address() as AddressInfo).port;
  }

  /** Answers NSDP read requests on a UDP port (the real port is 63322). */
  async listenNsdp(port = 0, host = '127.0.0.1'): Promise<number> {
    this.udp = dgram.createSocket('udp4');
    this.udp.on('message', (msg, rinfo) => {
      if (msg.length < 32 || msg[1] !== 1 || msg.toString('ascii', 24, 28) !== 'NSDP') return;
      const head = Buffer.from(msg.subarray(0, 32));
      head[1] = 2;
      const tlv = (t: number, v: Buffer) => {
        const b = Buffer.alloc(4);
        b.writeUInt16BE(t, 0);
        b.writeUInt16BE(v.length, 2);
        return Buffer.concat([b, v]);
      };
      const out = Buffer.concat([
        head,
        tlv(1, Buffer.from(this.spec.model)),
        tlv(3, Buffer.from(this.name)),
        tlv(4, Buffer.from(this.mac.split(':').map((h) => parseInt(h, 16)))),
        tlv(6, Buffer.from(this.ip.split('.').map(Number))),
        tlv(13, Buffer.from('13.0.4.26')),
        Buffer.from([0xff, 0xff, 0, 0])
      ]);
      this.udp!.send(out, rinfo.port, rinfo.address);
    });
    await new Promise<void>((r) => this.udp!.bind(port, host, r));
    return this.udp.address().port;
  }

  async close(): Promise<void> {
    this.udp?.close();
    this.udp = null;
    const s = this.server;
    this.server = null;
    if (!s) return;
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }

  private ok(data: Raw): [number, Raw] {
    return [200, { resp: { status: 'success', respCode: 0, respMsg: 'Operation success' }, ...data }];
  }
  private fail(msg: string, status = 200): [number, Raw] {
    return [status, { resp: { status: 'failure', respCode: 1, respMsg: msg } }];
  }

  private handle(method: string, url: string, auth: string, body: any): [number, Raw] {
    const u = new URL(url, 'https://x');
    const p = u.pathname.replace(/^\/api\/v1\//, '');
    this.requests.push(`${method} ${p}${u.search}`);
    if (!u.pathname.startsWith('/api/v1/')) return [404, { error: 'not found' }];
    if (p === 'login' && method === 'POST') {
      const l = body?.login;
      if (l?.username !== this.username || l?.password !== this.password) return this.fail('Invalid username or password', 401);
      const token = `tok-${Math.random().toString(36).slice(2)}`;
      this.tokens.add(token);
      return this.ok({ login: { token, expires: 3600 } });
    }
    const token = auth.replace(/^Bearer /, '');
    if (!this.tokens.has(token)) return this.fail('Invalid token or token expired', 401);
    if (p === 'logout') {
      this.tokens.delete(token);
      return this.ok({});
    }
    if (method !== 'GET') this.changes.push({ method, path: `${p}${u.search}`, body });
    const portid = u.searchParams.get('portid');
    const ports = [...this.portState.keys()];
    const pick = (fn: (i: number) => Raw) => (portid === 'ALL' || portid === null ? ports.map(fn) : this.portState.has(Number(portid)) ? fn(Number(portid)) : null);
    switch (`${method} ${p}`) {
      case 'GET device_info': {
        return this.ok({
          deviceInfo: {
            name: this.name,
            model: this.spec.model,
            serialNumber: '6LT1235F0001' + this.name.length,
            macAddr: this.mac,
            swVer: '13.0.4.26',
            upTime: '12 days, 04:31:07',
            numOfPorts: this.spec.ports,
            numOfActivePorts: [...this.portState.values()].filter((s) => s.up).length,
            cpuUsage: `${7 + (this.tick % 5)}%`,
            memoryUsage: '38%',
            fanState: [{ fanNum: 1, state: 'Operational' }],
            poeState: this.spec.poe > 0,
            adminPoePower: this.spec.budget,
            temperatureSensors: [{ sensorNum: 1, sensorDesc: 'MAC', sensorTemp: 46, sensorState: 1 }]
          }
        });
      }
      case 'GET sw_portstats': {
        this.tick++;
        const r = pick((i) => {
          const s = this.portState.get(i)!;
          const fibre = i > this.spec.ports - this.spec.sfp;
          const vlans = [...this.members].filter(([, m]) => m.has(i)).map(([v]) => v);
          const load = s.up ? ((i * 37 + this.tick * 13) % 90) + (s.pvid === 30 ? 300 : 5) : 0;
          return { portId: i, status: s.up ? 0 : 1, speed: s.up ? (fibre ? 8 : this.spec.speed) : 1, vlans, rxMbps: String(load), txMbps: String(Math.round(load * 0.6)), trafficRx: 0, trafficTx: 0 };
        });
        return r ? this.ok({ switchStatsPort: r }) : this.fail('Invalid port');
      }
      case 'GET swcfg_port': {
        if (portid === 'ALL' && !this.opts.bulkPortConfig) return this.fail('Failed to parse request params');
        const r = pick((i) => {
          const s = this.portState.get(i)!;
          return { ID: i, description: s.description, adminMode: s.adminMode, isPoE: !!s.poe, portVlanId: s.pvid, portType: 0, txRate: 0, defVlanPrio: 0 };
        });
        return r ? this.ok({ switchPortConfig: r }) : this.fail('Invalid port');
      }
      case 'POST swcfg_port': {
        const s = this.portState.get(Number(portid));
        const c = body?.switchPortConfig;
        if (!s || !c || typeof c !== 'object') return this.fail('system_config param error');
        if (c.portType === undefined) return this.fail('system_config param error'); // wants the whole record back
        if (typeof c.adminMode === 'boolean') {
          s.adminMode = c.adminMode;
          if (!c.adminMode) s.up = false;
          else s.up = s.description !== '';
        }
        if (Number.isInteger(c.portVlanId)) {
          if (!this.members.has(c.portVlanId)) return this.fail('VLAN does not exist');
          s.pvid = c.portVlanId;
        }
        if (typeof c.description === 'string') s.description = c.description.slice(0, 64);
        return this.ok({});
      }
      case 'GET swcfg_poe': {
        const list = (portid === 'ALL' ? ports : [Number(portid)]).filter((i) => this.portState.get(i)?.poe);
        if (!list.length) return this.fail('Invalid port');
        const r = list.map((i) => {
          const s = this.portState.get(i)!;
          return { portid: i, enable: s.poe!.enable, status: !s.poe!.enable ? 0 : s.up ? 2 : 1, currentPower: s.poe!.enable && s.up ? s.poe!.mw : 0, powerLimitMode: 1, classification: 4, powerLimit: 30000 };
        });
        return this.ok({ poePortConfig: r });
      }
      case 'POST swcfg_poe': {
        const s = this.portState.get(Number(portid));
        const c = body?.poePortConfig;
        if (!s?.poe || !c) return this.fail('Invalid port');
        if (c.powerLimit === undefined || 'portid' in c) return this.fail('Failed to parse request params');
        if (c.reset === true) {
          s.up = false;
          setTimeout(() => (s.up = s.adminMode), 300).unref();
        }
        if (typeof c.enable === 'boolean') s.poe.enable = c.enable;
        return this.ok({});
      }
      case 'GET poe_config':
        if (!this.spec.poe) return this.fail('Not supported');
        return this.ok({
          poe_config: {
            pseMainOperationStatus: 'ON',
            totalPowerConsumedWatts: ([...this.portState.values()].reduce((a, s) => a + (s.poe?.enable && s.up ? s.poe.mw : 0), 0) / 1000).toFixed(1),
            powerManagmentMode: 'Dynamic'
          }
        });
      case 'GET swcfg_vlan': {
        const id = u.searchParams.get('vlanid');
        if (id === 'ALL') return this.fail('Failed to parse request params');
        const v = VLANS.find((x) => x.id === Number(id));
        return v ? this.ok({ switchConfigVlan: { vlanId: v.id, name: v.name } }) : this.fail('VLAN does not exist');
      }
      case 'GET swcfg_vlan_membership': {
        const id = Number(u.searchParams.get('vlanid'));
        const m = this.members.get(id);
        if (!m) return this.fail('VLAN does not exist');
        return this.ok({ vlanMembership: { vlanid: id, portMembers: [...m].map(([port, tagged]) => ({ port, tagged })) } });
      }
      case 'POST swcfg_vlan_membership': {
        const v = body?.vlanMembership;
        const m = this.members.get(Number(v?.vlanid));
        if (!m || !Array.isArray(v.portMembers) || !Array.isArray(v.lagMembers) || !Array.isArray(v.pvidMembers)) return this.fail('Failed to parse request params');
        m.clear();
        for (const x of v.portMembers) if (this.portState.has(Number(x.port))) m.set(Number(x.port), !!x.tagged);
        return this.ok({});
      }
      case 'GET lldp_remote_devices':
        return this.ok({
          lldp_remote_devices: [...this.portState]
            .filter(([i, s]) => s.up && (i % 3 === 1 || i > this.spec.ports - this.spec.sfp))
            .map(([i, s]) => ({ ifIndex: i, chassisId: `28:94:01:BB:00:${String(i).padStart(2, '0')}`, remotePortId: i > this.spec.ports - this.spec.sfp ? '0/49' : 'eth0', remoteSysName: s.description || 'device' }))
        });
      case 'GET fiber_optics':
        return this.ok({ fiber_optics: [{ port: `0/${this.spec.ports - this.spec.sfp + 1}`, temp: '38.2', vendorName: 'NETGEAR', partNumber: 'AXM763' }] });
      case 'POST config_copy':
        if (u.searchParams.get('directive') !== 'rtos') return this.fail('Invalid directive');
        this.saved++;
        return this.ok({});
    }
    return [404, { error: 'not found' }];
  }
}
