// What the module shows about one switch, built from the REST API's records.
//
// The API is the "ConfigAgent" REST API of the AV Line (M4250, M4300, M4350, M4500) on port 8443.
// Field names and shapes vary by model and firmware (camelCase or snake_case wrappers, a port as 9
// or "0/9", an array or a single object), so everything here reads tolerantly and never throws.

export type LinkSpeed = number; // Mb/s, 0 when unknown or down

export interface Port {
  /** Front-panel port number. */
  idx: number;
  /** The port's description on the switch, '' when none. */
  name: string;
  /** Link is up. */
  up: boolean;
  /** Admin mode: false when the port is shut down. */
  enabled: boolean;
  speed: LinkSpeed;
  /** Port VLAN id (PVID): the untagged VLAN of an access port. 0 when not reported. */
  pvid: number;
  /** Every VLAN the port is a member of, as the switch reports it. */
  vlans: number[];
  /** Receive and transmit rates in Mb/s. */
  rx: number;
  tx: number;
  poe: null | {
    enabled: boolean;
    /** Delivering power, searching, fault… */
    status: string;
    watts: number;
    /** PoE class the powered device asked for (0-8), when reported. */
    class?: number;
  };
  /** What LLDP sees on the other end, '' when nothing. */
  neighbor: string;
  neighborPort: string;
  /** A transceiver is reported on this port. */
  sfp: boolean;
  /** What the switch reports about that transceiver, when it reports anything. */
  optic?: { vendor: string; part: string; temp: number | null };
}

export interface Vlan {
  id: number;
  name: string;
}

export interface SwitchInfo {
  name: string;
  model: string;
  serial: string;
  mac: string;
  firmware: string;
  uptime: string;
  cpu: string;
  memory: string;
  /** Hottest sensor, °C. Null when not reported. */
  temp: number | null;
  tempState: string;
  fan: string;
  /** PoE budget and draw in watts, null when the switch has no PoE. */
  poeBudget: number | null;
  poeDraw: number | null;
}

export interface SwitchView {
  info: SwitchInfo | null;
  ports: Port[];
  vlans: Vlan[];
  /** Total throughput, [rx, tx] Mb/s, one sample per fast poll. */
  history: [number, number][];
  /** The same per port, shorter: drawn for the selected port on a tall panel. */
  portHistory?: Record<number, [number, number][]>;
}

export const emptySwitch = (): SwitchView => ({ info: null, ports: [], vlans: [], history: [] });

type Raw = Record<string, any>;

/** Pulls the payload out of a {"resp": …, "<key>": …} envelope: a named key first, else the other one. */
export function unwrap(json: unknown, ...keys: string[]): any {
  if (!json || typeof json !== 'object') return undefined;
  const o = json as Raw;
  for (const k of keys) if (k in o) return o[k];
  for (const [k, v] of Object.entries(o)) if (k !== 'resp') return v;
  return undefined;
}

export function asList(v: unknown): Raw[] {
  if (Array.isArray(v)) return v.filter((x) => x && typeof x === 'object');
  if (v && typeof v === 'object') {
    const o = v as Raw;
    if (Array.isArray(o.rows)) return asList(o.rows);
    return Object.keys(o).length ? [o] : [];
  }
  return [];
}

/** 9, "9", "0/9", "1/0/9" → 9. Null for a LAG ("3/1", "lag 1"), a second stack unit, or anything else. */
export function portNumber(v: unknown): number | null {
  if (typeof v === 'number') return Number.isInteger(v) && v > 0 ? v : null;
  if (typeof v !== 'string') return null;
  const m = /^(?:(?:1\/)?0\/)?(\d+)$/.exec(v.trim());
  const n = m ? Number(m[1]) : 0;
  return n > 0 ? n : null;
}

const SPEEDS: Record<number, number> = { 2: 100, 3: 100, 4: 10, 5: 10, 6: 100, 7: 1000, 8: 10000, 9: 20000, 10: 40000, 11: 25000, 12: 50000, 13: 100000, 15: 5000, 128: 2500 };

export function speedOf(code: unknown): number {
  if (typeof code === 'number') return SPEEDS[code] ?? 0;
  if (typeof code === 'string') {
    const n = Number(code);
    if (Number.isInteger(n) && String(n) === code.trim()) return SPEEDS[n] ?? 0;
    const m = /([\d.]+)\s*([GM])/i.exec(code);
    if (m) return Math.round(Number(m[1]) * (m[2]!.toUpperCase() === 'G' ? 1000 : 1));
  }
  return 0;
}

const POE_STATUS: Record<number, string> = { [-1]: 'Invalid', 0: 'Off', 1: 'Searching', 2: 'Delivering', 3: 'Test', 4: 'Fault', 5: 'Fault', 6: 'Requesting', 7: 'Overload' };
export const poeStatus = (n: unknown): string => (typeof n === 'number' ? POE_STATUS[n] ?? 'Unknown' : typeof n === 'string' && n ? n : 'Unknown');

const TEMP_STATE: Record<number, string> = { 1: 'Normal', 2: 'Warning', 3: 'Critical', 4: 'Shutdown' };

const num = (v: unknown): number => {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? parseFloat(v) : NaN;
  return Number.isFinite(n) ? n : 0;
};
const str = (v: unknown, max = 80): string => (typeof v === 'string' || typeof v === 'number' ? String(v).trim().slice(0, max) : '');
const bool = (v: unknown): boolean => v === true || v === 1 || v === 'true' || v === 'enable' || v === 'Enable' || v === 'up';

export function parseInfo(d: Raw, name: string, poe: Raw | null): SwitchInfo {
  const sensors = asList(d.temperatureSensors);
  let temp: number | null = null;
  let tempState = '';
  for (const s of sensors) {
    const t = num(s.sensorTemp ?? s.temp);
    if (temp === null || t > temp) {
      temp = t;
      tempState = typeof s.sensorState === 'number' ? TEMP_STATE[s.sensorState] ?? '' : str(s.sensorState);
    }
  }
  const fan = Array.isArray(d.fanState) ? d.fanState.map((f: Raw) => str(f.state ?? f.fanState ?? f.status)).filter(Boolean).join(', ') : str(d.fanState);
  const budgetMw = num(d.adminPoePower);
  const draw = poe ? num(poe.totalPowerConsumedWatts ?? poe.totalPowerConsumed) : 0;
  return {
    name: str(d.name) || name,
    model: str(d.model),
    serial: str(d.serialNumber),
    mac: str(d.macAddr ?? d.macAddress).toUpperCase(),
    firmware: str(d.swVer),
    uptime: str(d.upTime),
    cpu: str(d.cpuUsage),
    memory: str(d.memoryUsage),
    temp,
    tempState,
    fan,
    poeBudget: budgetMw ? Math.round(budgetMw / 100) / 10 : null,
    poeDraw: poe ? Math.round(draw * 10) / 10 : null
  };
}

/**
 * Joins the per-port records: statistics (link, speed, rates, VLANs), configuration (description,
 * admin mode, PVID), PoE and LLDP. A port shows if any of them names it.
 */
export function parsePorts(stats: Raw[], configs: Raw[], poe: Raw[], lldp: Raw[], fibre: Raw[]): Port[] {
  const ports = new Map<number, Port>();
  const get = (idx: number): Port => {
    let p = ports.get(idx);
    if (!p) {
      p = { idx, name: '', up: false, enabled: true, speed: 0, pvid: 0, vlans: [], rx: 0, tx: 0, poe: null, neighbor: '', neighborPort: '', sfp: false };
      ports.set(idx, p);
    }
    return p;
  };
  for (const s of stats) {
    const idx = portNumber(s.portId ?? s.portid ?? s.ID ?? s.port);
    if (idx === null || num(s.speed) === 129) continue;
    const p = get(idx);
    p.up = s.status === 0 || s.status === '0' || s.status === 'up' || s.linkStatus === 'up';
    p.speed = p.up ? speedOf(s.speed) : 0;
    p.vlans = Array.isArray(s.vlans) ? [...new Set(s.vlans.map(num).filter((v: number) => v > 0 && v < 4095))].sort((a, b) => a - b) : [];
    p.rx = num(s.rxMbps);
    p.tx = num(s.txMbps);
    if (!p.name) p.name = str(s.myDesc ?? s.description, 64);
    if (s.neighborInfo && typeof s.neighborInfo === 'object') {
      p.neighbor ||= str(s.neighborInfo.name, 64);
      p.neighborPort ||= str(s.neighborInfo.portId, 32);
    }
  }
  for (const c of configs) {
    const idx = portNumber(c.ID ?? c.portid ?? c.portId);
    if (idx === null) continue;
    const p = get(idx);
    if (str(c.description, 64)) p.name = str(c.description, 64);
    if (c.adminMode !== undefined) p.enabled = bool(c.adminMode);
    if (c.portVlanId !== undefined) p.pvid = num(c.portVlanId);
  }
  for (const c of poe) {
    const idx = portNumber(c.portid ?? c.portId ?? c.ID);
    if (idx === null) continue;
    const cls = c.classification ?? c.class ?? c.poeClass;
    get(idx).poe = {
      enabled: bool(c.enable),
      status: poeStatus(c.status),
      watts: Math.round(num(c.currentPower) / 100) / 10,
      ...(cls !== undefined && cls !== null && cls !== '' && Number.isFinite(Number(cls)) ? { class: Number(cls) } : {})
    };
  }
  for (const n of lldp) {
    const idx = portNumber(n.ifIndex ?? n.portNum ?? n.port);
    if (idx === null || !ports.has(idx)) continue;
    const p = get(idx);
    p.neighbor = str(n.remoteSysName ?? n.hostName, 64) || str(n.chassisId, 32) || p.neighbor;
    p.neighborPort = str(n.remotePortDesc, 32) || str(n.remotePortId, 32) || p.neighborPort;
  }
  for (const f of fibre) {
    const idx = portNumber(f.port ?? f.portName);
    if (idx === null || !ports.has(idx)) continue;
    const p = get(idx);
    p.sfp = true;
    const temp = parseFloat(f.temp ?? f.temperature);
    const vendor = str(f.vendorName ?? f.vendor, 32);
    const part = str(f.partNumber ?? f.part ?? f.vendorPn, 32);
    if (vendor || part || Number.isFinite(temp)) p.optic = { vendor, part, temp: Number.isFinite(temp) ? temp : null };
  }
  for (const p of ports.values()) if (!p.pvid && p.vlans.length === 1) p.pvid = p.vlans[0]!;
  return [...ports.values()].sort((a, b) => a.idx - b.idx);
}

export function parseVlans(rows: Raw[], seen: Iterable<number>, names: Map<number, string>): Vlan[] {
  const out = new Map<number, string>();
  for (const r of rows) {
    const id = num(r.vlanId ?? r.vlanid ?? r.vlan_id ?? r.id);
    if (id > 0 && id < 4095) out.set(id, str(r.name ?? r.vlanName, 32));
  }
  for (const id of seen) if (id > 0 && id < 4095 && !out.has(id)) out.set(id, '');
  return [...out]
    .map(([id, name]) => ({ id, name: name || names.get(id) || (id === 1 ? 'default' : '') }))
    .sort((a, b) => a.id - b.id);
}

/**
 * Port layout as on the front panel: odd ports on the top row, even ports on the bottom row, in
 * columns of two. Switches with 8 ports or fewer have a single row. Returns rows of port numbers.
 */
export function frontPanel(ports: number[]): number[][] {
  const sorted = [...ports].sort((a, b) => a - b);
  if (sorted.length <= 8) return [sorted];
  return [sorted.filter((n) => n % 2 === 1), sorted.filter((n) => n % 2 === 0)];
}
