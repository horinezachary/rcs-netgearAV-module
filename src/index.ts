// Netgear AV Switches: find, watch and manage Netgear AV Line switches (M4250, M4300, M4350, M4500)
// over each switch's own REST API.
//
// The switches are the source of truth. Ports, VLANs, PoE and health are read from them on every
// poll and kept only in memory. State holds what the panel is looking at (switch, port); config
// holds the list of switches (address, port, pinned certificate) and the Allow changes switch; the
// switch logins are module secrets, kept apart from both and carried in named saves. Starting, restoring
// and reconnecting only read. A change (a port's VLAN, PoE, shutting a port, saving the running
// config) goes out only when the operator asks, only with Allow changes on, and only after a
// confirmation: a held key on the Stream Deck, a dialog on screen.
//
// NETGEAR Engage has no API other software can use, so the module does not talk to it. Switches
// onboarded to Engage take the Engage site password as their admin password: enter it once as the
// shared login and every switch uses it.
//
// Stream Deck:
//   keys 1-3    Overview, Ports, Discover (in every view but Ports)
//   Overview    keys 6-15 switches, press to open its ports
//   Ports       keys 1-10 VLANs for the selected port (key 10 pages with more than 10 VLANs),
//               11/12 previous/next port, 13 hold: PoE on/off, 14 hold: PoE power cycle,
//               15 hold: save the staged VLAN changes
//   Discover    keys 6-15 switches found, press to add

import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { defineModule, type Ctx, type KeySetParams } from '@rcs/module-sdk';
import { SwitchClient, type Login } from './client.js';
import { nsdpSearch, scan, type Found } from './discovery.js';
import { emptySwitch, frontPanel, type Port, type SwitchView } from './model.js';

export interface State {
  /** Id of the switch the panel shows. */
  sw: string;
  /** Port number on that switch. */
  selPort: number;
}

export interface SwitchEntry {
  id: string;
  address: string;
  port: number;
  /** SHA-256 of the switch's certificate, pinned on first connect. */
  fingerprint: string;
  /** Name to show before the first read, from discovery or the operator. */
  label: string;
}

export interface Config {
  switches: SwitchEntry[];
  /** Lets the operator change VLANs, PoE and port state, and save the config. Off: the module only reads. */
  allowChanges: boolean;
}

interface Credentials {
  /** Used by any switch without its own login: the Engage site password, or a common admin login. */
  shared?: Login;
  perSwitch: Record<string, Login>;
}

type C = Ctx<State, Config>;
export type View = 'overview' | 'ports' | 'discover' | 'setup';
const VIEWS: View[] = ['overview', 'ports', 'discover', 'setup'];
const STRIP_VIEWS: View[] = ['overview', 'ports', 'discover'];

export const KEY = { OVERVIEW: 0, PORTS: 1, DISCOVER: 2, MORE: 9, PREV: 10, NEXT: 11, POE: 12, CYCLE: 13, SAVE: 14 } as const;
const HOLD_MS = 700;
export const MAX_SWITCHES = 16;
const API_PORT = 8443;

const ACCENT = '#F5A524';
const ON_ACCENT = '#16181C';
const DANGER = '#3A1E1C';
const GOOD = '#173A2A';

interface Runtime {
  clients: Map<string, SwitchClient>;
  view: View;
  /** Unsaved VLAN picks on the panel's switch: port number to VLAN id. */
  pending: Map<number, number>;
  vlanPage: number;
  creds: Credentials;
  found: Found[];
  searching: '' | 'nsdp' | 'scan';
  /** Switches the module changed since it last saved their running config. Memory only. */
  unsaved: Set<string>;
  drawTimer: NodeJS.Timeout | null;
}
let rt: Runtime | null = null;

const ADDRESS_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]+\]?$/;
export const validAddress = (a: unknown): a is string => typeof a === 'string' && a !== '' && ADDRESS_RE.test(a);

function cfg(ctx: C): Config {
  const c = (ctx.config ?? {}) as Partial<Config>;
  return {
    switches: Array.isArray(c.switches) ? c.switches.map((s) => ({ id: s.id, address: s.address, port: s.port || API_PORT, fingerprint: s.fingerprint ?? '', label: s.label ?? '' })) : [],
    allowChanges: c.allowChanges ?? false
  };
}

const short = (s: string | undefined, n: number): string => [...(s ?? '')].slice(0, n).join('');
const loginFor = (id: string): Login | null => rt?.creds.perSwitch[id] ?? rt?.creds.shared ?? null;
const viewOf = (id: string): SwitchView => rt?.clients.get(id)?.view ?? emptySwitch();
const isReady = (id: string): boolean => !!rt?.clients.get(id)?.ready;

function currentEntry(ctx: C): SwitchEntry | undefined {
  const list = cfg(ctx).switches;
  return list.find((s) => s.id === ctx.state.value.sw) ?? list[0];
}

function mbps(m: number): string {
  return m >= 1000 ? (m / 1000).toFixed(1) + 'G' : m >= 100 ? m.toFixed(0) : m.toFixed(1);
}

function quiet(p: Promise<unknown>): void {
  p.catch(() => {});
}

// ---- credentials: module secrets, never in state or config ------------------------------------
//
// The controller keeps them apart from state and config, puts them in named saves (sealed with a
// passphrase in a downloaded save) and clears them on Reset. Earlier versions, and controllers
// before 0.15.0 that have no secrets, keep them in credentials.json in the data folder (mode 600,
// not in saves). On a newer controller that file is moved into the secrets on the first start.

const LEGACY_FILE = 'credentials.json';
/** Set false once the controller turns out to be one without secrets. */
let hostHasSecrets = true;
const cleanLogin = (l: any): Login | undefined =>
  l && typeof l.username === 'string' && typeof l.password === 'string' && l.username && l.password ? { username: l.username.slice(0, 64), password: l.password.slice(0, 128) } : undefined;

function credsOf(j: any): Credentials {
  const perSwitch: Record<string, Login> = {};
  for (const [k, v] of Object.entries(j?.perSwitch ?? {})) {
    const l = cleanLogin(v);
    if (l) perSwitch[k] = l;
  }
  const shared = cleanLogin(j?.shared);
  return shared ? { shared, perSwitch } : { perSwitch };
}

const anyLogin = (c: Credentials) => !!c.shared || Object.keys(c.perSwitch).length > 0;

async function loadCreds(ctx: C): Promise<Credentials> {
  hostHasSecrets = true;
  const file = path.join(ctx.dataDir, LEGACY_FILE);
  let legacy: Credentials | null = null;
  try {
    legacy = credsOf(JSON.parse(await readFile(file, 'utf8')));
  } catch {
    // none, or unreadable
  }
  if (!legacy) return credsOf(ctx.secrets.value);
  if (anyLogin(credsOf(ctx.secrets.value))) {
    await rm(file, { force: true }); // already moved: the secrets win
    return credsOf(ctx.secrets.value);
  }
  if (anyLogin(legacy)) await saveCreds(ctx, legacy);
  if (!hostHasSecrets) return legacy;
  await rm(file, { force: true });
  if (anyLogin(legacy)) await ctx.log('info', 'Moved the switch logins into the module secrets');
  return legacy;
}

async function saveCreds(ctx: C, c: Credentials): Promise<void> {
  const clean = c.shared ? { shared: c.shared, perSwitch: c.perSwitch } : { perSwitch: c.perSwitch };
  if (hostHasSecrets) {
    try {
      return await ctx.secrets.set(clean);
    } catch (e: any) {
      if (e?.reason !== 'method_not_found') throw e;
      hostHasSecrets = false;
    }
  }
  const file = path.join(ctx.dataDir, LEGACY_FILE);
  await mkdir(ctx.dataDir, { recursive: true });
  // Written aside and renamed, so a crash or a second save never leaves half a file.
  const tmp = `${file}.${process.pid}.${randomBytes(3).toString('hex')}`;
  await writeFile(tmp, JSON.stringify(clean), { mode: 0o600 });
  await chmod(tmp, 0o600).catch(() => {});
  await rename(tmp, file);
}

// ---- connections --------------------------------------------------------------------------------

/** Connects to each switch in config and drops the ones no longer there. Only reads. */
function sync(ctx: C, force: string[] = []): void {
  if (!rt) return;
  const list = cfg(ctx).switches;
  for (const [id, client] of rt.clients) {
    const e = list.find((s) => s.id === id);
    if (e && !force.includes(id) && client.host === e.address && client.port === e.port && (client.fingerprint === e.fingerprint || !e.fingerprint)) continue;
    client.removeAllListeners();
    client.stop();
    rt.clients.delete(id);
  }
  for (const e of list) {
    if (rt.clients.has(e.id)) continue;
    const client = new SwitchClient({ host: e.address, port: e.port, fingerprint: e.fingerprint, login: loginFor(e.id) });
    rt.clients.set(e.id, client);
    client.on('status', () => {
      if (rt?.clients.get(e.id) !== client) return;
      soon(ctx);
    });
    client.on('change', () => {
      if (rt?.clients.get(e.id) !== client) return;
      soon(ctx);
    });
    client.on('fingerprint', (fp) => {
      if (rt?.clients.get(e.id) !== client) return;
      // Trust on first use: the module's own setting, not device state.
      const c = cfg(ctx);
      quiet(
        ctx
          .setConfig({ ...c, switches: c.switches.map((s) => (s.id === e.id ? { ...s, fingerprint: fp } : s)) })
          .then(() => ctx.log('info', `Trusted the certificate of ${e.address}: ${fp}`))
      );
    });
    client.start();
  }
  quiet(reportStatus(ctx));
}

async function reportStatus(ctx: C): Promise<void> {
  const list = cfg(ctx).switches;
  if (!list.length) return ctx.status('disconnected', 'Add a switch on the Discover or Setup page');
  const up = list.filter((s) => isReady(s.id)).length;
  if (up === list.length) return ctx.status('connected', up === 1 ? '' : `${up} switches`);
  return ctx.status(up ? 'connecting' : 'disconnected', `${up} of ${list.length} switches connected`);
}

// ---- drawing -----------------------------------------------------------------------------------

function summary(e: SwitchEntry) {
  const client = rt?.clients.get(e.id);
  const v = viewOf(e.id);
  const ports = v.ports;
  return {
    id: e.id,
    address: e.address,
    port: e.port,
    label: e.label,
    name: v.info?.name || e.label || e.address,
    model: v.info?.model ?? '',
    connection: client?.connection ?? 'disconnected',
    statusText: client?.statusText || (loginFor(e.id) ? '' : 'Needs a login: set it in the web view Setup page'),
    ready: !!client?.ready,
    certificateSeen: client?.certificateSeen ?? '',
    fingerprint: e.fingerprint,
    login: rt?.creds.perSwitch[e.id] ? 'own' : rt?.creds.shared ? 'shared' : 'none',
    username: loginFor(e.id)?.username ?? '',
    info: v.info,
    portsUp: ports.filter((p) => p.up).length,
    portCount: ports.length,
    poeOn: ports.filter((p) => p.poe?.status === 'Delivering').length,
    faults: ports.filter((p) => p.poe && /Fault|Overload/.test(p.poe.status)).length,
    history: v.history.slice(-30),
    unsaved: rt?.unsaved.has(e.id) ?? false
  };
}

function detail(e: SwitchEntry | undefined) {
  if (!e) return null;
  const v = viewOf(e.id);
  return { id: e.id, name: v.info?.name || e.label || e.address, ports: v.ports, vlans: v.vlans, layout: frontPanel(v.ports.map((p) => p.idx)) };
}

export function snapshot(ctx: C) {
  const c = cfg(ctx);
  const cur = currentEntry(ctx);
  return {
    type: 'snapshot',
    view: rt?.view ?? 'overview',
    allowChanges: c.allowChanges,
    shared: rt?.creds.shared ? rt.creds.shared.username : '',
    switches: c.switches.map(summary),
    current: cur?.id ?? '',
    detail: detail(cur),
    selPort: ctx.state.value.selPort,
    pending: [...(rt?.pending ?? [])],
    found: rt?.found ?? [],
    searching: rt?.searching ?? ''
  };
}

function navFaces(): KeySetParams[] {
  const cur = rt?.view ?? 'overview';
  const nav = (index: number, label: string, v: View, sub = 'VIEW'): KeySetParams =>
    cur === v ? { index, label, sublabel: sub, background: ACCENT, color: ON_ACCENT } : { index, label, sublabel: sub };
  return [nav(KEY.OVERVIEW, 'STATUS', 'overview'), nav(KEY.PORTS, 'PORTS', 'ports'), nav(KEY.DISCOVER, 'FIND', 'discover'), { index: 3 }, { index: 4 }];
}

function vlanPaging(n: number): { perPage: number; pages: number } {
  const perPage = n > 10 ? 9 : 10;
  return { perPage, pages: Math.max(1, Math.ceil(n / perPage)) };
}

function selectedPort(ctx: C): Port | undefined {
  const e = currentEntry(ctx);
  const ports = e ? viewOf(e.id).ports : [];
  return ports.find((p) => p.idx === ctx.state.value.selPort) ?? ports[0];
}

function keyFaces(ctx: C): KeySetParams[] {
  const c = cfg(ctx);
  const cur = rt?.view ?? 'overview';
  const blanks = (from: number, to: number) => Array.from({ length: to - from }, (_, i) => ({ index: from + i }));

  if (cur === 'ports') {
    const e = currentEntry(ctx);
    if (!e || !isReady(e.id)) {
      return [...navFaces(), ...blanks(5, 7), { index: 7, label: 'OFFLINE', sublabel: short(e?.address ?? 'no switch', 12), background: DANGER }, ...blanks(8, 15)];
    }
    const v = viewOf(e.id);
    const port = selectedPort(ctx);
    const target = port ? rt!.pending.get(port.idx) ?? port.pvid : 0;
    const { perPage, pages } = vlanPaging(v.vlans.length);
    const page = Math.min(rt!.vlanPage, pages - 1);
    const faces: KeySetParams[] = [];
    for (let k = 0; k < 10; k++) {
      const vl = v.vlans[page * perPage + k];
      if (k === KEY.MORE && pages > 1) faces.push({ index: k, label: 'MORE ▶', sublabel: `page ${page + 1}/${pages}` });
      else if (k < perPage && vl && port) {
        const on = vl.id === target;
        faces.push({ index: k, label: short((vl.name || `VLAN ${vl.id}`).toUpperCase(), 10), sublabel: `VLAN ${vl.id}`, ...(on ? { background: ACCENT, color: ON_ACCENT } : {}) });
      } else faces.push({ index: k });
    }
    const n = rt!.pending.size;
    const allow = c.allowChanges;
    faces.push({ index: KEY.PREV, label: '◀ PORT', sublabel: port ? `port ${port.idx}` : '' });
    faces.push({ index: KEY.NEXT, label: 'PORT ▶', sublabel: short(v.info?.name || e.label, 12) });
    if (port?.poe && allow) {
      faces.push({ index: KEY.POE, label: port.poe.enabled ? 'POE OFF' : 'POE ON', sublabel: 'hold', ...(port.poe.enabled ? {} : { background: GOOD }) });
      faces.push({ index: KEY.CYCLE, label: 'POE CYCLE', sublabel: 'hold', background: DANGER });
    } else {
      faces.push({ index: KEY.POE, label: port?.poe ? (port.poe.enabled ? 'POE ON' : 'POE OFF') : 'NO POE', sublabel: port?.poe ? `${port.poe.watts} W` : '' });
      faces.push({ index: KEY.CYCLE });
    }
    faces.push(
      !allow
        ? { index: KEY.SAVE, label: 'VIEW ONLY', sublabel: 'see Setup' }
        : n
          ? { index: KEY.SAVE, label: 'SAVE', sublabel: `${n} · hold`, background: ACCENT, color: ON_ACCENT }
          : { index: KEY.SAVE, label: 'SAVE', sublabel: 'nothing' }
    );
    return faces;
  }

  const faces = navFaces();
  if (cur === 'overview' || cur === 'setup') {
    const list = c.switches.slice(0, 10).map(summary);
    list.forEach((s, i) =>
      faces.push({
        index: 5 + i,
        label: short(s.name.toUpperCase(), 10),
        sublabel: s.ready ? `${s.portsUp}/${s.portCount} up` : 'OFFLINE',
        ...(!s.ready ? { background: DANGER } : s.faults ? { background: DANGER } : s.id === currentEntry(ctx)?.id ? {} : {})
      })
    );
    faces.push(...blanks(5 + list.length, 15));
  } else if (cur === 'discover') {
    const list = (rt?.found ?? []).slice(0, 10);
    list.forEach((f, i) => {
      const known = knownEntry(ctx, f);
      const name = f.name || (known ? nameOf(known) : '') || f.model || f.address;
      faces.push({ index: 5 + i, label: short(name.toUpperCase(), 10), sublabel: known ? 'added' : short(f.address, 12), ...(known ? { background: GOOD } : {}) });
    });
    faces.push(...blanks(5 + list.length, 15));
  }
  return faces;
}

export async function draw(ctx: C, clientId?: string): Promise<void> {
  if (!clientId) {
    if (rt?.drawTimer) clearTimeout(rt.drawTimer);
    if (rt) rt.drawTimer = null;
    await ctx.keys.setMany(keyFaces(ctx));
  }
  await ctx.ui.send(snapshot(ctx), clientId);
}

/** Polls of several switches land close together: draw once for them. */
function soon(ctx: C): void {
  if (!rt || rt.drawTimer) return;
  rt.drawTimer = setTimeout(() => {
    if (!rt) return;
    rt.drawTimer = null;
    quiet(reportStatus(ctx));
    quiet(draw(ctx));
  }, 150);
}

// ---- selection: the module's own state ---------------------------------------------------------

async function setView(ctx: C, v: unknown): Promise<void> {
  if (!rt || !VIEWS.includes(v as View)) return;
  rt.view = v as View;
  if (STRIP_VIEWS.includes(rt.view)) quiet(ctx.strip.select(rt.view));
  if (rt.view === 'discover' && !rt.found.length && !rt.searching) void search(ctx, 'nsdp');
  await draw(ctx);
}

async function selectSwitch(ctx: C, id: unknown, open = false): Promise<void> {
  const e = cfg(ctx).switches.find((s) => s.id === id);
  if (!rt || !e) return;
  if (e.id !== currentEntry(ctx)?.id) rt.pending.clear(); // unsaved picks belong to one switch
  await ctx.state.patch({ sw: e.id, selPort: viewOf(e.id).ports[0]?.idx ?? 1 });
  rt.vlanPage = 0;
  if (open) return setView(ctx, 'ports');
  await draw(ctx);
}

async function stepPort(ctx: C, by: number): Promise<void> {
  const e = currentEntry(ctx);
  const ports = e ? viewOf(e.id).ports : [];
  if (!e || !ports.length) return;
  const i = Math.max(0, ports.findIndex((p) => p.idx === ctx.state.value.selPort));
  const next = ports[(i + by + ports.length) % ports.length]!;
  await ctx.state.patch({ sw: e.id, selPort: next.idx });
  await draw(ctx);
}

async function selectPort(ctx: C, idx: unknown): Promise<void> {
  const e = currentEntry(ctx);
  if (!e || !viewOf(e.id).ports.some((p) => p.idx === idx)) return;
  await ctx.state.patch({ sw: e.id, selPort: idx as number });
  await draw(ctx);
}

// ---- discovery: reads only ---------------------------------------------------------------------

/** Test and development hook: comma-separated host:port list to scan instead of the subnets. */
function scanTargets(): { host: string; port: number }[] | null {
  const env = process.env.RCS_NETGEAR_SCAN;
  if (!env) return null;
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [host, port] = s.split(':');
      return { host: host!, port: Number(port) || API_PORT };
    });
}

/** Test and development hook: host:port to send NSDP to instead of broadcasting. */
function nsdpTargets(): { targets?: string[]; ports?: number[]; localPorts?: number[]; waitMs?: number } {
  const env = process.env.RCS_NETGEAR_NSDP;
  if (!env) return {};
  const [host, port] = env.split(':');
  return { targets: [host!], ports: [Number(port) || 63322], localPorts: [0], waitMs: 600 };
}

async function search(ctx: C, how: 'nsdp' | 'scan'): Promise<void> {
  if (!rt || rt.searching) return;
  const r = rt;
  r.searching = how;
  await draw(ctx);
  try {
    const merged = new Map(r.found.map((f) => [`${f.address}:${f.apiPort || API_PORT}`, f]));
    const add = (f: Found) => {
      const key = `${f.address}:${f.apiPort || API_PORT}`;
      const old = merged.get(key) ?? [...merged.values()].find((x) => x.address === f.address && (!x.apiPort || !f.apiPort));
      if (old) {
        merged.delete(`${old.address}:${old.apiPort || API_PORT}`);
        merged.set(key, { ...old, ...Object.fromEntries(Object.entries(f).filter(([, v]) => v !== '' && v !== 0)), via: [...new Set([...old.via, ...f.via])] } as Found);
      } else merged.set(key, f);
    };
    if (how === 'nsdp') {
      for (const f of await nsdpSearch(nsdpTargets())) add({ ...f, apiPort: 0, via: ['nsdp'] });
    } else {
      const targets = scanTargets();
      const results = targets
        ? (await Promise.all(targets.map((t) => scan({ hosts: [t.host], port: t.port })))).flat()
        : await scan();
      for (const s of results) add({ address: s.address, apiPort: s.port, model: '', name: '', mac: '', firmware: '', via: ['scan'] });
    }
    if (rt !== r) return;
    r.found = [...merged.values()].slice(0, 64);
    if (how === 'scan' && !r.found.length) await ctx.notify('Nothing answered on the API port on this network');
  } catch (e) {
    await ctx.notify(`Search failed: ${(e as Error).message}`, 'warning');
  } finally {
    if (rt === r) {
      r.searching = '';
      await draw(ctx);
    }
  }
}

async function addSwitch(ctx: C, address: unknown, port: unknown, label: unknown): Promise<void> {
  if (!rt) return;
  const a = typeof address === 'string' ? address.trim() : '';
  if (!validAddress(a)) return ctx.notify('That is not an IP address or host name', 'warning');
  const p = port === undefined || port === '' || port === 0 ? API_PORT : Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) return ctx.notify('Port must be 1 to 65535', 'warning');
  const c = cfg(ctx);
  if (c.switches.some((s) => s.address === a && s.port === p)) return ctx.notify(`${a} is already in the list`);
  if (c.switches.length >= MAX_SWITCHES) return ctx.notify(`Up to ${MAX_SWITCHES} switches`, 'warning');
  const id = randomBytes(4).toString('hex');
  const name = typeof label === 'string' ? label.trim().slice(0, 40) : '';
  await ctx.setConfig({ ...c, switches: [...c.switches, { id, address: a, port: p, fingerprint: '', label: name }] });
  await ctx.log('info', `Added switch ${a}:${p}`);
  if (!loginFor(id)) await ctx.notify(`Added ${name || a}. Set its login (or the shared login) in the web view Setup page.`);
  if (!ctx.state.value.sw) await ctx.state.patch({ sw: id });
  sync(ctx);
  await draw(ctx);
}

async function removeSwitch(ctx: C, id: unknown): Promise<void> {
  if (!rt) return;
  const c = cfg(ctx);
  const e = c.switches.find((s) => s.id === id);
  if (!e) return;
  await ctx.setConfig({ ...c, switches: c.switches.filter((s) => s.id !== e.id) });
  if (rt.creds.perSwitch[e.id]) {
    delete rt.creds.perSwitch[e.id];
    await saveCreds(ctx, rt.creds);
  }
  rt.unsaved.delete(e.id);
  if (ctx.state.value.sw === e.id) {
    rt.pending.clear();
    await ctx.state.patch({ sw: cfg(ctx).switches[0]?.id ?? '', selPort: 1 });
  }
  await ctx.log('info', `Removed switch ${e.address}`);
  sync(ctx);
  await draw(ctx);
}

// ---- operator actions: the only things that change a switch ------------------------------------

function changesAllowed(ctx: C): boolean {
  if (cfg(ctx).allowChanges) return true;
  void ctx.notify('This module only reads. Turn on Allow changes in Setup to change the switches.', 'warning');
  return false;
}

function clientFor(ctx: C, id: unknown): { e: SwitchEntry; client: SwitchClient } | null {
  const e = cfg(ctx).switches.find((s) => s.id === id);
  const client = e ? rt?.clients.get(e.id) : undefined;
  if (!e || !client?.ready) {
    void ctx.notify('Not connected to that switch', 'warning');
    return null;
  }
  return { e, client };
}

const knownEntry = (ctx: C, f: Found) => cfg(ctx).switches.find((s) => s.address === f.address && s.port === (f.apiPort || API_PORT));
const nameOf = (e: SwitchEntry) => viewOf(e.id).info?.name || e.label || e.address;

/** Runs one change and reports it. True when the switch accepted it. */
async function change(ctx: C, id: unknown, what: string, fn: (client: SwitchClient, e: SwitchEntry) => Promise<void>, setting = true): Promise<boolean> {
  if (!changesAllowed(ctx)) return false;
  const t = clientFor(ctx, id);
  if (!t) return false;
  try {
    await fn(t.client, t.e);
    if (setting) rt?.unsaved.add(t.e.id);
    await ctx.log('info', `${nameOf(t.e)}: ${what}`);
    await ctx.notify(`${nameOf(t.e)}: ${what}`);
    return true;
  } catch (e) {
    await ctx.notify(`${nameOf(t.e)}: not changed. ${(e as Error).message}`, 'error');
    return false;
  } finally {
    await draw(ctx);
  }
}

/** Stages a VLAN for the panel's selected port. Nothing is sent until SAVE. */
async function pickVlan(ctx: C, vlan: number): Promise<void> {
  const e = currentEntry(ctx);
  if (!rt || !e || !isReady(e.id) || !changesAllowed(ctx)) return;
  const port = selectedPort(ctx);
  if (!port || !viewOf(e.id).vlans.some((v) => v.id === vlan)) return;
  if (port.pvid === vlan) rt.pending.delete(port.idx);
  else rt.pending.set(port.idx, vlan);
  await draw(ctx);
}

async function applyVlans(ctx: C, id: unknown, changes: { idx: number; vlan: number }[]): Promise<boolean> {
  const v = typeof id === 'string' ? viewOf(id) : emptySwitch();
  const valid = changes.filter((ch) => v.ports.some((p) => p.idx === ch.idx && p.pvid !== ch.vlan) && v.vlans.some((x) => x.id === ch.vlan));
  if (!valid.length) {
    await ctx.notify('No port changes to save');
    return false;
  }
  const list = valid.map((ch) => `${ch.idx} → VLAN ${ch.vlan}`).join(', ');
  return change(ctx, id, `port ${list}`, async (client) => {
    for (const ch of valid) await client.setAccessVlan(ch.idx, ch.vlan);
  });
}

async function savePending(ctx: C): Promise<void> {
  const e = currentEntry(ctx);
  if (!rt || !e || !rt.pending.size) return;
  const r = rt;
  if (await applyVlans(ctx, e.id, [...r.pending].map(([idx, vlan]) => ({ idx, vlan })))) r.pending.clear();
  await draw(ctx);
}

const portOf = (id: unknown, idx: unknown): Port | undefined => (typeof id === 'string' ? viewOf(id).ports.find((p) => p.idx === idx) : undefined);

async function setPoe(ctx: C, id: unknown, idx: unknown, on: boolean): Promise<void> {
  const p = portOf(id, idx);
  if (!p?.poe) return ctx.notify('That port has no PoE', 'warning');
  await change(ctx, id, `PoE ${on ? 'on' : 'off'} on port ${p.idx}`, (c) => c.setPoe(p.idx, on));
}

async function cyclePoe(ctx: C, id: unknown, idx: unknown): Promise<void> {
  const p = portOf(id, idx);
  if (!p?.poe) return ctx.notify('That port has no PoE', 'warning');
  await change(ctx, id, `power cycled port ${p.idx}`, (c) => c.cyclePoe(p.idx), false); // changes no setting
}

async function setPortEnabled(ctx: C, id: unknown, idx: unknown, on: boolean): Promise<void> {
  const p = portOf(id, idx);
  if (!p) return;
  await change(ctx, id, `port ${p.idx} ${on ? 'enabled' : 'shut down'}`, (c) => c.setPortEnabled(p.idx, on));
}

async function saveConfig(ctx: C, id: unknown): Promise<void> {
  if (await change(ctx, id, 'running config saved to startup', (c) => c.saveConfig(), false)) {
    rt?.unsaved.delete(String(id));
    await draw(ctx);
  }
}

/** Sends a stored password to the web client that asked, once the system PIN is entered. */
async function reveal(ctx: C, which: unknown, clientId: string): Promise<void> {
  if (!rt) return;
  const l = which === 'shared' ? rt.creds.shared : typeof which === 'string' ? rt.creds.perSwitch[which] : undefined;
  if (!l) return;
  const what = which === 'shared' ? 'the shared switch login' : `the login of ${nameOf(cfg(ctx).switches.find((s) => s.id === which) ?? { id: '', address: String(which), port: 0, fingerprint: '', label: '' })}`;
  if (!(await ctx.verifyPin(`Show the password for ${what}`, clientId))) return ctx.notify('Password not shown: the PIN was not entered', 'warning');
  await ctx.ui.send({ type: 'reveal', which, username: l.username, password: l.password }, clientId);
}

async function setCredentials(ctx: C, m: any): Promise<void> {
  if (!rt) return;
  const target: string = m.which === 'shared' ? 'shared' : typeof m.which === 'string' && cfg(ctx).switches.some((s) => s.id === m.which) ? m.which : '';
  if (!target) return;
  if (m.clear) {
    if (target === 'shared') delete rt.creds.shared;
    else delete rt.creds.perSwitch[target];
  } else {
    const l = cleanLogin({ username: typeof m.username === 'string' ? m.username.trim() : '', password: m.password });
    if (!l) return ctx.notify('Enter a username and a password', 'warning');
    if (target === 'shared') rt.creds.shared = l;
    else rt.creds.perSwitch[target] = l;
  }
  await saveCreds(ctx, rt.creds);
  await ctx.log('info', `${m.clear ? 'Removed' : 'Set'} ${target === 'shared' ? 'the shared login' : `the login for ${target}`}`);
  // Reconnect the switches whose login this changes.
  const affected = cfg(ctx).switches.filter((s) => target === s.id || (target === 'shared' && !rt!.creds.perSwitch[s.id])).map((s) => s.id);
  sync(ctx, affected);
  await draw(ctx);
}

async function setAllow(ctx: C, on: unknown): Promise<void> {
  await ctx.setConfig({ ...cfg(ctx), allowChanges: !!on });
  if (rt && !on) rt.pending.clear();
  await draw(ctx);
}

async function trust(ctx: C, id: unknown): Promise<void> {
  const client = typeof id === 'string' ? rt?.clients.get(id) : undefined;
  const seen = client?.certificateSeen;
  if (!seen) return;
  const c = cfg(ctx);
  await ctx.setConfig({ ...c, switches: c.switches.map((s) => (s.id === id ? { ...s, fingerprint: seen } : s)) });
  await ctx.log('warning', `Trusted a new certificate for ${id}: ${seen}`);
  sync(ctx, [String(id)]);
  await draw(ctx);
}

export default defineModule<State, Config>({
  holdMs: HOLD_MS,

  async start(ctx) {
    if (rt) for (const c of rt.clients.values()) c.stop();
    const r: Runtime = (rt = { clients: new Map(), view: 'overview', pending: new Map(), vlanPage: 0, creds: { perSwitch: {} }, found: [], searching: '', unsaved: new Set(), drawTimer: null });
    const saved = await loadCreds(ctx);
    if (!r.creds.shared && !Object.keys(r.creds.perSwitch).length) r.creds = saved; // unless a login came in meanwhile
    await ctx.state.init({ sw: '', selPort: 1 });
    await ctx.strip.set([
      { id: 'overview', label: 'Switches', icon: 'assets/overview.svg' },
      { id: 'ports', label: 'Ports', icon: 'assets/ports.svg' },
      { id: 'discover', label: 'Discover', icon: 'assets/discover.svg' }
    ]);
    sync(ctx); // reads only: no changes on start, whatever the reason
    await draw(ctx);
  },

  stop() {
    if (!rt) return;
    if (rt.drawTimer) clearTimeout(rt.drawTimer);
    for (const c of rt.clients.values()) {
      c.removeAllListeners();
      c.stop();
    }
    rt = null;
  },

  async key(ctx, { index, action }) {
    if (action !== 'down' || !rt) return;
    const cur = rt.view;
    if (cur === 'ports') {
      const e = currentEntry(ctx);
      const vlans = e ? viewOf(e.id).vlans : [];
      const { perPage, pages } = vlanPaging(vlans.length);
      if (index === KEY.MORE && pages > 1) {
        rt.vlanPage = (rt.vlanPage + 1) % pages;
        return draw(ctx);
      }
      if (index < perPage) {
        const vl = vlans[Math.min(rt.vlanPage, pages - 1) * perPage + index];
        if (vl) await pickVlan(ctx, vl.id);
        return;
      }
      if (index === KEY.PREV) return stepPort(ctx, -1);
      if (index === KEY.NEXT) return stepPort(ctx, 1);
      if (cfg(ctx).allowChanges) {
        if (index === KEY.SAVE && rt.pending.size) return ctx.notify('Hold SAVE to apply the port changes');
        if ((index === KEY.POE || index === KEY.CYCLE) && selectedPort(ctx)?.poe) return ctx.notify('Hold the key to change PoE');
      }
      return;
    }
    if (index === KEY.OVERVIEW) return setView(ctx, 'overview');
    if (index === KEY.PORTS) return setView(ctx, 'ports');
    if (index === KEY.DISCOVER) return setView(ctx, 'discover');
    if (index < 5) return;
    if (cur === 'overview' || cur === 'setup') {
      const e = cfg(ctx).switches[index - 5];
      if (e) await selectSwitch(ctx, e.id, true);
    } else if (cur === 'discover') {
      const f = rt.found[index - 5];
      if (f && !knownEntry(ctx, f)) await addSwitch(ctx, f.address, f.apiPort || API_PORT, f.name);
    }
  },

  async hold(ctx, index) {
    if (!rt || rt.view !== 'ports') return;
    const e = currentEntry(ctx);
    const p = selectedPort(ctx);
    if (index === KEY.SAVE) return savePending(ctx);
    if (!e || !p?.poe) return;
    if (index === KEY.POE) return setPoe(ctx, e.id, p.idx, !p.poe.enabled);
    if (index === KEY.CYCLE) return cyclePoe(ctx, e.id, p.idx);
  },

  async strip(ctx, id) {
    await setView(ctx, id);
  },

  async client(ctx, { clientId, action }) {
    if (action === 'connect') await draw(ctx, clientId);
  },

  async ui(ctx, { clientId, message: m }) {
    if (!rt || typeof m !== 'object' || m === null) return;
    switch (m.type) {
      case 'hello':
        return draw(ctx, clientId);
      case 'view':
        return setView(ctx, m.view);
      case 'select-switch':
        return selectSwitch(ctx, m.id, !!m.open);
      case 'select-port':
        return selectPort(ctx, m.idx);
      case 'pick-vlan':
        return pickVlan(ctx, Number(m.vlan));
      case 'revert':
        rt.pending.clear();
        return draw(ctx);
      case 'save':
        return savePending(ctx);
      case 'get-switch': {
        // The web view keeps its own switch, so browsing there never moves the panel.
        const e = cfg(ctx).switches.find((s) => s.id === m.id);
        return ctx.ui.send({ type: 'switch', switch: detail(e) }, clientId);
      }
      case 'apply-vlans': {
        // From the web view, which keeps its own unsaved picks: an explicit switch and port list.
        const changes = Array.isArray(m.changes)
          ? m.changes.filter((ch: any) => Number.isInteger(ch?.idx) && Number.isInteger(ch?.vlan)).map((ch: any) => ({ idx: ch.idx, vlan: ch.vlan }))
          : [];
        await applyVlans(ctx, m.id, changes);
        return ctx.ui.send({ type: 'applied', id: m.id }, clientId);
      }
      case 'poe':
        return setPoe(ctx, m.id, m.idx, !!m.on);
      case 'cycle':
        return cyclePoe(ctx, m.id, m.idx);
      case 'port-enabled':
        return setPortEnabled(ctx, m.id, m.idx, !!m.on);
      case 'save-config':
        return saveConfig(ctx, m.id);
      case 'search':
        return search(ctx, m.how === 'scan' ? 'scan' : 'nsdp');
      case 'add':
        return addSwitch(ctx, m.address, m.port, m.label);
      case 'remove':
        return removeSwitch(ctx, m.id);
      case 'allow':
        return setAllow(ctx, m.on);
      case 'credentials':
        return setCredentials(ctx, m);
      case 'reveal':
        return reveal(ctx, m.which, clientId);
      case 'trust':
        return trust(ctx, m.id);
      case 'reconnect':
        sync(ctx, cfg(ctx).switches.map((s) => s.id));
        return draw(ctx);
    }
  }
});
