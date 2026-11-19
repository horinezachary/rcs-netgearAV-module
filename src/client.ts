// A connection to one Netgear AV Line switch (M4250, M4300, M4350, M4500) over its REST API:
// https://<switch>:8443/api/v1, the API Netgear documents for these switches and that Bitfocus
// Companion's AV Line module uses.
//
// Connecting only reads. The client logs in, then polls with GETs (port statistics every few
// seconds; device, port settings, PoE, LLDP and VLAN names more slowly) and mirrors what the switch
// reports. The things that change the switch (a port's VLAN, PoE, a port shut down, saving the
// running config) are separate methods the module calls only when the operator asks, and afterwards
// the client shows what the switch then reports, never a guess at what the change did.

import { EventEmitter } from 'node:events';
import { CertificateChanged, request, type Target } from './http.js';
import { asList, emptySwitch, parseInfo, parsePorts, parseVlans, portNumber, unwrap, type SwitchView } from './model.js';

export type Connection = 'connected' | 'connecting' | 'disconnected';

export interface Login {
  username: string;
  password: string;
}

export interface ClientOptions {
  host: string;
  port: number;
  fingerprint: string;
  login: Login | null;
  fastMs?: number;
  slowMs?: number;
  retryMs?: number;
  retryMaxMs?: number;
  historyLength?: number;
  timeoutMs?: number;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status = 0,
    readonly kind: 'api' | 'auth' | 'forbidden' = 'api'
  ) {
    super(message);
  }
}

export interface SwitchClient {
  on(event: 'status', fn: (connection: Connection, text: string) => void): this;
  on(event: 'change', fn: (view: SwitchView) => void): this;
  /** First connection to a switch whose certificate was not pinned yet. */
  on(event: 'fingerprint', fn: (fingerprint: string) => void): this;
}

type Raw = Record<string, any>;
export type VlanMode = 'untagged' | 'tagged' | 'excluded';

export class SwitchClient extends EventEmitter {
  view: SwitchView = emptySwitch();
  connection: Connection = 'disconnected';
  statusText = '';
  ready = false;
  /** Set when the switch's certificate is not the pinned one. Cleared by trusting it. */
  certificateSeen = '';

  private token = '';
  private fastTimer: NodeJS.Timeout | null = null;
  private slowTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private retryDelay: number;
  private stopped = true;
  private generation = 0;
  private raw = { stats: [] as Raw[], configs: [] as Raw[], poe: [] as Raw[], lldp: [] as Raw[], fibre: [] as Raw[], vlans: [] as Raw[], device: {} as Raw, poeConfig: null as Raw | null };
  private vlanNames = new Map<number, string>();
  /** Optional endpoints this switch does not answer, so they are not asked again every poll. */
  private unsupported = new Set<string>();
  /** Optional endpoints that have answered once: a later failure is a blip, not a missing feature. */
  private answered = new Set<string>();
  private busy: Promise<unknown> = Promise.resolve();
  private readonly o: Required<Omit<ClientOptions, 'login'>> & { login: Login | null };

  constructor(opts: ClientOptions) {
    super();
    this.o = { fastMs: 5000, slowMs: 20_000, retryMs: 2000, retryMaxMs: 30_000, historyLength: 60, timeoutMs: 10_000, ...opts };
    this.retryDelay = this.o.retryMs;
  }

  get host(): string {
    return this.o.host;
  }
  get port(): number {
    return this.o.port;
  }
  get fingerprint(): string {
    return this.o.fingerprint;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    void this.connect();
  }

  /** Stops polling and logs out (best effort: the switch keeps a few sessions per user). */
  stop(): void {
    const token = this.token;
    this.stopped = true;
    this.generation++;
    for (const t of [this.fastTimer, this.slowTimer, this.retryTimer]) if (t) clearTimeout(t);
    this.fastTimer = this.slowTimer = this.retryTimer = null;
    this.ready = false;
    this.token = '';
    if (token) void request({ ...this.target(), timeoutMs: 1500 }, 'POST', '/api/v1/logout', { authorization: `Bearer ${token}` }).catch(() => {});
    this.setStatus('disconnected', '');
  }

  // ---- reading ---------------------------------------------------------------------------------

  private setStatus(connection: Connection, text: string): void {
    if (connection === this.connection && text === this.statusText) return;
    this.connection = connection;
    this.statusText = text;
    this.emit('status', connection, text);
  }

  private async connect(): Promise<void> {
    const gen = ++this.generation;
    this.setStatus('connecting', `Connecting to ${this.o.host}`);
    try {
      await this.login();
      await this.pollSlow(gen);
      await this.pollFast(gen);
      if (gen !== this.generation) return;
      this.retryDelay = this.o.retryMs;
    } catch (e) {
      this.fail(gen, e);
    }
  }

  private fail(gen: number, e: unknown): void {
    if (gen !== this.generation || this.stopped) return;
    this.generation++;
    for (const t of [this.fastTimer, this.slowTimer]) if (t) clearTimeout(t);
    this.ready = false;
    this.token = '';
    if (e instanceof CertificateChanged) {
      this.certificateSeen = e.seen;
      this.setStatus('disconnected', 'The switch certificate changed. Check it, then trust it in Setup.');
      this.emit('change', this.view);
      return; // no retry until the operator trusts the new certificate
    }
    const msg = e instanceof Error ? e.message : String(e);
    this.setStatus('disconnected', msg);
    this.emit('change', this.view);
    // A refused password is retried slowly: the switch locks an account after a few failures.
    const wait = e instanceof ApiError && e.kind !== 'api' ? Math.max(this.o.retryMaxMs, 60_000) : this.retryDelay;
    this.retryTimer = setTimeout(() => void this.connect(), wait);
    this.retryDelay = Math.min(this.retryDelay * 2, this.o.retryMaxMs);
  }

  private pushHistory(): void {
    const rx = this.raw.stats.reduce((a, s) => a + (parseFloat(s.rxMbps) || 0), 0);
    const tx = this.raw.stats.reduce((a, s) => a + (parseFloat(s.txMbps) || 0), 0);
    this.view.history = this.view.history.concat([[Math.round(rx * 10) / 10, Math.round(tx * 10) / 10]]).slice(-this.o.historyLength);
    // A shorter history per port, for the detail panel on a tall screen.
    const per: Record<number, [number, number][]> = {};
    const old = this.view.portHistory ?? {};
    for (const st of this.raw.stats) {
      const idx = portNumber(st.portId ?? st.portid ?? st.ID ?? st.port);
      if (idx === null) continue;
      per[idx] = (old[idx] ?? []).concat([[Math.round((parseFloat(st.rxMbps) || 0) * 10) / 10, Math.round((parseFloat(st.txMbps) || 0) * 10) / 10]]).slice(-30);
    }
    this.view.portHistory = per;
  }

  private rebuild(): void {
    const r = this.raw;
    const ports = parsePorts(r.stats, r.configs, r.poe, r.lldp, r.fibre);
    const seen = new Set<number>();
    for (const p of ports) {
      if (p.pvid) seen.add(p.pvid);
      for (const v of p.vlans) seen.add(v);
    }
    this.view = {
      ...this.view,
      info: parseInfo(r.device, this.o.host, r.poeConfig),
      ports,
      vlans: parseVlans(r.vlans, seen, this.vlanNames)
    };
  }

  private async pollFast(gen: number): Promise<void> {
    if (gen !== this.generation) return;
    if (this.fastTimer) clearTimeout(this.fastTimer);
    try {
      const [stats, poe] = await Promise.all([this.list('sw_portstats?portid=ALL', 'switchStatsPort', 'switch_stats_port'), this.optional('swcfg_poe?portid=ALL', 'poePortConfig', 'poe_port_config')]);
      if (gen !== this.generation) return;
      this.raw.stats = stats;
      if (poe) this.raw.poe = poe;
      this.pushHistory();
      this.rebuild();
      this.emit('change', this.view);
      if (this.fastTimer) clearTimeout(this.fastTimer);
      this.fastTimer = setTimeout(() => void this.pollFast(gen), this.o.fastMs);
    } catch (e) {
      this.fail(gen, e);
    }
  }

  private async pollSlow(gen: number): Promise<void> {
    if (gen !== this.generation) return;
    if (this.slowTimer) clearTimeout(this.slowTimer);
    try {
      const device = unwrap(await this.call('GET', 'device_info'), 'deviceInfo', 'device_info') ?? {};
      const [stats, poe, configs, poeConfig, lldp, fibre, vlans] = await Promise.all([
        this.list('sw_portstats?portid=ALL', 'switchStatsPort', 'switch_stats_port'),
        this.optional('swcfg_poe?portid=ALL', 'poePortConfig', 'poe_port_config'),
        this.portConfigs(Number(device.numOfPorts) || 0),
        this.optional('poe_config', 'poe_config', 'poeConfig'),
        this.optional('lldp_remote_devices', 'lldp_remote_devices', 'lldpRemoteDevices'),
        this.optional('fiber_optics', 'fiber_optics', 'fiberOptics'),
        this.optional('swcfg_vlan?vlanid=ALL', 'switchConfigVlan', 'switch_config_vlan')
      ]);
      if (gen !== this.generation) return;
      Object.assign(this.raw, { device, stats, poe: poe ?? this.raw.poe, configs, poeConfig: poeConfig?.[0] ?? null, lldp: lldp ?? [], fibre: fibre ?? [], vlans: vlans ?? [] });
      if (!this.ready) this.pushHistory();
      this.rebuild();
      await this.readVlanNames(gen);
      this.rebuild();
      this.ready = true;
      this.setStatus('connected', '');
      this.emit('change', this.view);
      if (this.slowTimer) clearTimeout(this.slowTimer);
      this.slowTimer = setTimeout(() => void this.pollSlow(gen), this.o.slowMs);
    } catch (e) {
      this.fail(gen, e);
    }
  }

  /** Names of VLANs in use that the bulk read did not name, one request each, once. */
  private async readVlanNames(gen: number): Promise<void> {
    if (this.raw.vlans.length) return;
    for (const v of this.view.vlans) {
      if (gen !== this.generation || this.vlanNames.has(v.id)) continue;
      const row = (await this.optional(`swcfg_vlan?vlanid=${v.id}`, 'switchConfigVlan', 'switch_config_vlan', true))?.[0];
      this.vlanNames.set(v.id, typeof row?.name === 'string' ? row.name.slice(0, 32) : '');
    }
  }

  /** Every port's settings in one request where the firmware allows it, else one per port. */
  private async portConfigs(count: number): Promise<Raw[]> {
    const all = await this.optional('swcfg_port?portid=ALL', 'switchPortConfig', 'switch_port_config');
    if (all && all.length > 1) return all;
    const out: Raw[] = [];
    const n = count || this.raw.stats.length;
    for (let i = 1; i <= Math.min(n, 128); i++) {
      const one = await this.optional(`swcfg_port?portid=${i}`, 'switchPortConfig', 'switch_port_config', true);
      if (!one) break;
      out.push({ ...one[0], ID: one[0]?.ID ?? i });
    }
    return out;
  }

  /** Reads everything again now, after a change. */
  refresh(): Promise<void> {
    if (!this.ready) return Promise.resolve();
    const gen = this.generation;
    return this.pollSlow(gen).then(() => this.pollFast(gen));
  }

  // ---- the HTTP API ----------------------------------------------------------------------------

  private target(): Target {
    return { host: this.o.host, port: this.o.port, fingerprint: this.o.fingerprint, timeoutMs: this.o.timeoutMs };
  }

  private async send(method: 'GET' | 'POST', path: string, body?: unknown, auth = true): Promise<Raw> {
    const headers: Record<string, string> = auth && this.token ? { authorization: `Bearer ${this.token}` } : {};
    const res = await request(this.target(), method, `/api/v1/${path}`, headers, body);
    if (!this.o.fingerprint) {
      this.o.fingerprint = res.fingerprint;
      this.emit('fingerprint', res.fingerprint);
    }
    if (res.status === 401) throw new ApiError(`${path}: not signed in`, 401, 'auth');
    if (res.status === 403) throw new ApiError(`The switch refused ${path}: this account may not be allowed to do that`, 403, 'forbidden');
    let json: Raw;
    try {
      json = JSON.parse(res.body);
    } catch {
      throw new ApiError(res.status === 404 ? `The switch does not answer ${path}` : `Unexpected answer to ${path} (HTTP ${res.status})`, res.status);
    }
    const resp = json?.resp;
    const failed = res.status >= 400 || (resp && typeof resp.status === 'string' && resp.status !== 'success');
    if (failed) {
      const why = String(resp?.respMsg ?? `HTTP ${res.status}`);
      if (/denied|permission|privilege|not allowed|read.?only|forbidden/i.test(why)) throw new ApiError(`The switch refused ${path}: ${why}`, res.status, 'forbidden');
      if (/token|authentic|login|session|expire/i.test(why)) throw new ApiError(`${path}: ${why}`, res.status, 'auth');
      throw new ApiError(`${path}: ${why}`, res.status);
    }
    return json;
  }

  private async login(): Promise<void> {
    const l = this.o.login;
    if (!l) throw new ApiError('Needs a login: set it in the web view Setup page', 0, 'auth');
    this.token = '';
    let json: Raw;
    try {
      json = await this.send('POST', 'login', { login: { username: l.username, password: l.password } }, false);
    } catch (e) {
      if (e instanceof ApiError && e.status !== 404) throw new ApiError('The switch refused the username or password', e.status, 'auth');
      throw e instanceof ApiError ? new ApiError('No REST API answered on this port. Is it an AV Line switch with the API on?', e.status) : e;
    }
    const token = unwrap(json, 'login')?.token;
    if (typeof token !== 'string' || !token) throw new ApiError('The switch did not send a session token', 0, 'auth');
    this.token = token;
  }

  /** One request, logging in again once if the session has expired (a reboot, a timeout). */
  private async call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Raw> {
    if (!this.token) await this.login();
    try {
      return await this.send(method, path, body);
    } catch (e) {
      if (!(e instanceof ApiError && e.kind === 'auth')) throw e;
      await this.login();
      return this.send(method, path, body);
    }
  }

  private async list(path: string, ...keys: string[]): Promise<Raw[]> {
    return asList(unwrap(await this.call('GET', path), ...keys));
  }

  /** A read the switch may not support. Null when it does not; asked again only if `retry`. */
  private async optional(path: string, k1: string, k2: string, retry = false): Promise<Raw[] | null> {
    if (this.unsupported.has(path)) return null;
    try {
      const rows = asList(unwrap(await this.call('GET', path), k1, k2));
      this.answered.add(path);
      return rows;
    } catch (e) {
      if (e instanceof CertificateChanged || !(e instanceof ApiError) || e.kind !== 'api') throw e;
      if (!retry && !this.answered.has(path)) this.unsupported.add(path);
      return null;
    }
  }

  // ---- changes: only on operator action --------------------------------------------------------

  /** Runs changes one after another, never two at once on one switch. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.busy.then(fn, fn);
    this.busy = run.catch(() => {});
    return run;
  }

  private requireReady(): void {
    if (!this.ready) throw new ApiError('Not connected to the switch');
  }

  /** The port's settings as the switch reports them; writes send them back with one change. */
  private async portConfig(port: number): Promise<Raw> {
    const c = asList(unwrap(await this.call('GET', `swcfg_port?portid=${port}`), 'switchPortConfig', 'switch_port_config'))[0];
    if (!c) throw new ApiError(`The switch did not report port ${port}`);
    return { ...c, ID: c.ID ?? port };
  }

  private async membership(vlan: number): Promise<Raw> {
    const m = unwrap(await this.call('GET', `swcfg_vlan_membership?vlanid=${vlan}`), 'vlanMembership', 'vlan_membership');
    return m && typeof m === 'object' && !Array.isArray(m) ? m : { vlanid: vlan, portMembers: [] };
  }

  /**
   * Sets one port's membership of a VLAN. A write replaces the VLAN's whole membership, so it is
   * read first and sent back with only this port changed; lists the switch left out are sent empty.
   */
  private async setMembership(port: number, vlan: number, mode: VlanMode): Promise<void> {
    const cur = await this.membership(vlan);
    const members = (Array.isArray(cur.portMembers) ? cur.portMembers : []).filter((m: Raw) => Number(m.port) !== port);
    if (mode !== 'excluded') members.push({ port, tagged: mode === 'tagged' });
    const defaults = { lagMembers: [], trafficPrio: 0, trafficPrioPortMem: [], trafficPrioLagMem: [], pvidMembers: [] };
    await this.call('POST', 'swcfg_vlan_membership', { vlanMembership: { ...defaults, ...cur, vlanid: vlan, portMembers: members } });
  }

  /**
   * Makes a VLAN the port's untagged (access) VLAN: joins it untagged, sets it as the PVID, then
   * leaves the old untagged VLAN. Tagged VLANs on the port are kept. Stops at the first refusal.
   */
  async setAccessVlan(port: number, vlan: number): Promise<void> {
    return this.serial(async () => {
      this.requireReady();
      const cfg = await this.portConfig(port);
      const old = Number(cfg.portVlanId) || 0;
      if (old === vlan) return;
      await this.setMembership(port, vlan, 'untagged');
      await this.call('POST', `swcfg_port?portid=${port}`, { switchPortConfig: { ...cfg, portVlanId: vlan } });
      if (old) {
        const was = await this.membership(old);
        const entry = (Array.isArray(was.portMembers) ? was.portMembers : []).find((m: Raw) => Number(m.port) === port);
        if (entry && !entry.tagged) await this.setMembership(port, old, 'excluded');
      }
      await this.refresh();
    });
  }

  /** Turns a port on or off (admin mode). */
  async setPortEnabled(port: number, enabled: boolean): Promise<void> {
    return this.serial(async () => {
      this.requireReady();
      const cfg = await this.portConfig(port);
      await this.call('POST', `swcfg_port?portid=${port}`, { switchPortConfig: { ...cfg, adminMode: enabled } });
      await this.refresh();
    });
  }

  private async poeConfig(port: number): Promise<Raw> {
    const all = asList(unwrap(await this.call('GET', `swcfg_poe?portid=${port}`), 'poePortConfig', 'poe_port_config'));
    const c = all.find((x) => Number(x.portid) === port) ?? all[0];
    if (!c) throw new ApiError(`Port ${port} has no PoE`);
    return c;
  }

  /** PoE on or off. The switch wants the port's whole PoE record back, without the port id. */
  async setPoe(port: number, enable: boolean): Promise<void> {
    return this.serial(async () => {
      this.requireReady();
      const { portid: _id, ...c } = await this.poeConfig(port);
      await this.call('POST', `swcfg_poe?portid=${port}`, { poePortConfig: { ...c, enable } });
      await this.refresh();
    });
  }

  /** Cuts PoE on the port for a moment so the device restarts. */
  async cyclePoe(port: number): Promise<void> {
    return this.serial(async () => {
      this.requireReady();
      const { portid: _id, ...c } = await this.poeConfig(port);
      await this.call('POST', `swcfg_poe?portid=${port}`, { poePortConfig: { ...c, reset: true } });
      await this.refresh();
    });
  }

  /** Copies the running config to the startup config, so changes survive a reboot. */
  async saveConfig(): Promise<void> {
    return this.serial(async () => {
      this.requireReady();
      await this.call('POST', 'config_copy?directive=rtos');
    });
  }
}
