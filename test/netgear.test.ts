import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startTestModule, type TestModule } from '@rcs/module-sdk/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SwitchClient } from '../src/client.js';
import { nsdpRequest, nsdpSearch, parseNsdp, scan, subnetHosts } from '../src/discovery.js';
import mod, { KEY, type Config, type State } from '../src/index.js';
import { MockSwitch, type MockOptions } from '../src/mock.js';
import { frontPanel, parsePorts, portNumber, speedOf, unwrap } from '../src/model.js';

let mocks: MockSwitch[] = [];
let sim: TestModule<State, Config> | null = null;
let client: SwitchClient | null = null;

afterEach(async () => {
  await sim?.close();
  client?.stop();
  for (const m of mocks) await m.close();
  sim = null;
  client = null;
  mocks = [];
  delete process.env.RCS_NETGEAR_NSDP;
  delete process.env.RCS_NETGEAR_SCAN;
});

async function until(check: () => boolean, ms = 5000, what = ''): Promise<void> {
  const end = performance.now() + ms;
  while (!check()) {
    if (performance.now() > end) {
      const snap = sim ? last() : null;
      throw new Error(`timed out ${what} (${snap ? JSON.stringify(snap.switches.map((s: any) => [s.name, s.connection, s.statusText])) + ' errors ' + sim!.errors.map(String) : client ? `${client.connection} ${client.statusText}` : ''})`);
    }
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function startMock(opts: MockOptions = {}): Promise<{ mock: MockSwitch; port: number }> {
  const mock = new MockSwitch({ password: 'pw', ...opts });
  mocks.push(mock);
  return { mock, port: await mock.listen(0) };
}

const entry = (id: string, port: number) => ({ id, address: '127.0.0.1', port, fingerprint: '', label: '' });

async function startModule(
  ports: number[],
  extra: { allow?: boolean; state?: State; reason?: 'boot' | 'restore' | 'user'; verifyPin?: (r: string, c?: string) => boolean; login?: boolean; deck?: { columns: number; rows: number } } = {}
) {
  const config: Config = { switches: ports.map((p, i) => entry(`0000000${i + 1}`, p)), allowChanges: extra.allow ?? false };
  sim = await startTestModule(mod, { config, state: extra.state, reason: extra.reason, verifyPin: extra.verifyPin, deck: extra.deck });
  await sim.settle();
  await until(() => sim!.strip.length > 0);
  if (extra.login !== false) {
    // The test controller starts with no secrets: give the shared login as the web view would.
    await sim.sendUi({ type: 'credentials', which: 'shared', username: 'admin', password: 'pw' });
    await until(() => last()?.switches.every((s: any) => s.ready), 6000, 'for the switches');
    await sim.settle();
  }
  return sim;
}

const last = () => [...sim!.uiMessages].reverse().find((m) => m.message?.type === 'snapshot')?.message;
const writes = (m: MockSwitch) => m.changes;

describe('model', () => {
  it('reads port ids in their different spellings and skips LAGs', () => {
    expect([9, '9', '0/9', '1/0/9', '3/1', 'lag 1', 0, '2/0/9'].map(portNumber)).toEqual([9, 9, 9, 9, null, null, null, null]);
  });

  it('reads link speed codes', () => {
    expect([7, 8, 128, '7', '10G', '2.5G', 1].map(speedOf)).toEqual([1000, 10000, 2500, 1000, 10000, 2500, 0]);
  });

  it('lays ports out like the front panel: odd on top, even below; small switches in one row', () => {
    expect(frontPanel([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])).toEqual([
      [1, 3, 5, 7, 9, 11],
      [2, 4, 6, 8, 10, 12]
    ]);
    expect(frontPanel([1, 2, 3, 4, 5, 6, 7, 8])).toEqual([[1, 2, 3, 4, 5, 6, 7, 8]]);
  });

  it('joins statistics, settings, PoE and LLDP by port, tolerating snake_case and odd shapes', () => {
    expect(unwrap({ resp: {}, device_info: { a: 1 } }, 'deviceInfo')).toEqual({ a: 1 });
    const ports = parsePorts(
      [{ portId: '0/1', status: 0, speed: 7, vlans: [10, 20], rxMbps: '12.5', txMbps: '3' }, { portId: 2, status: 1, speed: 1, vlans: [20] }, { portId: 'lag 1', status: 0, speed: 129 }],
      [{ ID: 1, description: 'Camera', adminMode: true, portVlanId: 20 }],
      [{ portid: 1, enable: true, status: 2, currentPower: 6400 }],
      [{ ifIndex: 1, remoteSysName: 'cam-1', remotePortId: 'eth0' }],
      []
    );
    expect(ports).toHaveLength(2);
    expect(ports[0]).toMatchObject({ idx: 1, name: 'Camera', up: true, speed: 1000, pvid: 20, vlans: [10, 20], rx: 12.5, poe: { enabled: true, status: 'Delivering', watts: 6.4 }, neighbor: 'cam-1' });
    expect(ports[1]).toMatchObject({ idx: 2, up: false, speed: 0, pvid: 20, poe: null });
  });
});

describe('discovery', () => {
  it('makes and reads NSDP packets', () => {
    const req = nsdpRequest(Buffer.from([1, 2, 3, 4, 5, 6]), 7);
    expect(req.toString('ascii', 24, 28)).toBe('NSDP');
    expect(req[1]).toBe(1);
    expect(req.subarray(-4)).toEqual(Buffer.from([0xff, 0xff, 0, 0]));
    expect(parseNsdp(req)).toBeNull(); // a request, not an answer
  });

  it('finds a switch by NSDP and by its API port', async () => {
    const { mock, port } = await startMock();
    const udp = await mock.listenNsdp(0);
    const found = await nsdpSearch({ targets: ['127.0.0.1'], ports: [udp], localPorts: [0], waitMs: 300 });
    expect(found).toEqual([{ address: '127.0.0.1', model: 'M4250-26G4F-PoE+', name: 'SW-FOH', mac: '28:94:01:AA:00:01', firmware: '13.0.4.26' }]);
    const scanned = await scan({ hosts: ['127.0.0.1'], port });
    expect(scanned).toEqual([{ address: '127.0.0.1', port, subject: 'Mock AV Line switch mock.netgear.test' }]);
    expect(mock.requests).toEqual([]); // the scan sends no request
  });

  it('lists the hosts of small subnets only', () => {
    expect(subnetHosts('10.0.0.5', '255.255.255.252')).toEqual(['10.0.0.6']);
    expect(subnetHosts('10.0.0.5', '255.255.255.0')).toHaveLength(253);
    expect(subnetHosts('10.0.0.5', '255.255.0.0')).toEqual([]);
  });
});

describe('client', () => {
  it('logs in, reads the switch, pins its certificate and sends nothing but reads', async () => {
    const { mock, port } = await startMock();
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: '', login: { username: 'admin', password: 'pw' } });
    let pinned = '';
    client.on('fingerprint', (fp) => (pinned = fp));
    client.start();
    await until(() => client!.ready);
    expect(pinned).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    const v = client.view;
    expect(v.info).toMatchObject({ name: 'SW-FOH', model: 'M4250-26G4F-PoE+', poeBudget: 480, temp: 46 });
    expect(v.ports).toHaveLength(30);
    expect(v.ports[0]).toMatchObject({ idx: 1, name: 'Camera 1', up: true, pvid: 20, poe: { enabled: true, status: 'Delivering' } });
    expect(v.ports[13]).toMatchObject({ idx: 14, enabled: false, up: false });
    expect(v.vlans.map((x) => x.name)).toEqual(['default', 'Mgmt', 'Dante Pri', 'Dante Sec', 'NDI', 'sACN', 'Control', 'LED']);
    expect(v.ports[26]).toMatchObject({ idx: 27, sfp: true, vlans: [1, 10, 20, 21, 30, 40, 50, 60] });
    expect(writes(mock)).toEqual([]);
    // Per-port settings, since this firmware does not answer portid=ALL.
    expect(mock.requests).toContain('GET swcfg_port?portid=30');
  });

  it('reads every port setting at once where the firmware allows it', async () => {
    const { mock, port } = await startMock({ bulkPortConfig: true, model: 'M4350-24X4V' });
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: '', login: { username: 'admin', password: 'pw' } });
    client.start();
    await until(() => client!.ready);
    expect(client.view.ports).toHaveLength(28);
    expect(client.view.info?.poeBudget).toBeNull();
    expect(mock.requests.filter((r) => r.startsWith('GET swcfg_port?portid=') && !r.endsWith('ALL'))).toEqual([]);
  });

  it('says so when the password is wrong, and does not hammer the switch', async () => {
    const { mock, port } = await startMock();
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: '', login: { username: 'admin', password: 'nope' }, retryMs: 50 });
    client.start();
    await until(() => client!.statusText.includes('refused'));
    await new Promise((r) => setTimeout(r, 300));
    expect(mock.requests.filter((r) => r === 'POST login')).toHaveLength(1);
  });

  it('stops when the certificate changes', async () => {
    const { port } = await startMock({ otherCertificate: true });
    const { port: p2 } = await startMock();
    const good = new SwitchClient({ host: '127.0.0.1', port: p2, fingerprint: '', login: { username: 'admin', password: 'pw' } });
    good.start();
    await until(() => good.ready);
    const fp = good.fingerprint;
    good.stop();
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: fp, login: { username: 'admin', password: 'pw' } });
    client.start();
    await until(() => !!client!.certificateSeen);
    expect(client.certificateSeen).not.toBe(fp);
    expect(mocks[0]!.requests).toEqual([]); // no password went to it
  });

  it('moves a port to another access VLAN, keeping its tagged VLANs', async () => {
    const { mock, port } = await startMock();
    mock.members.get(60)!.set(1, true); // port 1 also carries LED tagged
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: '', login: { username: 'admin', password: 'pw' } });
    client.start();
    await until(() => client!.ready);
    await client.setAccessVlan(1, 30);
    expect(mock.portState.get(1)!.pvid).toBe(30);
    expect(mock.members.get(30)!.get(1)).toBe(false); // untagged
    expect(mock.members.get(20)!.has(1)).toBe(false); // left the old one
    expect(mock.members.get(60)!.get(1)).toBe(true); // tagged kept
    expect(mock.members.get(20)!.has(2)).toBe(true); // other ports untouched
    expect(client.view.ports[0]).toMatchObject({ pvid: 30, vlans: [30, 60] });
    expect(mock.saved).toBe(0);
  });

  it('turns PoE off, power cycles, shuts a port and saves the config', async () => {
    const { mock, port } = await startMock();
    client = new SwitchClient({ host: '127.0.0.1', port, fingerprint: '', login: { username: 'admin', password: 'pw' } });
    client.start();
    await until(() => client!.ready);
    await client.setPoe(2, false);
    expect(mock.portState.get(2)!.poe!.enable).toBe(false);
    await client.cyclePoe(3);
    expect(writes(mock).at(-1)).toMatchObject({ path: 'swcfg_poe?portid=3', body: { poePortConfig: { reset: true } } });
    await client.setPortEnabled(5, false);
    expect(mock.portState.get(5)!.adminMode).toBe(false);
    expect(client.view.ports[4]).toMatchObject({ enabled: false, up: false });
    await client.saveConfig();
    expect(mock.saved).toBe(1);
  });
});

describe('module', () => {
  it('reads two switches on start, from any reason, without changing anything', async () => {
    const a = await startMock();
    const b = await startMock({ name: 'SW-Stage', model: 'M4250-10G2F-PoE+' });
    for (const reason of ['boot', 'restore'] as const) {
      await startModule([a.port, b.port], { reason, allow: true, state: { sw: '00000002', selPort: 3 } });
      const s = last();
      expect(s.switches.map((x: any) => [x.name, x.portCount, x.login])).toEqual([
        ['SW-FOH', 30, 'shared'],
        ['SW-Stage', 12, 'shared']
      ]);
      expect(s.detail.layout).toEqual([[1, 3, 5, 7, 9, 11], [2, 4, 6, 8, 10, 12]]);
      expect(sim!.status?.connection).toBe('connected');
      await sim!.close();
      sim = null;
    }
    expect(writes(a.mock)).toEqual([]);
    expect(writes(b.mock)).toEqual([]);
  });

  it('sends every switch\'s ports for a tall panel, and a tap there picks the switch and port', async () => {
    const a = await startMock();
    const b = await startMock({ name: 'SW-Stage', model: 'M4250-10G2F-PoE+' });
    await startModule([a.port, b.port], { allow: true, state: { sw: '00000001', selPort: 1 } });
    await sim!.sendUi({ type: 'pick-vlan', vlan: 30 });
    expect(last().pending.length).toBe(1);
    const s = last();
    expect(s.all.map((d: any) => [d.name, d.ports.length])).toEqual([
      ['SW-FOH', 30],
      ['SW-Stage', 12]
    ]);
    expect(s.all[0].ports[0].poe.class).toBe(4);
    expect(s.all[0].ports.find((p: any) => p.optic)?.optic).toMatchObject({ vendor: 'NETGEAR', part: 'AXM763', temp: 38.2 });
    await sim!.sendUi({ type: 'select-port', id: '00000002', idx: 5 });
    const t = last();
    expect([t.current, t.selPort, t.pending]).toEqual(['00000002', 5, []]); // unsaved picks belong to one switch
    expect(Array.isArray(t.selHistory)).toBe(true);
    expect(writes(a.mock)).toEqual([]);
    expect(writes(b.mock)).toEqual([]);
  });

  it('keeps logins out of config and state, in the module secrets', async () => {
    const a = await startMock();
    await startModule([a.port]);
    expect(JSON.stringify(sim!.config)).not.toContain('pw');
    expect(JSON.stringify(sim!.state)).not.toContain('pw');
    expect(sim!.config.switches[0]!.fingerprint).toMatch(/:/); // pinned
    expect(sim!.secrets).toEqual({ shared: { username: 'admin', password: 'pw' }, perSwitch: {} });
    expect(JSON.stringify(sim!.uiMessages)).not.toContain('"pw"');
  });

  it('keeps credentials.json on a controller without secrets', async () => {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), 'netgear-old-host-'));
    const login = { username: 'admin', password: 'pw' };
    await writeFile(path.join(dataDir, 'credentials.json'), JSON.stringify({ shared: login, perSwitch: {} }));
    sim = await startTestModule(mod, { config: { switches: [], allowChanges: false }, dataDir, noSecrets: true });
    await until(() => sim!.strip.length > 0);
    expect(last().shared).toBe('admin');
    expect(JSON.parse(await readFile(path.join(dataDir, 'credentials.json'), 'utf8'))).toEqual({ shared: login, perSwitch: {} });
    expect(sim.errors).toEqual([]);
  });

  it('moves credentials.json from an older version into the secrets', async () => {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), 'netgear-legacy-'));
    const login = { username: 'admin', password: 'pw' };
    await writeFile(path.join(dataDir, 'credentials.json'), JSON.stringify({ shared: login, perSwitch: { abc: login } }));
    sim = await startTestModule(mod, { config: { switches: [], allowChanges: false }, dataDir });
    await until(() => sim!.strip.length > 0); // drawn after the logins are loaded
    expect(sim.secrets).toEqual({ shared: login, perSwitch: { abc: login } });
    await expect(readFile(path.join(dataDir, 'credentials.json'))).rejects.toThrow();
  });

  it('stages VLANs on the keys and applies them only on a held SAVE', async () => {
    const a = await startMock();
    await startModule([a.port], { allow: true });
    await sim!.tapStrip('ports');
    await sim!.sendUi({ type: 'select-port', idx: 1 });
    expect(sim!.keys[2]?.background).toBeTruthy(); // Dante Pri (20) is lit
    await sim!.press(4); // NDI (30)
    await sim!.press(KEY.NEXT);
    await sim!.press(6); // Control (50) for port 2
    expect(last().pending).toEqual([[1, 30], [2, 50]]);
    expect(sim!.keys[KEY.SAVE]?.sublabel).toBe('2 · hold');
    await sim!.press(KEY.SAVE); // a tap does nothing
    expect(writes(a.mock)).toEqual([]);
    await sim!.press(KEY.SAVE, { holdMs: 750 });
    await until(() => a.mock.portState.get(2)!.pvid === 50);
    expect(a.mock.portState.get(1)!.pvid).toBe(30);
    await until(() => last().pending.length === 0);
    await until(() => last().switches[0].unsaved === true);
    await sim!.sendUi({ type: 'save-config', id: '00000001' });
    await until(() => last().switches[0].unsaved === false);
    expect(a.mock.saved).toBe(1);
  });

  it('puts the port keys on the bottom row of an XL', async () => {
    const a = await startMock();
    await startModule([a.port], { allow: true, deck: { columns: 8, rows: 4 } });
    expect(sim!.keys[5]?.label).toBeTruthy(); // the switch, after the view keys
    await sim!.tapStrip('ports');
    await sim!.sendUi({ type: 'select-port', idx: 1 });
    expect(sim!.keys).toHaveLength(32);
    expect(sim!.keys[24]).toMatchObject({ label: '◀ PORT' });
    expect(sim!.keys[25]).toMatchObject({ label: 'PORT ▶' });
    await sim!.press(4); // NDI (30)
    expect(sim!.keys[31]).toMatchObject({ label: 'SAVE', sublabel: '1 · hold' });
    await sim!.press(31, { holdMs: 750 });
    await until(() => a.mock.portState.get(1)!.pvid === 30);
  });

  it('changes nothing with Allow changes off', async () => {
    const a = await startMock();
    await startModule([a.port]);
    await sim!.tapStrip('ports');
    await sim!.press(4);
    await sim!.press(KEY.SAVE, { holdMs: 750 });
    await sim!.press(KEY.POE, { holdMs: 750 });
    await sim!.sendUi({ type: 'poe', id: '00000001', idx: 1, on: false });
    await sim!.sendUi({ type: 'port-enabled', id: '00000001', idx: 1, on: false });
    await sim!.sendUi({ type: 'apply-vlans', id: '00000001', changes: [{ idx: 1, vlan: 30 }] });
    await sim!.sendUi({ type: 'save-config', id: '00000001' });
    expect(writes(a.mock)).toEqual([]);
    expect(sim!.notifications.some((n) => n.text.includes('only reads'))).toBe(true);
    expect(sim!.keys[KEY.SAVE]?.label).toBe('VIEW ONLY');
  });

  it('turns PoE off on a held key and applies web VLAN picks for its own switch', async () => {
    const a = await startMock();
    const b = await startMock({ name: 'SW-Stage', model: 'M4250-10G2F-PoE+' });
    await startModule([a.port, b.port], { allow: true });
    await sim!.tapStrip('ports');
    await sim!.sendUi({ type: 'select-port', idx: 2 });
    await sim!.press(KEY.POE, { holdMs: 750 });
    await until(() => a.mock.portState.get(2)!.poe!.enable === false);
    // The web view applies to the switch it shows, not the panel's.
    await sim!.sendUi({ type: 'apply-vlans', id: '00000002', changes: [{ idx: 3, vlan: 60 }] }, 'web-1');
    await until(() => b.mock.portState.get(3)!.pvid === 60);
    await until(() => sim!.uiMessages.some((m) => m.message?.type === 'applied'));
    expect(sim!.uiMessages.some((m) => m.message?.type === 'applied' && m.clientId === 'web-1')).toBe(true);
    expect(last().current).toBe('00000001');
  });

  it('shows a stored password only after the PIN, and only to the client that asked', async () => {
    const a = await startMock();
    let answer = false;
    await startModule([a.port], { verifyPin: () => answer });
    await sim!.sendUi({ type: 'reveal', which: 'shared' }, 'web-1');
    expect(sim!.pinRequests).toHaveLength(1);
    expect(sim!.uiMessages.some((m) => m.message?.type === 'reveal')).toBe(false);
    answer = true;
    await sim!.sendUi({ type: 'reveal', which: 'shared' }, 'web-1');
    const r = sim!.uiMessages.filter((m) => m.message?.type === 'reveal');
    expect(r).toEqual([{ clientId: 'web-1', message: { type: 'reveal', which: 'shared', username: 'admin', password: 'pw' } }]);
  });

  it('finds switches, adds one, gives it its own login and removes it', async () => {
    const a = await startMock();
    const udp = await a.mock.listenNsdp(0);
    process.env.RCS_NETGEAR_NSDP = `127.0.0.1:${udp}`;
    process.env.RCS_NETGEAR_SCAN = `127.0.0.1:${a.port}`;
    await startModule([], { login: false });
    await sim!.tapStrip('discover'); // opening Discover searches
    await until(() => last()?.found.length === 1 && !last().searching);
    await sim!.sendUi({ type: 'search', how: 'scan' });
    await until(() => !last().searching);
    expect(last().found).toEqual([{ address: '127.0.0.1', apiPort: a.port, model: 'M4250-26G4F-PoE+', name: 'SW-FOH', mac: '28:94:01:AA:00:01', firmware: '13.0.4.26', via: ['nsdp', 'scan'] }]);
    await sim!.press(5); // add it
    expect(sim!.config.switches).toHaveLength(1);
    expect(sim!.config.switches[0]).toMatchObject({ address: '127.0.0.1', port: a.port, label: 'SW-FOH' });
    await until(() => last().switches[0].statusText.includes('Needs a login'));
    const id = sim!.config.switches[0]!.id;
    await sim!.sendUi({ type: 'credentials', which: id, username: 'admin', password: 'pw' });
    await until(() => last().switches[0].ready);
    expect(last().switches[0].login).toBe('own');
    await sim!.sendUi({ type: 'add', address: '127.0.0.1', port: a.port });
    expect(sim!.config.switches).toHaveLength(1); // no duplicates
    await sim!.sendUi({ type: 'add', address: 'not an address!' });
    expect(sim!.config.switches).toHaveLength(1);
    await sim!.sendUi({ type: 'remove', id });
    expect(sim!.config.switches).toEqual([]);
    await sim!.settle();
    await new Promise((r) => setTimeout(r, 100));
    expect(sim!.secrets.perSwitch).toEqual({});
    expect(writes(a.mock)).toEqual([]);
  });
});
