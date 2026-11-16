#!/usr/bin/env node
// npm run mock -- [--port 8443] [--password password1] [--other-cert]
// Starts three pretend AV Line switches on consecutive ports (FOH M4250-26G4F-PoE+, Stage
// M4250-10G2F-PoE+, Core M4350-24X4V) and an NSDP responder for the first one on UDP 63322.
// Log in as admin with the password. To have Discover find them in the simulator, start it with
//   RCS_NETGEAR_SCAN=127.0.0.1:8443,127.0.0.1:8444,127.0.0.1:8445 RCS_NETGEAR_NSDP=127.0.0.1:63322 npm run dev

import { parseArgs } from 'node:util';
import { MockSwitch } from './mock.js';

const { values } = parseArgs({
  options: {
    port: { type: 'string', default: '8443' },
    host: { type: 'string', default: '127.0.0.1' },
    nsdp: { type: 'string', default: '63322' },
    password: { type: 'string', default: 'password1' },
    'other-cert': { type: 'boolean', default: false }
  }
});

const base = Number(values.port);
const specs = [
  { name: 'SW-FOH', model: 'M4250-26G4F-PoE+', mac: '28:94:01:AA:00:01' },
  { name: 'SW-Stage', model: 'M4250-10G2F-PoE+', mac: '28:94:01:AA:00:02', seed: [20, 21, 20, 21, 40, 40, 50, 60, 30, 10] },
  { name: 'SW-Core', model: 'M4350-24X4V', mac: '28:94:01:AA:00:03', seed: [10, 10, 30, 30, 60, 60, 1, 1] }
] as const;

const mocks: MockSwitch[] = [];
for (const [i, s] of specs.entries()) {
  const m = new MockSwitch({ ...s, password: values.password, otherCertificate: values['other-cert'], bulkPortConfig: i === 2, ip: values.host });
  const port = await m.listen(base + i, values.host);
  mocks.push(m);
  console.log(`Mock ${s.model} "${s.name}" on https://${values.host}:${port}`);
}
await mocks[0]!.listenNsdp(Number(values.nsdp), values.host);
console.log(`NSDP answers for ${specs[0].name} on udp ${values.host}:${values.nsdp}. Log in as admin / ${values.password}.`);

const last = mocks.map(() => 0);
setInterval(() => {
  mocks.forEach((m, i) => {
    if (m.changes.length !== last[i]) console.log(`${m.name}: ${m.changes.length} change(s); last: ${JSON.stringify(m.changes.at(-1))}`);
    last[i] = m.changes.length;
  });
}, 500);
