// jcs_leg.mjs — Node-native JCS (RFC 8785) leg for tests/threeway.py.
//
// Built from Node natives only (no deps): recursive UTF-16 code-unit key sort
// + JSON.stringify (ES number repr, minimal escaping). RFC 8785-faithful for
// the threeway.py vector set; NOT a general-purpose JCS library (exotic
// exponent ranges beyond this vector set are unvalidated — see
// ops/plans/TICKET_CANONICAL_FORMS_RESPONSE_2026-07-03.md §6d).
//
// Protocol: one JSON text per stdin line (the vector's Form-A bytes, so the
// real cross-language round-trip shows — JSON.parse here is exactly the
// "naive JS round-trip" that silently corrupts 10**24 to 1e+24). One result
// per line on stdout:
//   OK <canonical JSON, UTF-8>
//   REJECTED <ErrorName>: <message>
//
// Line-based framing is safe: minimal-form JSON contains no raw newlines.

import { createInterface } from 'node:readline';

function sortKeysDeep(v) {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v !== null && typeof v === 'object') {
    const out = {};
    // Default Array.prototype.sort on strings compares UTF-16 code units —
    // exactly the JCS (RFC 8785 §3.2.3) member ordering.
    for (const k of Object.keys(v).sort()) out[k] = sortKeysDeep(v[k]);
    return out;
  }
  return v;
}

const rl = createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const canonical = JSON.stringify(sortKeysDeep(JSON.parse(line)));
    process.stdout.write(Buffer.concat([
      Buffer.from('OK ', 'ascii'),
      Buffer.from(canonical, 'utf8'),
      Buffer.from('\n', 'ascii'),
    ]));
  } catch (e) {
    process.stdout.write(`REJECTED ${e.name}: ${e.message}\n`);
  }
});
