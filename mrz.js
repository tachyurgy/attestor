// ICAO 9303 Machine Readable Zone parsing and check-digit validation.
//
// This is the real algorithm, not a stand-in: weights cycle 7-3-1 across the
// field, letters map A=10..Z=35, filler '<' is 0, and the check digit is the sum
// modulo 10. A tampered document usually survives a visual inspection and fails
// here, which is why the MRZ check is the cheapest high-signal test in the stack.

const WEIGHTS = [7, 3, 1];

export function charValue(c) {
  if (c === '<') return 0;
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55; // A -> 10
  return NaN;
}

export function checkDigit(field) {
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    const v = charValue(field[i]);
    if (Number.isNaN(v)) return null;
    sum += v * WEIGHTS[i % 3];
  }
  return sum % 10;
}

export function verifyField(field, expected) {
  const computed = checkDigit(field);
  return { field, expected, computed, ok: computed !== null && String(computed) === String(expected) };
}

/**
 * Parse a TD3 passport MRZ (2 lines x 44 chars) and validate every check digit,
 * including the composite digit that covers the whole lower line.
 */
export function parseTD3(line1, line2) {
  const l1 = line1.padEnd(44, '<').slice(0, 44);
  const l2 = line2.padEnd(44, '<').slice(0, 44);

  const docType = l1.slice(0, 2).replace(/</g, '');
  const issuer = l1.slice(2, 5).replace(/</g, '');
  const names = l1.slice(5).split('<<');
  const surname = (names[0] || '').replace(/</g, ' ').trim();
  const given = (names[1] || '').replace(/</g, ' ').trim();

  const docNumber = l2.slice(0, 9);
  const docNumberCd = l2[9];
  const nationality = l2.slice(10, 13).replace(/</g, '');
  const dob = l2.slice(13, 19);
  const dobCd = l2[19];
  const sex = l2[20];
  const expiry = l2.slice(21, 27);
  const expiryCd = l2[27];
  const optional = l2.slice(28, 42);
  const optionalCd = l2[42];
  const compositeCd = l2[43];

  // The composite covers doc number + its CD, DOB + its CD, expiry + its CD,
  // and the optional field + its CD, concatenated.
  const compositeField =
    l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 28) + l2.slice(28, 43);

  const checks = [
    { name: 'Document number', ...verifyField(docNumber, docNumberCd) },
    { name: 'Date of birth', ...verifyField(dob, dobCd) },
    { name: 'Expiry date', ...verifyField(expiry, expiryCd) },
    { name: 'Optional data', ...verifyField(optional, optionalCd) },
    { name: 'Composite', ...verifyField(compositeField, compositeCd) },
  ];

  return {
    docType, issuer, surname, given, docNumber: docNumber.replace(/</g, ''),
    nationality, dob: fmtDate(dob), sex, expiry: fmtDate(expiry),
    optional: optional.replace(/</g, ''),
    checks,
    valid: checks.every((c) => c.ok),
    lines: [l1, l2],
  };
}

function fmtDate(yymmdd) {
  if (!/^\d{6}$/.test(yymmdd)) return yymmdd;
  const yy = +yymmdd.slice(0, 2), mm = yymmdd.slice(2, 4), dd = yymmdd.slice(4, 6);
  // ICAO has no century; the usual convention pivots on the current year.
  const year = yy > 40 ? 1900 + yy : 2000 + yy;
  return `${year}-${mm}-${dd}`;
}

/** Build a valid TD3 MRZ, used to generate the demo's clean documents. */
export function buildTD3({ issuer, surname, given, docNumber, nationality, dob, sex, expiry, optional = '' }) {
  const nameField = `${surname}<<${given.replace(/ /g, '<')}`.padEnd(39, '<').slice(0, 39);
  const l1 = `P<${issuer}${nameField}`;
  const dn = docNumber.padEnd(9, '<').slice(0, 9);
  const opt = optional.padEnd(14, '<').slice(0, 14);
  const p1 = `${dn}${checkDigit(dn)}${nationality}${dob}${checkDigit(dob)}${sex}${expiry}${checkDigit(expiry)}${opt}${checkDigit(opt)}`;
  const composite = `${dn}${checkDigit(dn)}${dob}${checkDigit(dob)}${expiry}${checkDigit(expiry)}${opt}${checkDigit(opt)}`;
  return [l1.padEnd(44, '<'), `${p1}${checkDigit(composite)}`];
}
