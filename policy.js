// Step-up policy and presentation/injection attack scoring for helpdesk identity
// verification.
//
// The threat model is specific: an attacker calls the service desk claiming to
// be an employee who is locked out, and asks for a password or MFA reset. The
// agent is the vulnerability. Everything here exists to give the agent a signal
// that does not depend on their judgment under social pressure.

export const ACTIONS = {
  password_reset: { label: 'Password reset', assurance: 2, blast: 'Account access' },
  mfa_reset: { label: 'MFA / passkey reset', assurance: 3, blast: 'Bypasses second factor' },
  email_change: { label: 'Recovery email change', assurance: 3, blast: 'Account takeover primitive' },
  privileged_grant: { label: 'Privileged role grant', assurance: 4, blast: 'Tenant-wide' },
  device_enroll: { label: 'New device enrolment', assurance: 3, blast: 'Persistent access' },
};

// Signals a verification session can produce, with the assurance each one buys.
export const SIGNALS = {
  gov_id_mrz_valid: { label: 'Government ID — MRZ check digits valid', weight: 1.0, kind: 'document' },
  gov_id_chip_read: { label: 'NFC chip read, passive authentication', weight: 1.6, kind: 'document' },
  face_match: { label: 'Selfie matches document portrait', weight: 1.2, kind: 'biometric' },
  liveness_passive: { label: 'Passive liveness', weight: 0.8, kind: 'biometric' },
  liveness_active: { label: 'Active liveness challenge', weight: 1.1, kind: 'biometric' },
  device_attested: { label: 'Hardware-attested device key', weight: 1.5, kind: 'cryptographic' },
  device_known: { label: 'Device previously bound to this identity', weight: 1.0, kind: 'cryptographic' },
  hr_record_match: { label: 'Matches HR record of employment', weight: 0.9, kind: 'directory' },
  manager_approval: { label: 'Out-of-band manager approval', weight: 1.0, kind: 'human' },
};

// Attack indicators subtract assurance. These are the ones that actually matter
// in 2026: a printed photo is a solved problem, a synthetic face injected into a
// virtual camera is not.
export const ATTACKS = {
  screen_replay: { label: 'Screen replay — moiré and refresh banding', penalty: 3.0 },
  print_attack: { label: 'Print attack — paper texture, no depth', penalty: 3.0 },
  virtual_camera: { label: 'Virtual camera device in the capture chain', penalty: 4.0 },
  injection_no_sensor: { label: 'Frames lack sensor noise fingerprint', penalty: 3.5 },
  deepfake_temporal: { label: 'Temporal inconsistency across frames', penalty: 3.2 },
  doc_font_mismatch: { label: 'Document font does not match issuer template', penalty: 2.6 },
  doc_portrait_substituted: { label: 'Portrait region resampled — substitution', penalty: 3.4 },
  mrz_checksum_fail: { label: 'MRZ check digit mismatch', penalty: 3.0 },
  emulator: { label: 'Emulated OS / rooted device', penalty: 2.2 },
  geo_impossible: { label: 'Impossible travel since last auth', penalty: 1.6 },
};

/**
 * Score a session: assurance earned minus attack penalties, compared against the
 * assurance the requested action demands.
 */
export function scoreSession(session) {
  let earned = 0;
  const earnedDetail = [];
  for (const s of session.signals) {
    const def = SIGNALS[s];
    if (!def) continue;
    earned += def.weight;
    earnedDetail.push({ id: s, ...def });
  }

  let penalty = 0;
  const attackDetail = [];
  for (const a of session.attacks) {
    const def = ATTACKS[a];
    if (!def) continue;
    penalty += def.penalty;
    attackDetail.push({ id: a, ...def });
  }

  const net = earned - penalty;
  const action = ACTIONS[session.action];
  const required = action.assurance;

  // Any single high-severity attack indicator is disqualifying regardless of how
  // much assurance was otherwise collected — you cannot out-vote an injection.
  const hardFail = attackDetail.some((a) => a.penalty >= 3.0);

  let verdict;
  if (hardFail) verdict = 'DENY';
  else if (net >= required) verdict = 'ALLOW';
  else if (net >= required - 1.2) verdict = 'STEP_UP';
  else verdict = 'DENY';

  return {
    earned, penalty, net, required, verdict, hardFail,
    earnedDetail, attackDetail,
    // What else would close the gap, cheapest first.
    remedies: verdict === 'ALLOW' || hardFail
      ? []
      : Object.entries(SIGNALS)
          .filter(([id]) => !session.signals.includes(id))
          .map(([id, d]) => ({ id, ...d }))
          .sort((a, b) => b.weight - a.weight)
          .filter((r) => net + r.weight >= required)
          .slice(0, 3),
  };
}
