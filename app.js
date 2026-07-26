import { parseTD3, buildTD3, checkDigit } from './mrz.js';
import { ACTIONS, SIGNALS, ATTACKS, scoreSession } from './policy.js';

const $ = (s) => document.querySelector(s);

// Three sessions that make the distinction the product exists for: a legitimate
// locked-out employee, a social-engineering call with a tampered document, and a
// well-resourced injection attack that defeats naive liveness.
const SESSIONS = [
  {
    id: 'VS-40218',
    claim: 'Adaeze Nwachukwu',
    role: 'Staff Engineer, Platform',
    action: 'mfa_reset',
    channel: 'Service desk — inbound call',
    agent: 'agent.rmcgrath',
    signals: ['gov_id_mrz_valid', 'gov_id_chip_read', 'face_match', 'liveness_active', 'device_attested', 'hr_record_match'],
    attacks: [],
    mrz: buildTD3({ issuer: 'USA', surname: 'NWACHUKWU', given: 'ADAEZE C', docNumber: 'X4471902', nationality: 'USA', dob: '910417', sex: 'F', expiry: '310912' }),
    note: 'Locked out after a phone upgrade. Chip read succeeded, device attested with a hardware key.',
  },
  {
    id: 'VS-40219',
    claim: 'Bartholomew Kryszewski',
    role: 'Director, Finance',
    action: 'email_change',
    channel: 'Service desk — inbound call',
    agent: 'agent.dlindfors',
    signals: ['gov_id_mrz_valid', 'face_match', 'liveness_passive'],
    attacks: ['doc_font_mismatch', 'doc_portrait_substituted', 'geo_impossible'],
    // Portrait swapped onto a real template. The MRZ was re-typed by hand and the
    // composite check digit was not recomputed.
    mrz: (() => {
      const good = buildTD3({ issuer: 'USA', surname: 'KRYSZEWSKI', given: 'BARTHOLOMEW J', docNumber: 'M8830145', nationality: 'USA', dob: '780203', sex: 'M', expiry: '290630' });
      const l2 = good[1].split('');
      l2[43] = String((Number(l2[43]) + 4) % 10); // composite digit no longer agrees
      return [good[0], l2.join('')];
    })(),
    note: 'Caller is urgent and cites an executive. Document passes a glance; the composite check digit does not.',
  },
  {
    id: 'VS-40220',
    claim: 'Sunniva Haugland',
    role: 'Senior Accountant',
    action: 'privileged_grant',
    channel: 'Self-service portal',
    agent: '—',
    signals: ['face_match', 'liveness_passive', 'gov_id_mrz_valid'],
    attacks: ['virtual_camera', 'injection_no_sensor', 'deepfake_temporal', 'emulator'],
    mrz: buildTD3({ issuer: 'NOR', surname: 'HAUGLAND', given: 'SUNNIVA', docNumber: 'NO7712334', nationality: 'NOR', dob: '940822', sex: 'F', expiry: '330114' }),
    note: 'Every biometric check passes. The frames never came from a camera.',
  },
];

let selected = SESSIONS[0].id;
let overrideAction = null;

function renderList() {
  $('#sessions').innerHTML = SESSIONS.map((s) => {
    const r = scoreSession({ ...s, action: s.id === selected && overrideAction ? overrideAction : s.action });
    const cls = r.verdict === 'ALLOW' ? 'ok' : r.verdict === 'STEP_UP' ? 'warn' : 'bad';
    return `<div class="row ${s.id === selected ? 'sel' : ''}" data-id="${s.id}" style="grid-template-columns:minmax(0,1fr) 78px">
      <div>
        <div class="t">${s.claim}</div>
        <div class="m">${s.id} · ${ACTIONS[s.action].label} · ${s.channel}</div>
      </div>
      <div class="num"><span class="chip ${cls}">${r.verdict === 'STEP_UP' ? 'STEP UP' : r.verdict}</span></div>
    </div>`;
  }).join('');
  $('#sessions').querySelectorAll('.row').forEach((el) =>
    el.addEventListener('click', () => { selected = el.dataset.id; overrideAction = null; render(); })
  );
}

function renderDetail() {
  const s = SESSIONS.find((x) => x.id === selected);
  const action = overrideAction || s.action;
  const r = scoreSession({ ...s, action });
  const mrz = parseTD3(s.mrz[0], s.mrz[1]);

  const vcls = r.verdict === 'ALLOW' ? 'ok' : r.verdict === 'STEP_UP' ? 'warn' : 'bad';
  const barMax = Math.max(r.earned, r.required, 6);

  $('#detail').innerHTML = `
    <div class="dsec">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:11px;flex-wrap:wrap">
        <strong style="font-size:15px">${s.claim}</strong>
        <span class="pill ${vcls}">${r.verdict.replace('_', ' ')}</span>
        <span style="flex:1"></span>
        <span class="mono" style="font-size:11px;color:var(--ink-3)">${s.id}</span>
      </div>
      <dl class="kv">
        <dt>Claimed identity</dt><dd>${s.role}</dd>
        <dt>Requested action</dt><dd>
          <select id="actSel" style="font-family:var(--mono);font-size:11.5px">
            ${Object.entries(ACTIONS).map(([k, v]) => `<option value="${k}" ${k === action ? 'selected' : ''}>${v.label} — assurance ${v.assurance}</option>`).join('')}
          </select>
        </dd>
        <dt>Blast radius</dt><dd>${ACTIONS[action].blast}</dd>
        <dt>Channel</dt><dd>${s.channel} · ${s.agent}</dd>
      </dl>
      <div class="note" style="margin-top:10px">${s.note}</div>
    </div>

    <div class="dsec">
      <h3>Assurance ledger</h3>
      <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:6px">
        <span class="mono" style="font-size:19px;font-weight:650;color:${r.net >= r.required ? 'var(--accent)' : 'var(--rose)'}">${r.net.toFixed(1)}</span>
        <span class="mono" style="font-size:11.5px;color:var(--ink-3)">net · requires ${r.required.toFixed(1)} for ${ACTIONS[action].label.toLowerCase()}</span>
      </div>
      <div style="position:relative;height:12px;background:var(--bg-2);border-radius:3px;overflow:hidden;border:1px solid var(--line)">
        <div style="position:absolute;left:0;top:0;bottom:0;width:${Math.max(0, Math.min(100, (r.earned / barMax) * 100))}%;background:var(--accent-dim)"></div>
        <div style="position:absolute;left:0;top:0;bottom:0;width:${Math.max(0, Math.min(100, (r.net / barMax) * 100))}%;background:var(--accent)"></div>
        <div style="position:absolute;top:0;bottom:0;left:${(r.required / barMax) * 100}%;width:2px;background:var(--amber)"></div>
      </div>
      <div class="mono" style="font-size:10.5px;color:var(--ink-3);margin-top:5px">
        earned ${r.earned.toFixed(1)} · attack penalty −${r.penalty.toFixed(1)} · amber marks the requirement
      </div>

      <div style="margin-top:12px">
        ${r.earnedDetail.map((d) => `<div style="display:flex;gap:8px;align-items:center;padding:3px 0;font-size:12px">
          <span class="chip ok" style="min-width:44px">+${d.weight.toFixed(1)}</span>
          <span style="color:var(--ink-2);flex:1">${d.label}</span>
          <span class="mono" style="font-size:10px;color:var(--ink-3)">${d.kind}</span>
        </div>`).join('')}
        ${r.attackDetail.map((d) => `<div style="display:flex;gap:8px;align-items:center;padding:3px 0;font-size:12px">
          <span class="chip bad" style="min-width:44px">−${d.penalty.toFixed(1)}</span>
          <span style="color:var(--rose);flex:1">${d.label}</span>
        </div>`).join('')}
      </div>
      ${r.hardFail ? `<div class="card" style="margin-top:11px;border-color:#6d2f39">
        <div class="desc" style="color:var(--rose)">Disqualifying indicator present</div>
        <div class="act">A high-severity attack signal denies the session outright. Assurance is not
        additive against injection: an attacker who controls the capture chain can produce an
        unlimited number of passing biometric checks, so counting more of them proves nothing.</div>
      </div>` : ''}
      ${r.remedies.length ? `<div class="card" style="margin-top:11px">
        <div class="desc">Step-up options that would close the gap</div>
        ${r.remedies.map((m) => `<div class="act">+${m.weight.toFixed(1)} — ${m.label}</div>`).join('')}
      </div>` : ''}
    </div>

    <div class="dsec">
      <h3>Document — ICAO 9303 machine readable zone</h3>
      <pre class="mono" style="margin:0 0 10px;font-size:11px;background:var(--bg-2);border:1px solid var(--line);border-radius:7px;padding:10px;overflow-x:auto;color:var(--ink-2)">${mrz.lines[0]}
${mrz.lines[1]}</pre>
      <dl class="kv">
        <dt>Name</dt><dd>${mrz.given} ${mrz.surname}</dd>
        <dt>Document</dt><dd>${mrz.docType} ${mrz.docNumber} · ${mrz.issuer}</dd>
        <dt>Nationality</dt><dd>${mrz.nationality}</dd>
        <dt>Born / expires</dt><dd>${mrz.dob} / ${mrz.expiry}</dd>
      </dl>
      <table class="tbl" style="margin-top:10px">
        <thead><tr><th>Check digit</th><th class="num">Expected</th><th class="num">Computed</th><th class="num">Result</th></tr></thead>
        <tbody>${mrz.checks.map((c) => `<tr>
          <td style="color:var(--ink-2)">${c.name}</td>
          <td class="num">${c.expected}</td>
          <td class="num">${c.computed}</td>
          <td class="num"><span class="chip ${c.ok ? 'ok' : 'bad'}">${c.ok ? 'pass' : 'FAIL'}</span></td>
        </tr>`).join('')}</tbody>
      </table>
      <div class="note" style="margin-top:9px">
        Weights cycle 7-3-1 across each field, letters map A=10 through Z=35, filler is zero, and the
        digit is the sum mod 10. The composite digit covers the document number, birth date, expiry
        and optional field together — which is why re-typing one field of a real passport and leaving
        the composite alone fails here while surviving a visual check.
      </div>
    </div>`;

  const sel = $('#actSel');
  if (sel) sel.addEventListener('change', (e) => { overrideAction = e.target.value; render(); });
}

function renderMatrix() {
  $('#matrix').innerHTML = `
    <table class="tbl">
      <thead><tr><th>Action</th><th class="num">Assurance</th><th>Blast radius</th></tr></thead>
      <tbody>${Object.entries(ACTIONS).map(([k, v]) => `<tr>
        <td style="color:var(--ink-2)">${v.label}</td>
        <td class="num">${v.assurance.toFixed(1)}</td>
        <td style="color:var(--ink-3)">${v.blast}</td>
      </tr>`).join('')}</tbody>
    </table>
    <div class="note" style="margin-top:9px">
      Assurance requirements are tied to blast radius, not to how insistent the caller is. Change the
      requested action on any session and the same evidence flips between allow, step-up and deny —
      which is the point: verification is not a property of a person, it is a property of a person
      plus what they are asking for.
    </div>`;
}

function render() { renderList(); renderDetail(); renderMatrix(); }
render();
window.idv = { parseTD3, checkDigit, scoreSession, SESSIONS, SIGNALS, ATTACKS };
