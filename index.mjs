/* logscrub -- find and mask secrets in free-form log text.
 *
 * Most redaction libraries walk an object and blank the values under keys you
 * name. This one reads TEXT and finds secrets by their shape, so it works on
 * the thing you actually have: a log file, a stack trace, a CI transcript, a
 * paste from someone else's terminal.
 *
 * Built by Levain, an autonomous AI agent. https://levain.bmac.io
 * Zero dependencies. No network calls. No telemetry. The source is short;
 * read it before you trust it with a secret.
 */
import { collect, DETECTORS, luhn, looksRandom, encodingHazard } from "./lib/detectors.mjs";

/* ------------------------------------------------------------------ */

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/* Resolve a detector name the caller gave us. Accepts a detector id
   ("aws_key") or a tag ("AWS_KEY"), case-insensitively. Throws on an unknown
   name rather than silently doing nothing: a typo that quietly disables
   nothing is the worst kind of bug in a redaction tool. */
function resolve(name) {
  const want = String(name).toLowerCase();
  const hits = DETECTORS.filter(
    (d) => d.id.toLowerCase() === want || d.tag.toLowerCase() === want
  );
  if (!hits.length) {
    throw new Error(
      `logscrub: unknown detector ${JSON.stringify(name)}. ` +
        `Use detectors() to list valid ids and tags.`
    );
  }
  return hits;
}

/* collect() reads each detector's `on` flag, so enable/disable is expressed by
   flipping flags around the call and putting them back afterwards. */
function withDetectors(opts, fn) {
  const saved = DETECTORS.map((d) => d.on);
  try {
    for (const name of opts.disable || []) {
      for (const d of resolve(name)) d.on = false;
    }
    for (const name of opts.enable || []) {
      for (const d of resolve(name)) d.on = true;
    }
    return fn();
  } finally {
    DETECTORS.forEach((d, i) => {
      d.on = saved[i];
    });
  }
}

/* ------------------------------------------------------------------ */

/**
 * Find secrets in `text` without changing it.
 * Returns findings in document order, non-overlapping.
 *   [{ tag, detector, start, end, value, line }]
 */
export function detect(text, opts = {}) {
  if (typeof text !== "string") {
    throw new TypeError("logscrub: detect(text) expects a string");
  }
  return withDetectors(opts, () =>
    collect(text).map((s) => ({
      tag: s.tag,
      detector: s.det,
      start: s.start,
      end: s.end,
      value: s.value,
      line: lineOf(text, s.start),
    }))
  );
}

/**
 * Replace every secret in `text` with a placeholder.
 *
 * Returns { text, findings, tags, count }.
 *   text     the redacted string
 *   findings as detect(), plus the placeholder each secret became
 *   tags     [{ tag, count }], most frequent first
 *   count    total secrets replaced
 *   hazard   null, or { kind, label, note } when the input is UTF-16,
 *            binary or compressed. In that case a count of 0 means the
 *            scan was blind, NOT that the input is clean -- check it.
 *
 * Options:
 *   numbered  true (default) -> [AWS_KEY_1], [AWS_KEY_2]; the SAME secret
 *             always becomes the SAME placeholder, so a log stays readable
 *             and you can still tell two different keys apart.
 *             false -> every AWS key becomes [AWS_KEY].
 *   prefix    string put inside the brackets, e.g. "X" -> [XAWS_KEY_1]
 *   mask      (finding) => string, to build placeholders yourself
 *   enable    detector ids or tags to switch ON  (phone, uuid and hexblob
 *             ship off by default because they are noisy)
 *   disable   detector ids or tags to switch OFF
 */
export function redact(text, opts = {}) {
  if (typeof text !== "string") {
    throw new TypeError("logscrub: redact(text) expects a string");
  }
  const numbered = opts.numbered !== false;
  const prefix = opts.prefix || "";
  const spans = detect(text, opts);

  const seen = new Map(); // "TAG value" -> placeholder
  const perTag = new Map(); // TAG -> next index
  const counts = new Map(); // TAG -> occurrences
  const findings = [];
  let out = "";
  let cursor = 0;

  for (const s of spans) {
    const key = s.tag + " " + s.value;
    let label = seen.get(key);
    if (label === undefined) {
      if (opts.mask) {
        label = String(opts.mask(s));
      } else if (numbered) {
        const n = (perTag.get(s.tag) || 0) + 1;
        perTag.set(s.tag, n);
        label = "[" + prefix + s.tag + "_" + n + "]";
      } else {
        label = "[" + prefix + s.tag + "]";
      }
      seen.set(key, label);
    }
    counts.set(s.tag, (counts.get(s.tag) || 0) + 1);
    findings.push({ ...s, placeholder: label });
    out += text.slice(cursor, s.start) + label;
    cursor = s.end;
  }
  out += text.slice(cursor);

  const tags = [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));

  return { text: out, findings, tags, count: findings.length,
           hazard: encodingHazard(text) };
}

/**
 * Every detector, as plain data: { id, tag, label, group, on }.
 * `on` is whether it runs unless you pass enable/disable.
 */
export function detectors() {
  return DETECTORS.map((d) => ({
    id: d.id,
    tag: d.tag,
    label: d.label,
    group: d.g,
    on: !!d.on,
  }));
}

export { luhn, looksRandom, encodingHazard };
export default { detect, redact, detectors, encodingHazard, luhn, looksRandom };
