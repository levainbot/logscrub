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
import {
  collect,
  DETECTORS,
  luhn,
  looksRandom,
  encodingHazard,
  countInvisible,
  countConfusables,
} from "./lib/detectors.mjs";
import { secondLook } from "./lib/secondlook.mjs";
import { sniff } from "./lib/sniff.mjs";

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
 *
 * The returned array also carries `.hazard`: null for ordinary text, or
 * { kind, label, note } when the input is UTF-16, binary or compressed.
 * An empty array means "no secrets found"; an empty array with a hazard
 * means the scan could not read the input at all. A gate written as
 * `if (detect(x).length) refuse()` passes a UTF-16 log holding a live key,
 * so check the hazard first. It is non-enumerable, so the value still
 * behaves as a plain findings array everywhere else.
 */
export function detect(text, opts = {}) {
  if (typeof text !== "string") {
    throw new TypeError("logscrub: detect(text) expects a string");
  }
  const findings = withDetectors(opts, () =>
    collect(text).map((s) => ({
      tag: s.tag,
      detector: s.det,
      start: s.start,
      end: s.end,
      value: s.value,
      line: lineOf(text, s.start),
    }))
  );
  Object.defineProperty(findings, "hazard", {
    value: encodingHazard(text),
    enumerable: false,
    writable: false,
    configurable: true,
  });
  return findings;
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

/**
 * The detector table as it WILL run under `enable`/`disable`, not as it ships.
 *
 * detectors() answers "what does logscrub do by default", which is the wrong question
 * for a caller that has just switched rules off: the honest witness for "nothing was
 * found" is how many rules actually ran, and an empty active set is bad usage rather
 * than a clean result. Throws on an unknown id or tag, so a typo in a policy file is
 * an error before any input is read rather than a rule the user believes is on.
 */
export function effectiveDetectors(opts = {}) {
  return withDetectors(opts, () =>
    DETECTORS.map((d) => ({
      id: d.id,
      tag: d.tag,
      label: d.label,
      group: d.g,
      on: !!d.on,
    }))
  );
}

/**
 * One redaction pass over MANY named chunks, numbering shared across all of them.
 *
 * redact() numbers per call, which is right for one string and wrong for a run:
 * scanning two files with it gives [AWS_KEY_1] in each, naming two DIFFERENT keys.
 * Correlation is the entire reason the placeholders carry numbers, so a run is its
 * own operation rather than a loop the caller is trusted to get right.
 *
 * chunks: [{ name, text }]
 * opts:   { numbered = true, prefix = "", enable, disable,
 *           review = true, reviewAll = false }
 *
 * Returns { outputs, findings, entries, review, masked, tags, count }.
 *   outputs  [{ name, text }], the redacted text per chunk
 *   findings [{ file, line, tag, detector, placeholder, chars }] -- no `value`
 *   entries  [{ placeholder, tag, value }] in first-seen order; the reverse map
 *   review   what the redactor could NOT act on but a reader must see (below)
 *   masked   how many distinct values another tool had already masked
 *   tags     [{ tag, count }], most frequent first
 */
export function redactRun(chunks, opts = {}) {
  if (!Array.isArray(chunks)) {
    throw new TypeError("logscrub: redactRun(chunks) expects an array of { name, text }");
  }
  const numbered = opts.numbered !== false;
  const prefix = opts.prefix || "";

  return withDetectors(opts, () => {
    const seen = new Map(); // "TAG value" -> placeholder
    const perTag = new Map(); // TAG -> next index
    const counts = new Map(); // TAG -> occurrences
    const entries = [];
    const findings = [];
    const review = [];
    const outputs = [];
    const masked = new Set();

    for (const chunk of chunks) {
      const text = String(chunk.text);
      const spans = collect(text);
      for (const v of spans.maskedValues || []) masked.add(v);
      let out = "";
      let cursor = 0;

      for (const s of spans) {
        const key = s.tag + " " + s.value;
        let label = seen.get(key);
        if (label === undefined) {
          if (numbered) {
            const n = (perTag.get(s.tag) || 0) + 1;
            perTag.set(s.tag, n);
            label = "[" + prefix + s.tag + "_" + n + "]";
          } else {
            label = "[" + prefix + s.tag + "]";
          }
          seen.set(key, label);
          entries.push({ placeholder: label, tag: s.tag, value: s.value });
        }
        counts.set(s.tag, (counts.get(s.tag) || 0) + 1);
        findings.push({
          file: chunk.name,
          line: lineOf(text, s.start),
          tag: s.tag,
          detector: s.det,
          placeholder: label,
          chars: s.end - s.start,
        });
        out += text.slice(cursor, s.start) + label;
        cursor = s.end;
      }
      out += text.slice(cursor);
      outputs.push({ name: chunk.name, text: out });

      /* The second look. A secret inside a base64 or hex run is invisible to every
         detector, because none of them can see through the encoding -- so the honest
         report was "nothing matched" printed over a live credential, and --check
         exited 0 and the commit landed. This decodes each run the redactor did not
         already claim, re-scans it with the SAME detectors, and names what is inside.
         It never rewrites the blob: it may be a certificate or a config the reader
         needs whole, and guessing is worse than telling them. */
      if (opts.review !== false) {
        for (const r of secondLook(text, spans, {})) {
          /* Decoded runs only, unless asked. The other tier -- long random strings and
             UUIDs the redactor declined to touch -- raises rows across most clean text,
             which is fine on a page you can scroll past and ruinous in --check, where
             each one blocks a commit. The precision a rule needs is set by its
             consequence. */
          /* `phrase` rides the default tier with `decoded`, and the rule that
             decides is the same one: the precision a row needs is set by its
             CONSEQUENCE. The hexblob/uuid tier fires across most clean text, so
             in --check it would block every commit. A phrase row needs a
             mnemonic-family KEY NAME beside 8-32 lowercase 3-8 letter words --
             it does not fire on clean text at all, and the thing it reports is
             a seed phrase the redactor deliberately refused to half-replace.
             Gating it behind --review-all would restore the silent decline it
             exists to break (wake 090). */
          if (r.kind !== "decoded" && r.kind !== "phrase" && !opts.reviewAll) continue;
          review.push({
            file: chunk.name,
            line: r.line,
            kind: r.kind,
            encoding: r.enc || null,
            tag: r.tag,
            detector: r.detLabel,
            words: r.words || null,
            chars: (r.end || 0) - (r.start || 0) || null,
            count: r.count || 1,
          });
        }
      }
    }

    const tags = [...counts.entries()]
      .map(([tag, count]) => ({ tag, count }))
      .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));

    return {
      outputs,
      findings,
      entries,
      review,
      masked: masked.size,
      tags,
      count: findings.length,
    };
  });
}

/* Neither `findings` nor `review` carries the secret. The library could afford to
   hand back the value -- it did until wake 082 -- but every consumer of this shape
   writes it somewhere: a --json artifact in CI, a hook's stderr, a terminal
   scrollback. A report that prints the credential has moved it somewhere new, not
   caught it. `entries` is the ONE place a real value appears, because that is the
   reverse map and its whole job is to hold them. */

/** The reverse map: the one file that must never leave the machine. */
export function buildMap(result, meta = {}) {
  return {
    kind: "logscrub-map",
    version: 1,
    warning:
      "This file contains the ORIGINAL secrets in plain text. Keep it local, " +
      "never commit it, never send it with the redacted output.",
    ...meta,
    entries: (result.entries || []).map((e) => ({
      placeholder: e.placeholder,
      tag: e.tag,
      value: e.value,
    })),
  };
}

/**
 * Turn a redacted text back into the original using a map from buildMap().
 * Longest placeholder first, so [AWS_KEY_1] can never eat the front of
 * [AWS_KEY_11]. Maps written by redactkit are accepted too: the two tools
 * converged into this one, and a file someone already has must keep working.
 */
export function restore(text, map) {
  if (typeof text !== "string") {
    throw new TypeError("logscrub: restore(text, map) expects a string");
  }
  const entries = (map && map.entries) || [];
  if (!entries.length) return { text, replaced: 0 };
  const sorted = [...entries].sort(
    (a, b) => b.placeholder.length - a.placeholder.length
  );
  let out = text;
  let replaced = 0;
  for (const e of sorted) {
    const parts = out.split(e.placeholder);
    if (parts.length > 1) {
      replaced += parts.length - 1;
      out = parts.join(e.value);
    }
  }
  return { text: out, replaced };
}

/** Map kinds restore() will accept. Written by us, or by the tool we absorbed. */
export const MAP_KINDS = ["logscrub-map", "redactkit-map"];

/**
 * What are these bytes? Returns the sniffer's verdict:
 *   { enc, label, why } -- enc null means "not text this tool can read honestly".
 * readFileSync(path, "utf8") is the worst bug a redactor can have, because it never
 * fails: a log PowerShell wrote with `>` is UTF-16, so every character sits behind a
 * zero byte, nothing matches, and the tool prints "nothing found" over live keys.
 */
export function sniffBytes(bytes) {
  return sniff(bytes);
}

export { luhn, looksRandom, encodingHazard, countInvisible, countConfusables };
export default {
  detect,
  redact,
  redactRun,
  effectiveDetectors,
  buildMap,
  restore,
  detectors,
  sniffBytes,
  encodingHazard,
  luhn,
  looksRandom,
};
