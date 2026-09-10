#!/usr/bin/env node
/* logscrub -- find and mask secrets in free-form log text, by shape, not by key name.
 *
 * The library is the product; this is the way it travels. `npx logscrub` needs no
 * install, and a pre-commit hook or a CI step is where a redactor is actually useful:
 * at the boundary where text stops being yours.
 *
 * Built by Levain, an autonomous AI agent. https://levain.bmac.io
 * Zero dependencies. No network calls. No telemetry.
 */
import { readFileSync, writeFileSync, existsSync, writeSync, readSync } from "node:fs";
import { isatty } from "node:tty";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  redactRun,
  restore,
  buildMap,
  detectors,
  effectiveDetectors,
  sniffBytes,
  countInvisible,
  countConfusables,
  MAP_KINDS,
} from "../index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8")).version;
const RC = ".logscrubrc.json";

const COMMON_LABELS =
  "utf-8, utf-16le, utf-16be, windows-1252, windows-1251, windows-1250, " +
  "iso-8859-2, koi8-r, shift_jis, euc-jp, euc-kr, big5";

const USAGE = `logscrub ${VERSION} -- mask secrets in log text by their shape, not by key name

USAGE
  logscrub [options] [file ...]        redact to stdout; reads stdin when no file is given
                                       (a lone - also means stdin). Placeholder numbering is
                                       shared across files: one secret, one number.
  logscrub --check [file ...]          exit 1 if anything was found -- for hooks and CI
  logscrub --restore --map keys.json   turn a redacted log back into the original
  logscrub --list                      every detector, and whether it is on by default

OPTIONS
  -c, --check         find, do not rewrite. Report to stderr, exit 1 on any finding.
      --json          emit JSON instead of text: {count, findings, review[, tags, text]}
  -o, --out FILE      write the output here instead of stdout
  -m, --map FILE      write the reverse map, so this run can be undone (see --restore).
                      It holds the REAL secrets: written mode 600, keep it local.
      --restore       reverse a redaction; requires --map
      --plain         [TAG] instead of [TAG_1]; loses correlation, keeps brevity
      --prefix STR    put STR inside every placeholder, e.g. --prefix ACME_
      --enable  ids   comma-separated detector ids or tags to force on
      --disable ids   comma-separated detector ids or tags to force off
      --config FILE   JSON policy file (default: ${RC} if present)
  -e, --encoding L    force the input encoding (utf-8, utf-16le, windows-1251, ...)
                      by default the bytes are sniffed; this overrides that
      --no-review     skip the second look (see below)
      --review-all    also review long random strings and UUIDs (certificates,
                      checksums, digests). For reading a report once, not for
                      --check: every row would block a commit. See the README.
  -q, --quiet         no stderr summary
  -l, --list          list detectors
  -h, --help          this text
  -V, --version       print version

EXIT CODES
  0  ran fine (with --check: nothing found)
  1  --check found at least one secret, or the second look named one inside a blob
  2  bad usage, an unreadable file, or an input this scanner cannot read honestly

THE REPORT NEVER PRINTS THE SECRET
  --check names the file, the line, the detector and the tag -- never the value.
  A hook that echoes the credential into your terminal scrollback or a CI log has moved
  it somewhere new, not caught it. The one file that does hold real values is the
  --map file, whose whole job is to, and it is written mode 600 and says so.

THE SECOND LOOK
  A secret inside a base64 or hex run is invisible to every detector here, because none
  of them can see through the encoding. The old answer was "nothing found" printed over
  a live token, with --check exiting 0, so the hook waved the commit through. logscrub
  decodes each run it did not already redact, re-scans it with the same detectors, and
  tells you what is in there, by line. It does not rewrite the blob: it may be a
  certificate or a config you need whole, and guessing is worse than telling you.
  --check counts these. --no-review turns it off.

INPUT IS READ AS BYTES, NOT AS UTF-8
  A log written by PowerShell (> or Out-File) is UTF-16: read as UTF-8 every secret in
  it hides behind a zero byte and the scan reports clean. logscrub reads the bytes,
  decodes what they actually are, and says so on stderr. Bytes that are not text at
  all -- gzip, zip, PDF, an ELF binary -- are refused by name rather than scanned into
  a meaningless all-clear. Bytes that are text in a legacy encoding are refused too,
  with the flag that reads them, because decoding them as UTF-8 destroys the log
  around the secrets it finds. Output is always UTF-8.

EXAMPLES
  npm test 2>&1 | npx logscrub              scrub before you paste it anywhere
  git diff --cached --name-only | xargs -r npx logscrub --check   gate a commit
  npx logscrub app.log -o safe.log -m keys.json   share safe.log, keep keys.json
  npx logscrub --restore -m keys.json < reply.txt read a reply that quotes placeholders
  npx logscrub -e windows-1251 old.log      legacy bytes, decoded not destroyed
`;

/* The library says "use detectors()"; from the CLI the answer is --list. */
function cliMsg(m) {
  return m
    .replace(/^logscrub: /, "")
    .replace("Use detectors() to list valid ids and tags.", "Run `logscrub --list` for valid ids and tags.");
}

function fail(msg) {
  err("logscrub: " + msg + "\n");
  process.exit(2);
}

const splitIds = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);

/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const o = { files: [], enable: [], disable: [], review: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined) fail(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case "-c": case "--check":   o.check = true; break;
      case "--json":               o.json = true; break;
      case "-o": case "--out":     o.out = need(); break;
      case "-m": case "--map":     o.map = need(); break;
      case "--restore":            o.restore = true; break;
      case "--plain":              o.plain = true; break;
      case "--prefix":             o.prefix = need(); break;
      case "--enable":             o.enable.push(...splitIds(need())); break;
      case "--disable":            o.disable.push(...splitIds(need())); break;
      case "--config":             o.config = need(); break;
      case "-e": case "--encoding": o.encoding = need(); break;
      case "--no-review":          o.review = false; break;
      case "--review-all":         o.reviewAll = true; break;
      case "-q": case "--quiet":   o.quiet = true; break;
      case "-l": case "--list":    o.list = true; break;
      case "-h": case "--help":    o.help = true; break;
      case "-V": case "--version": o.version = true; break;
      case "--":                   o.files.push(...argv.slice(i + 1)); i = argv.length; break;
      default:
        if (a.startsWith("-") && a !== "-") fail(`unknown option ${a}. Try --help.`);
        o.files.push(a);
    }
  }
  return o;
}

/* A policy file is how a repo says "this project does not care about phone numbers"
   once instead of in every hook invocation. Command-line flags win over it, so a
   one-off override never needs an edit -- and, more importantly, so a file nobody
   remembered can never override what the person at the terminal just typed. */
function loadConfig(o) {
  const path = o.config || (existsSync(RC) ? RC : null);
  if (!path) return;
  let cfg;
  try {
    cfg = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    fail(`cannot read config ${path}: ${e.code || e.message}`);
  }
  if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) {
    fail(`${path} must be a JSON object, e.g. {"disable": ["phone"]}`);
  }
  const known = ["enable", "disable", "prefix", "numbered", "review", "reviewAll"];
  const strange = Object.keys(cfg).filter((k) => !known.includes(k));
  if (strange.length) {
    /* A typo in a config file that is silently ignored is a rule the user believes is
       on and is not. Refuse rather than half-apply. */
    fail(`${path} has key(s) this version does not know: ${strange.join(", ")}\n` +
      `  Known keys: ${known.join(", ")}`);
  }
  o.enable = [...(cfg.enable || []), ...o.enable];
  o.disable = [...(cfg.disable || []), ...o.disable];
  if (cfg.prefix && o.prefix === undefined) o.prefix = cfg.prefix;
  if (cfg.numbered === false && !o.plain) o.plain = true;
  if (cfg.review === false && o.review) o.review = false;
  if (cfg.reviewAll === true && !o.reviewAll) o.reviewAll = true;
}

/* --- reading, as bytes ---------------------------------------------------------
 *
 * readFileSync(path, "utf8") is the worst bug a redactor can have, because it never
 * fails. A log PowerShell wrote with > is UTF-16: every character sits behind a zero
 * byte, so nothing matches and the tool prints "nothing found" over a file full of
 * live credentials. A log in Windows-1251 is worse -- the secrets ARE found, and the
 * utf-8 read has already replaced every non-ASCII byte with U+FFFD, so writing the
 * result back destroys the log. Both look exactly like success. So: read bytes, ask
 * what they are, refuse what cannot be read honestly. The sniffer is the browser
 * tool's own, generated into lib/sniff.mjs from the same page as the detectors. */

function stripBom(t) {
  return t.charCodeAt(0) === 0xfeff ? t.slice(1) : t;
}

function nonAsciiCount(b) {
  let n = 0;
  for (let i = 0; i < b.length; i++) if (b[i] > 0x7f) n++;
  return n;
}

/* Advice that names the actual next command, per container. A refusal that only says
   "this is not text" leaves the reader exactly where they were. */
const UNPACK = {
  gzip: (w) => `  Decompress it first:  gunzip -c ${w} | logscrub`,
  zip: () => `  Unpack it and scan the files inside.`,
};

function decodeBytes(bytes, where, o) {
  if (o.encoding) {
    let dec;
    try {
      dec = new TextDecoder(o.encoding);
    } catch {
      fail(`unknown encoding "${o.encoding}". Try one of: ${COMMON_LABELS}`);
    }
    return {
      text: stripBom(dec.decode(bytes)),
      note: `${where}: decoded as ${dec.encoding} because --encoding said so; output is UTF-8`,
    };
  }

/* The byte form of U+FFFD in each encoding that can express it. A UTF-16 code
   unit never begins at an odd offset, so that scan steps two -- otherwise the
   FD FF inside an unrelated pair would be counted as a character. */
const FFFD_BYTES = { "utf-8": [0xef, 0xbf, 0xbd], "utf-16le": [0xfd, 0xff], "utf-16be": [0xff, 0xfd] };
function encodedReplacements(bytes, enc) {
  const seq = FFFD_BYTES[enc];
  if (!seq) return 0;
  const step = seq.length === 3 ? 1 : 2;
  let n = 0;
  for (let i = 0; i + seq.length <= bytes.length; i += step) {
    let hit = true;
    for (let j = 0; j < seq.length; j++) if (bytes[i + j] !== seq[j]) { hit = false; break; }
    if (hit) n++;
  }
  return n;
}

  const g = sniffBytes(bytes);

  if (g.enc === null) {
    /* A container has a next command; say THAT rather than offering an encoding label,
       which cannot help with bytes that are not text at all. */
    const extra = UNPACK[g.label] ? UNPACK[g.label](where) : null;
    fail(
      `${where}: ${g.why}\n` +
        (extra || `  If you know what it really is, say so: --encoding LABEL`)
    );
  }

  if (g.label === "not UTF-8") {
    const bad = nonAsciiCount(bytes);
    fail(
      `${where} is not valid UTF-8, so it was written in a legacy encoding ` +
        `(${bad} of ${bytes.length} bytes are outside ASCII).\n` +
        `  Decoding it as UTF-8 would replace every one of them before the scan ran. The ` +
        `secrets would still be found\n  and the log around them would already be ` +
        `destroyed, so saving the output over the original would lose it.\n` +
        `  Say which encoding it is:  logscrub --encoding windows-1251 ${where}\n` +
        `  Labels: ${COMMON_LABELS}\n` +
        `  To read it as UTF-8 anyway and accept the loss: --encoding utf-8`
    );
  }

  const text = stripBom(new TextDecoder(g.enc).decode(bytes));

  /* The sniffer's verdict is evidence, not proof, and on a short file with no
     byte-order mark the only evidence for UTF-16 is "every other byte is zero" --
     which a five-byte binary also satisfies. It used to be decoded, scanned, reported
     clean, and written to stdout with U+FFFD where the bytes had been. So: if the
     decode INTRODUCED replacement characters, it destroyed bytes, and a redactor whose
     output is a corrupted copy of your file is worse than one that refuses. Skipped
     when --encoding is given, because there the user has said so and the loss is the
     documented escape hatch. */
  /* A NUL survives a UTF-8 decode intact, so it produces no replacement character and
     the check below cannot see it -- but a text log never contains one, and scanning
     five bytes of a binary and reporting them clean is the lie this whole function
     exists to stop. Asked here rather than at the byte layer so a UTF-16 log, whose
     bytes are half NUL and whose TEXT has none, is unaffected. */
  if (text.indexOf("\u0000") >= 0) {
    fail(
      `${where} contains NUL bytes after decoding, so it is not text and this scan ` +
        `would be blind.\n  Refusing rather than reporting it clean.`
    );
  }

  /* U+FFFD IS A LEGAL CHARACTER, AND FINDING ONE IN THE DECODED TEXT IS NOT
     EVIDENCE THE DECODE DESTROYED ANYTHING. A log that has already been through
     a mangled pipeline contains replacement characters by the dozen, and its own
     bytes encode them: nothing was lost reading it, it is exactly the UTF-8 it
     claims to be, and refusing it leaves a real secret unscanned -- the failure
     this whole function exists to prevent, arrived at from the other side.
     Found by running the tool over my own site: redact.html holds 30 of them as
     printed examples, is valid UTF-8 by iconv and by Python, and was refused.
     So count what the SOURCE BYTES already encode and subtract. Only the three
     Unicode encodings can represent U+FFFD at all; under every legacy label it
     is unrepresentable, so there every one found was introduced by the decode. */
  const lost = (text.match(/�/g) || []).length - encodedReplacements(bytes, g.enc);
  if (lost > 0) {
    fail(
      `${where}: reading these bytes as ${g.label} produced ${lost} replacement ` +
        `character${lost === 1 ? "" : "s"}, so they are not ${g.label}.\n` +
        `  Scanning would report on a corrupted copy and writing the output back would ` +
        `lose the original.\n` +
        `  Say what it is:  logscrub --encoding LABEL ${where}\n` +
        `  Labels: ${COMMON_LABELS}`
    );
  }

  const note = g.enc === "utf-8" ? null : `${where}: decoded as ${g.label}; output is UTF-8`;
  return { text, note };
}

/* The read-side twin of fdWrite, and it exists for a worse bug than the write one.

   TOUCHING process.stdin is what broke this. The getter constructs a net.Socket over
   fd 0, and for a PIPE that puts the fd into NON-BLOCKING mode for the whole process.
   readFileSync(0) then throws EAGAIN the first moment the pipe is empty -- which is
   every producer slower than this reader:

       kubectl logs pod | logscrub    read 0 of 548,750 bytes
                                      "nothing was replaced", exit 0, secret in the log

   and the old catch turned that EAGAIN into Buffer.alloc(0), so a redactor called a log
   CLEAN without ever reading it. `cat big.log | logscrub` cannot show it: cat keeps the
   pipe full, so no read ever finds it empty. The witness has to be a SLOW producer.

   Reading fd 0 from a terminal blocks forever, which once turned the documented
   `--check $(git diff --cached --name-only)` into a hung commit whenever nothing was
   staged. tty.isatty answers that without constructing the stream.

   EAGAIN means "not yet", never "end". The only end is read() returning 0; any other
   error exits 2 rather than reporting a clean empty string. */
function readStdin() {
  if (isatty(0)) {
    fail("no input. Give a file, or pipe text in. Try --help.");
  }
  const parts = [];
  const buf = Buffer.allocUnsafe(65536);
  const idle = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    let n;
    try {
      n = readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      /* Atomics.wait is a synchronous sleep; a bare `continue` would spin a core flat
         for as long as the producer is quiet, and `tail -f` is quiet for hours. */
      if (e.code === "EAGAIN") { Atomics.wait(idle, 0, 0, 5); continue; }
      if (e.code === "EOF") break;
      fail(`cannot read stdin: ${e.code || e.message}`);
    }
    if (n === 0) break;
    parts.push(Buffer.from(buf.subarray(0, n)));
  }
  return Buffer.concat(parts);
}

function readChunks(files, o) {
  const notes = [];
  const take = (bytes, name, where) => {
    const { text, note } = decodeBytes(bytes, where, o);
    if (note) notes.push(note);
    return { name, text };
  };
  const chunks = !files.length
    ? [take(readStdin(), "(stdin)", "stdin")]
    : files.map((f) => {
        if (f === "-") return take(readStdin(), "(stdin)", "stdin");
        let bytes;
        try {
          bytes = readFileSync(f);
        } catch (e) {
          fail(`cannot read ${f}: ${e.code || e.message}`);
        }
        return take(bytes, f, f);
      });
  if (!o.quiet) for (const n of notes) err("logscrub: " + n + "\n");
  return chunks;
}

/* writeFileSync throwing raw put a Node stack trace on stderr and exited 1 -- the
   same code `--check` uses for "found a secret", so a full disk read as a leak. */
function writeOut(file, body, mode) {
  try {
    writeFileSync(file, body, mode ? { mode } : undefined);
  } catch (e) {
    fail(`cannot write ${file}: ${e.code || e.message}`);
  }
}

/* ------------------------------------------------------------------ */
/* EVERY byte this tool prints goes through these two, never through
   process.stdout.write, and the reason is a silent-data-loss bug wake 083 found by
   scanning a real source tree: node's stdout write is ASYNCHRONOUS when stdout is a
   PIPE, and process.exit() throws away whatever has not flushed yet. So

       logscrub big.log | less        lost 161 of 227 KB
       logscrub big.log --json | jq   produced unparseable JSON

   and both exited 0. The truncation is invisible to a redirect (`> file` and a TTY
   are synchronous), which is exactly why it survived every test I had: the tests
   redirect. writeSync on the raw fd is synchronous on every target, so no exit can
   race it. EAGAIN happens on a non-blocking pipe and means "retry"; EPIPE means the
   reader closed early (`| head`), which for a filter is a normal end, not an error. */
function fdWrite(fd, text) {
  const buf = Buffer.from(String(text), "utf8");
  let off = 0;
  while (off < buf.length) {
    try {
      off += writeSync(fd, buf, off, buf.length - off);
    } catch (e) {
      if (e.code === "EAGAIN") continue;
      if (e.code === "EPIPE") return;
      throw e;
    }
  }
}
/* declarations, not consts: fail() and the notes printer sit ABOVE this block and
   call these, and a const would be in the temporal dead zone for any caller that
   ran during module evaluation. */
function out(text) { fdWrite(1, text); }
function err(text) { fdWrite(2, text); }

function emit(text, o) {
  if (o.out) writeOut(o.out, text);
  else out(text);
}

/* ------------------------------------------------------------------ */

const opts = parseArgs(process.argv.slice(2));

if (opts.help)    { out(USAGE); process.exit(0); }
if (opts.version) { out(VERSION + "\n"); process.exit(0); }

loadConfig(opts);

if (opts.list) {
  const all = detectors();
  const w = Math.max(...all.map((d) => d.id.length));
  const t = Math.max(...all.map((d) => d.tag.length));
  for (const d of all) {
    out(
      `${d.on ? "on " : "off"}  ${d.id.padEnd(w)}  ${d.tag.padEnd(t)}  ${d.label}\n`
    );
  }
  const on = all.filter((d) => d.on).length;
  err(
    `\n${all.length} detectors, ${on} on by default, ` +
      `${new Set(all.map((d) => d.tag)).size} distinct tags\n`
  );
  process.exit(0);
}

/* Flag combinations that cannot both be honoured. Each of these was silently ignored
   before, which is the failure mode a redactor can least afford: the user asked for
   something, got no error, and believes it happened. */
if (opts.check && opts.out) {
  fail("--out has no meaning with --check: the report goes to stderr, and there is no redacted text to write.");
}
if (opts.check && opts.map && !opts.restore) {
  fail("--map has no meaning with --check: nothing is replaced, so there is nothing to map back.");
}
if (opts.restore && opts.check) {
  fail("--restore and --check do opposite jobs. Pick one.");
}

const detOpts = { enable: opts.enable, disable: opts.disable };

/* --- restore ------------------------------------------------------ */

if (opts.restore) {
  if (!opts.map) fail("--restore needs --map FILE (the map written by the run you are undoing)");
  let map;
  try {
    map = JSON.parse(readFileSync(resolve(opts.map), "utf8"));
  } catch (e) {
    fail(`cannot read map ${opts.map}: ${e.code || e.message}`);
  }
  if (!map || !MAP_KINDS.includes(map.kind)) {
    fail(`${opts.map} is not a logscrub map (its "kind" is ${JSON.stringify(map && map.kind)}).`);
  }
  const chunks = readChunks(opts.files, opts);
  let total = 0;
  const text = chunks
    .map((c) => {
      const r = restore(c.text, map);
      total += r.replaced;
      return r.text;
    })
    .join("");
  emit(text, opts);
  if (!opts.quiet) {
    err(
      `logscrub: restored ${total} placeholder${total === 1 ? "" : "s"}` +
        (total ? "" : " -- nothing in the input matched a placeholder in the map") + "\n"
    );
  }
  process.exit(0);
}

/* An empty rule set is bad usage, not a clean result. --disable, or a .logscrubrc.json
   this process picked up without being told, can switch every detector off; the run
   then replaces nothing and --check exits 0. That is a pre-commit gate passing because
   nothing looked, and with -q it passes in silence. */
let table;
try {
  /* This also throws on an unknown id or tag, which is why it runs BEFORE any input is
     read: a typo in --disable or in a policy file must be an error, not a rule the
     user believes is off. */
  table = effectiveDetectors(detOpts);
} catch (e) {
  fail(cliMsg(e.message));
}
if (!table.some((d) => d.on)) {
  fail(
    "every detector is switched off, so this run would scan nothing. An empty result " +
      "would not mean the input is clean -- it would mean nothing looked. Check " +
      `--disable and any ${RC}, then re-run. \`logscrub --list\` shows the whole set.`
  );
}

/* --- the run ------------------------------------------------------ */

const chunks = readChunks(opts.files, opts);

/* The mirror of the empty rule set above, and the same lie told from the other side:
   there, nothing looked; here, there is nothing to look AT.

       kubectl logs pod | logscrub > safe.log

   when kubectl fails writes its diagnosis to ITS stderr and not one byte into the
   pipe. The old run printed "nothing was replaced; 31 of 34 rules ran", exited 0, and
   left a reassuring summary over a file nobody scanned; --check passed the same way,
   which is a gate opening because there was nothing in front of it. An empty input is
   not a clean input. The only honest thing a redactor can say about bytes it never
   got is that it never got them.

   Two shapes, and what separates them is the CONSEQUENCE, not the byte count:

   - Nothing came in on stdin and a redacted COPY was asked for. There is no copy to
     make, and the user is one step from walking away believing a log was cleaned when
     it was never captured. Hard error.
   - Everything else: an empty file the user NAMED, or a gate (--check) with nothing in
     front of it. Both are ordinary -- an empty file leaks nothing, and turning either
     into exit 2 would fail a pre-commit hook over a newly staged empty file. They
     still may not be told "nothing was replaced", so the summary is replaced.

   Not `!chunks.length`: several files where ONE is empty is an ordinary run. This is
   the case where the whole input, from every source, came to nothing. */
const emptyInput = !chunks.some((c) => c.text.length);
const fromStdin = !opts.files.length || opts.files.every((f) => f === "-");
if (emptyInput && fromStdin && !opts.check) {
  fail(
    "nothing arrived on stdin, so this run scanned nothing and there is no redacted " +
      "copy to give you. That is not a clean result, it is no result. If you piped a " +
      "command in, check that it actually produced output -- a command that fails " +
      "writes its error to your terminal, not into the pipe."
  );
}
if (emptyInput) {
  /* Printed even under -q, for the same reason the empty rule set is: a gate that
     passes because there was nothing in front of it must never pass in silence. */
  err(
    "logscrub: " +
      (fromStdin ? "nothing arrived on stdin" : "every file you named is empty") +
      " -- nothing was scanned. That is not a clean result, it is no result.\n"
  );
}

let result;
try {
  result = redactRun(chunks, {
    ...detOpts,
    numbered: !opts.plain,
    prefix: opts.prefix || "",
    review: opts.review,
    reviewAll: opts.reviewAll,
  });
} catch (e) {
  fail(cliMsg(e.message));
}

/* --- check mode --------------------------------------------------- */

if (opts.check) {
  const { findings, review } = result;
  if (opts.json) {
    out(
      JSON.stringify({ count: findings.length, findings, review }, null, 2) + "\n"
    );
  } else if (!opts.quiet && (findings.length || review.length)) {
    if (findings.length) {
      const files = new Set(findings.map((f) => f.file));
      err(
        `logscrub: ${findings.length} secret${findings.length === 1 ? "" : "s"} in ` +
          `${files.size} file${files.size === 1 ? "" : "s"}\n`
      );
      for (const f of findings) {
        err(`  ${f.file}:${f.line}  ${f.detector.padEnd(14)}[${f.tag}]\n`);
      }
      err(
        `  (values withheld on purpose -- printing a secret into a log is not catching it)\n`
      );
    }
    err(reviewLines(result, chunks));
  }
  process.exit(findings.length || result.review.length ? 1 : 0);
}

/* --- redact mode -------------------------------------------------- */

const text = result.outputs.map((o) => o.text).join("");

if (opts.map) {
  /* mode 600 and a line saying why. This is the only artefact logscrub writes that
     contains real credentials, and the whole design elsewhere is that none of them do. */
  writeOut(
    opts.map,
    JSON.stringify(buildMap(result, { files: chunks.map((c) => c.name) }), null, 2) + "\n",
    0o600
  );
  if (!opts.quiet) {
    err(
      `logscrub: wrote ${opts.map} (mode 600) -- it holds the real secrets, keep it local\n`
    );
  }
}

if (opts.json) {
  /* no `value` on any finding: --json is a thing people redirect into a CI artifact. */
  const payload = {
    count: result.count,
    tags: result.tags,
    findings: result.findings,
    review: result.review,
    text,
  };
  emit(JSON.stringify(payload, null, 2) + "\n", opts);
} else {
  emit(text, opts);
}

/* `!emptyInput`: the empty-input line above already said nothing was scanned, and the
   summary's "nothing was replaced; N of M rules ran" would contradict it in the next
   breath -- true of the rules, false about the run. */
if (!opts.quiet && !emptyInput) err(summary(result, chunks, table));
process.exit(0);

/* ------------------------------------------------------------------ */

/* Characters with no advance width -- a zero-width space, a word joiner, a soft
   hyphen, a stray byte-order mark, a bidi control. The engine reads past them, so a
   secret split by one is still replaced. Saying the count is not housekeeping: you
   cannot see them by definition, and dropping U+200B into a key is the cheapest way
   there is to walk a secret past a scanner. */
function invisibleLine(chunks) {
  const n = chunks.reduce((a, c) => a + countInvisible(c.text), 0);
  if (!n) return "";
  return `  read past ${n} invisible character${n === 1 ? "" : "s"} ` +
    "(zero-width, joiners, soft hyphens, BOM, bidi); they render as nothing and can " +
    "split a secret in two. They are still in your output.\n";
}

/* The mirror of the line above. A homoglyph does not render as nothing, it renders as
   the WRONG thing. The engine folds them to their ASCII twin before matching, one
   character in and one out, so every span still addresses your bytes. */
function confusableLine(chunks) {
  const n = chunks.reduce((a, c) => a + countConfusables(c.text), 0);
  if (!n) return "";
  return `  read past ${n} character${n === 1 ? "" : "s"} that look like ASCII and are not ` +
    "(Cyrillic or Greek lookalikes, fullwidth forms, typographic dashes and quotes); " +
    "they are folded to their ASCII twin for matching only, and your output keeps your bytes.\n";
}

/* Values another tool had already masked. After the mask rules do their job, an
   already-scrubbed file reports "nothing was replaced", which is word for word what a
   file nobody ever scrubbed reports. */
function maskedLine(result) {
  const n = result.masked || 0;
  if (!n) return "";
  return `  read past ${n} value${n === 1 ? "" : "s"} another tool had already ` +
    "masked (stars, [REDACTED], <sensitive> and the like); they stay exactly as they " +
    "were in your output.\n";
}

/* The second look, beside the replacements. Deliberately loud and deliberately
   separate: these are things logscrub did NOT change in the output, so a reader who
   skims the diff will not see them anywhere else.

   It names the line and what decodes out of it, and NEVER the run itself. redactkit,
   the tool this CLI absorbed, printed 28 characters of the encoded blob to help you
   find it -- but 28 characters of base64 over a live token is the front of that token
   in a terminal scrollback, which is exactly what "the report never prints the
   secret" exists to prevent. The line number is enough to find it. */
function reviewLines(result, chunks) {
  const rows = result.review || [];
  if (!rows.length) return "";
  const many = chunks.length > 1;
  const decoded = rows.filter((r) => r.kind === "decoded");
  /* A phrase row is NOT "off by default" -- the mnemonic detector is on and it
     declined this value on purpose, because its word count is not one BIP-39
     uses and a partial redaction of a seed phrase is worse than a miss. Saying
     "off by default" over it would be a false explanation of a real decline,
     so it gets its own line (wake 090). */
  const phrase = rows.filter((r) => r.kind === "phrase");
  const rest = rows.filter((r) => r.kind !== "decoded" && r.kind !== "phrase");
  let out =
    `logscrub: SECOND LOOK -- ${rows.length} thing${rows.length === 1 ? "" : "s"} the ` +
    `redactor could not act on. Read ${rows.length === 1 ? "it" : "them"} before you share this.\n`;
  for (const r of decoded) {
    const at = (many ? `${r.file}:` : "line ") + r.line;
    out +=
      `  ${at}  a ${r.encoding} run${r.chars ? ` of ${r.chars} chars` : ""} decodes to ` +
      `${r.tag}${r.count > 1 ? ` x${r.count}` : ""}  (detector: ${r.detector})\n`;
  }
  for (const r of phrase) {
    const at = (many ? `${r.file}:` : "line ") + r.line;
    out +=
      `  ${at}  a seed-phrase key with a ${r.words}-word value  ` +
      `(BIP-39 uses 12, 15, 18, 21 or 24 -- NOT redacted, on purpose)\n`;
  }
  for (const r of rest) {
    const at = (many ? `${r.file}:` : "line ") + r.line;
    out += `  ${at}  ${r.detector} -- not redacted, off by default\n`;
  }
  if (phrase.length) {
    out +=
      "  A phrase this tool cannot count is a phrase it will not half-replace: redacting " +
      "twelve of thirteen words would read to you as handled. Check it yourself.\n";
  }
  if (decoded.length) {
    out +=
      "  The blob itself was left alone on purpose: it may be a certificate or a config " +
      "you need whole.\n";
  }
  return out;
}

function summary(result, chunks, table) {
  const n = result.count;
  const look =
    invisibleLine(chunks) + confusableLine(chunks) + maskedLine(result) + reviewLines(result, chunks);
  if (!n) {
    /* "Nothing was replaced" is a negative assertion, and a negative assertion needs a
       witness. Three detectors ship off, and a config file can switch off more without
       the reader remembering, so the empty result states how many rules ran and names
       what was not looked for. */
    const off = table.filter((d) => !d.on).map((d) => d.id);
    return (
      `logscrub: nothing was replaced; ${table.length - off.length} of ${table.length} ` +
      "rules ran. That does not mean the text is clean -- read it yourself before you " +
      "share it.\n" +
      (off.length ? `  not looked for: ${off.join(", ")}\n` : "") +
      look
    );
  }
  const chips = result.tags.map((t) => `${t.tag} x${t.count}`).join(", ");
  const distinct = result.entries.length;
  const where = chunks.length > 1 ? ` across ${chunks.length} files` : "";
  return (
    `logscrub: ${n} replacement${n === 1 ? "" : "s"}${where}, ${distinct} distinct ` +
    `value${distinct === 1 ? "" : "s"}\n  ${chips}\n` +
    look
  );
}
