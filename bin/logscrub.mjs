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
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { redact, detect, detectors } from "../index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8")).version;

const USAGE = `logscrub ${VERSION} -- mask secrets in log text by their shape, not by key name

USAGE
  logscrub [options] [file ...]     redact to stdout; reads stdin when no file is given
  logscrub --check [file ...]       exit 1 if anything was found -- for hooks and CI
  logscrub --list                   every detector, and whether it is on by default

OPTIONS
  -c, --check         find, do not rewrite. Report to stderr, exit 1 on any finding.
      --json          emit JSON instead of text: {count, hazard, findings[, text]}
  -o, --out FILE      write the redacted text here instead of stdout
      --plain         [TAG] instead of [TAG_1]; loses correlation, keeps brevity
      --prefix STR    put STR inside every placeholder, e.g. --prefix ACME_
      --enable  ids   comma-separated detector ids or tags to force on
      --disable ids   comma-separated detector ids or tags to force off
  -q, --quiet         no stderr summary
  -l, --list          list detectors
  -h, --help          this text
  -V, --version       print version

EXIT CODES
  0  ran fine (with --check: nothing found)
  1  --check found at least one secret
  2  bad usage, an unreadable file, or an input this scanner cannot read honestly

THE REPORT NEVER PRINTS THE SECRET
  --check names the file, the line, the detector and the placeholder -- never the value.
  A hook that echoes the credential into your terminal scrollback or a CI log has moved
  it somewhere new, not caught it.

EXAMPLES
  npm test 2>&1 | npx logscrub              scrub before you paste it anywhere
  npx logscrub --check $(git diff --cached --name-only)   gate a commit
  npx logscrub app.log -o safe.log          share safe.log, keep app.log
`;

/* The library says "use detectors()"; from the CLI the answer is --list. */
function cliMsg(m) {
  return m.replace(/^logscrub: /, "").replace("Use detectors() to list valid ids and tags.", "Run `logscrub --list` for valid ids and tags.");
}

function fail(msg) {
  process.stderr.write("logscrub: " + msg + "\n");
  process.exit(2);
}

/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const o = { files: [], enable: [], disable: [] };
  const list = (v, where) => {
    if (v === undefined) fail(`${where} needs a comma-separated list`);
    return v.split(",").map((s) => s.trim()).filter(Boolean);
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-c": case "--check":   o.check = true; break;
      case "--json":               o.json = true; break;
      case "-o": case "--out":     o.out = argv[++i]; if (!o.out) fail("--out needs a file"); break;
      case "--plain":              o.plain = true; break;
      case "--prefix":             o.prefix = argv[++i]; if (o.prefix === undefined) fail("--prefix needs a string"); break;
      case "--enable":             o.enable = list(argv[++i], "--enable"); break;
      case "--disable":            o.disable = list(argv[++i], "--disable"); break;
      case "-q": case "--quiet":   o.quiet = true; break;
      case "-l": case "--list":    o.list = true; break;
      case "-h": case "--help":    o.help = true; break;
      case "-V": case "--version": o.version = true; break;
      default:
        if (a.startsWith("-") && a !== "-") fail(`unknown option ${a}. Try --help.`);
        o.files.push(a);
    }
  }
  return o;
}

function readInput(files) {
  if (!files.length) {
    let buf;
    try { buf = readFileSync(0); } catch { buf = Buffer.alloc(0); }
    return [{ name: "(stdin)", text: buf.toString("utf8") }];
  }
  return files.map((f) => {
    try {
      return { name: f, text: readFileSync(f, "utf8") };
    } catch (e) {
      fail(`cannot read ${f}: ${e.code || e.message}`);
    }
  });
}

/* An input this scanner cannot read is the one case where zero findings is a lie, so
   it is refused rather than reported clean. detect().hazard is the library's own
   channel for exactly this; the CLI is just the first caller that has to act on it. */
function refuseHazard(name, hazard) {
  process.stderr.write(
    `logscrub: ${name} looks like ${hazard.label}, so this scan would be blind.\n` +
      `  ${hazard.note}\n` +
      `  Refusing rather than reporting it clean. Exclude the file from the hook, or\n` +
      `  convert it to UTF-8 first.\n`
  );
  process.exit(2);
}

/* ------------------------------------------------------------------ */

const opts = parseArgs(process.argv.slice(2));

if (opts.help)    { process.stdout.write(USAGE); process.exit(0); }
if (opts.version) { process.stdout.write(VERSION + "\n"); process.exit(0); }
if (opts.list) {
  const all = detectors();
  const w = Math.max(...all.map((d) => d.id.length));
  const t = Math.max(...all.map((d) => d.tag.length));
  for (const d of all) {
    process.stdout.write(
      `${d.on ? "on " : "off"}  ${d.id.padEnd(w)}  ${d.tag.padEnd(t)}  ${d.label}\n`
    );
  }
  process.exit(0);
}

const detOpts = { enable: opts.enable, disable: opts.disable };
const chunks = readInput(opts.files);

if (opts.check) {
  const findings = [];
  for (const c of chunks) {
    let f;
    try { f = detect(c.text, detOpts); } catch (e) { fail(cliMsg(e.message)); }
    if (f.hazard) refuseHazard(c.name, f.hazard);
    for (const s of f) findings.push({ file: c.name, line: s.line, tag: s.tag, detector: s.detector });
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify({ count: findings.length, hazard: null, findings }, null, 2) + "\n");
  } else if (findings.length && !opts.quiet) {
    const files = new Set(findings.map((f) => f.file));
    process.stderr.write(
      `logscrub: ${findings.length} secret${findings.length === 1 ? "" : "s"} in ` +
        `${files.size} file${files.size === 1 ? "" : "s"}\n`
    );
    for (const f of findings) {
      process.stderr.write(
        `  ${f.file}:${f.line}  ${f.detector.padEnd(14)}[${f.tag}]\n`
      );
    }
    process.stderr.write(
      `  (values withheld on purpose -- printing a secret into a log is not catching it)\n`
    );
  }
  process.exit(findings.length ? 1 : 0);
}

/* redact mode */
let out = "";
let total = 0;
const tags = new Map();
for (const c of chunks) {
  let r;
  try { r = redact(c.text, { ...detOpts, numbered: !opts.plain, prefix: opts.prefix || "" }); }
  catch (e) { fail(cliMsg(e.message)); }
  if (r.hazard) refuseHazard(c.name, r.hazard);
  out += r.text;
  total += r.count;
  for (const t of r.tags) tags.set(t.tag, (tags.get(t.tag) || 0) + t.count);
}

if (opts.json) {
  const payload = { count: total, hazard: null, text: out,
    tags: [...tags.entries()].map(([tag, count]) => ({ tag, count })) };
  const body = JSON.stringify(payload, null, 2) + "\n";
  if (opts.out) writeFileSync(opts.out, body); else process.stdout.write(body);
} else if (opts.out) {
  writeFileSync(opts.out, out);
} else {
  process.stdout.write(out);
}

if (!opts.quiet) {
  const summary = total
    ? `logscrub: ${total} replaced -- ` +
      [...tags.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([t, n]) => `${t} x${n}`).join(", ")
    : "logscrub: nothing found";
  process.stderr.write(summary + "\n");
}
process.exit(0);
