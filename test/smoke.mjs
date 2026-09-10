/* smoke.mjs -- proves THIS installed copy of logscrub works, on your machine.
 *   npm test          (or: node node_modules/logscrub/test/smoke.mjs)
 *
 * Neither the example input nor its expected output is typed here: both are
 * extracted from the README you were shipped, so rewording the example is free
 * and making it untrue is not. The detector count is stamped at build time from
 * the single source of truth, so a truncated table fails here rather than
 * quietly redacting less than you were promised.
 */
import { readFileSync } from "node:fs";
import { redact, detect, detectors } from "../index.mjs";

const EXPECTED_DETECTORS = 37;

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
let pass = 0;
const fails = [];
const ok = (cond, what) => (cond ? pass++ : fails.push(what));

/* the first js block holds the example; the line after "redact(log).text;" is the output */
const block = readme.match(/```js\n([\s\S]*?)```/);
ok(block, "README has a js example block");
const input = block && block[1].match(/const log = `([\s\S]*?)`;/);
ok(input, "example input found");
const want = block && block[1].match(/redact\(log\)\.text;\n\/\/ (.*)/);
ok(want, "example output found");
if (input && want) {
  const got = redact(input[1]).text;
  ok(got === want[1], `README example is true\n  got  ${got}\n  want ${want[1]}`);
}

/* the whole detector table shipped, not a truncated one */
const all = detectors();
ok(
  all.length === EXPECTED_DETECTORS,
  `detector table is whole: ${all.length} shipped, ${EXPECTED_DETECTORS} expected`,
);
ok(
  all.every((d) => d.id && d.tag && d.label && d.group),
  "every detector has id/tag/label/group",
);
ok(new Set(all.map((d) => d.id)).size === all.length, "detector ids are unique");

/* the API surface the README promises */
ok(redact("nothing to see here").text === "nothing to see here", "clean text is untouched");
ok(redact("").text === "", "empty input is empty output");
const two = redact("key AKIAIOSFODNN7EXAMPLE and key AKIAIOSFODNN7EXAMPLE");
ok(two.text.split("[AWS_KEY_1]").length === 3, "the same secret gets the same number twice");
ok(two.findings.length === 2, "both positions are reported, not just the first");

/* detect() finds without rewriting, and never hands back the secret */
const found = detect("aws AKIAIOSFODNN7EXAMPLE");
ok(Array.isArray(found), "detect() returns an array");
ok(found.length === 1, "detect() finds the key");
ok(
  found.every((f) => typeof f.start === "number" && typeof f.end === "number" && f.detector),
  "every finding carries start/end/detector",
);

for (const f of fails) console.log("FAIL " + f);
console.log(`${pass} passed, ${fails.length} failed`);
process.exit(fails.length ? 1 : 0);
