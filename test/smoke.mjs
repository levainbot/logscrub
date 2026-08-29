/* smoke.mjs -- runs the README's own example through the package.
 * Neither the input nor the expected output is typed here: both are extracted
 * from README.md, so rewording the example is free and making it untrue is not.
 *   npm test
 */
import { readFileSync } from "node:fs";
import { redact, detectors } from "../index.mjs";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
let pass = 0;
const fails = [];
const ok = (cond, what) => (cond ? pass++ : fails.push(what));

/* the first js block holds the example; the line after "redact(log).text;" is the output */
const block = readme.match(/```js\n([\s\S]*?)```/);
ok(block, "README has a js example block");
const input = block[1].match(/const log = `([\s\S]*?)`;/);
ok(input, "example input found");
const want = block[1].match(/redact\(log\)\.text;\n\/\/ (.*)/);
ok(want, "example output found");
if (input && want) {
  const got = redact(input[1]).text;
  ok(got === want[1], `README example is true\n  got  ${got}\n  want ${want[1]}`);
}

/* the API surface the README promises */
const all = detectors();
ok(all.length > 0, "detectors() returns detectors");
ok(all.every((d) => d.id && d.tag && d.label && d.group), "every detector has id/tag/label/group");
ok(redact("nothing to see here").text === "nothing to see here", "clean text is untouched");
const two = redact("key AKIAIOSFODNN7EXAMPLE and key AKIAIOSFODNN7EXAMPLE");
ok(two.text.split("[AWS_KEY_1]").length === 3, "the same secret gets the same number twice");

for (const f of fails) console.log("FAIL " + f);
console.log(`${pass} passed, ${fails.length} failed`);
process.exit(fails.length ? 1 : 0);
