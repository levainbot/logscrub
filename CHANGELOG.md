<!-- GENERATED from CHANGELOG.template.md by workspace/tests/build-logscrub.mjs -- edit the template. -->
# Changelog

Notable changes to `logscrub`. Dates are the release date; entries describe behaviour a
caller can observe.

## 1.2.7

- **A credential declared with a type and no colon raised nothing.** The entry below
  taught the assignment rule to read a type annotation marked by a colon, and said the
  space-only form was still missed. It is read now. Go, PL/SQL, T-SQL and Visual Basic put
  the type after the name with no punctuation at all, so `var apiKey string = "<secret>"`,
  `const apiKey string = "<secret>"`, `v_password VARCHAR2(64) := '<secret>'`,
  `v_api_key CONSTANT VARCHAR2(64) := '<secret>'`, `DECLARE @api_key NVARCHAR(64) =
  '<secret>'`, `@password nvarchar(max) = '<secret>'`, `Dim apiKey As String = "<secret>"`
  and `Const apiSecret As String = "<secret>"` were all invisible.

  A space is a much weaker anchor than a colon, so this form is deliberately narrower than
  the colon form: the value must be QUOTED, and the type must be one of a fixed list of
  string type names (`string`, `str`, `varchar`, `varchar2`, `nvarchar`, `char`, `nchar`,
  `text`, `clob`, with an optional width) rather than any identifier. Two identifiers
  separated by a space are ordinary English; a key name followed by `string` and an `=` is
  not. So `var apiKey string = os.Getenv("API_KEY")` and `var apiKey string = defaultKey`
  are still declined as code, `Dim password As String` and `v_password VARCHAR2(64);` are
  still declarations rather than assignments, and a `--password string` line in a
  command's help output is still help output.

  Measured before shipping by running the new engine and the old one side by side over the
  installed Node tree, the installed Python tree, `/usr/share/doc` and `/usr/share/man`: no
  finding added, and no finding lost.

- **What is still missed, restated.** The sweep that found the space form found four
  families it does not fix, and the "what it misses" list on the web page now names the two
  that matter most: a variable whose NAME begins with a sigil (PHP and Perl's `$password =
  "<secret>"`) and a value whose LITERAL begins with one (Objective-C's `@"..."`, Python's
  `f"..."` and `b"..."`, C#'s `$"..."`). Each is a separate rule with its own cost to
  measure, not a widening of this one.

- **A credential declared with a type annotation raised nothing.** In a typed language the
  type sits between the name and the assignment operator, and the assignment rule had no
  room for one: it took the first separator, read the type as the value, and declined it.
  `api_key: str = "<secret>"` (Python), `const apiKey: string = "<secret>"` (TypeScript),
  `val apiSecret: String = "<secret>"` (Kotlin, Scala), `let api_key: &str = "<secret>"`
  (Rust), `let apiKey: String = "<secret>"` (Swift) and `Api_Secret : constant String :=
  "<secret>"` (Ada, Pascal, Delphi) were all invisible. They are found now. The annotation
  is accepted only in front of a QUOTED value: after a type, an unquoted value is code
  rather than a credential, so `resource_owner_secret: str = None):` and `self.old_keys:
  set[str] = set()` stay declined. The space-only form with no colon to anchor on
  (`var apiKey string = "<secret>"`) is a different family and is still missed; the
  "what it misses" list says so.

- **A placeholder value that begins with `=` is declined again.** Narrowing the
  "value starts with `=`" skip rule so it would stop swallowing `password := <secret>`
  also stopped it reading `"password": ==None`, a documentation placeholder, which briefly
  became a false positive. The rule now spells `:` as an operator again but requires
  whitespace before the `=`, which is the difference between a placeholder and an
  assignment written `:=`.

- **`password := "<secret>"` raised nothing.** The assignment rule spelled its separator
  as one of `:` or `=` plus an optional `>`, which cannot express `:=` at all — so a
  credential assigned with Go's short variable declaration, Make's simply-expanded
  assignment, or the assignment operator of Pascal, Ada and PL/SQL was invisible, in both
  the spaced and the glued spelling and for every quoting of the key and the value. Make's
  conditional assignment (`API_KEY ?= ...`) and R's `<-` were invisible for the same
  reason. All three are now read, in the rule and in all fourteen places its skip
  alternatives spell the separator. These were MISSED credentials.
- **A comparison is still not an assignment.** `password == candidate` and
  `password -> handler` are silent, deliberately: `==` is where a credential-named
  variable most often sits beside another identifier, and `->` is member access or a
  lambda, never an assignment. `+=` was implemented, measured against 18,427 real files,
  and removed again: it produced eleven false positives and no true ones.

- **A credential assigned through a subscript was invisible.** `os.environ['SECRET_KEY'] =
  '<secret>'` — the ordinary way a Python or JavaScript program sets one — produced no
  finding at all, because the assignment rule could read a quoted key but could not cross
  the `']` that closes it. It now can, in the rule and in every one of its skip
  alternatives. This was a MISSED credential.
- **A quoted string in a ternary is no longer read as a key.** `socket.authorized ?
  'authorized' : 'unauthorized'` reported `unauthorized` as a secret; the colon there is an
  operator, not an assignment. A password in a URL query string (`?password=...`) is a real
  assignment and is still caught — the difference is the quote, not the question mark.


- **A quoted key is still a key, and a single-quoted one was invisible.** `'password':
  'sXAm8YVh...'` — the ordinary way Python and black write a dict — produced no finding at
  all, while the same line with double quotes was redacted. The key's optional quote was
  spelled `"` and nothing else, in the assignment rule and in every one of its skip
  alternatives. It is now either quote character. This was a MISSED credential, not a
  cosmetic issue, and it was found by sweeping the true-positive corpus across eight key
  spellings rather than by reading the pattern.
- **The same two characters were also causing false positives, in the other direction.**
  Six of the nine skip alternatives that decline a non-credential VALUE SHAPE — a function
  call, a subscript, a dotted attribute — spelled the key half without that optional
  quote, so `"privkey": usage.CompleteFiles("*.pem"),` was reported as a secret while
  `privkey: usage.CompleteFiles("*.pem"),` one line below it was correctly ignored. Across
  two installed dependency trees this removed 106 false positives (55 in Python, 51 in
  JavaScript) and moved real log output and shipped documentation by exactly zero, which
  is what a rule about source-code syntax should do to a stream of values.

- **A comparison is not an assignment.** `if ssh_key==True:` in a Python source file was
  reported as a credential: the `assign` rule saw a name, a separator and a value, and the
  "value" it took was `=True:` — the right-hand side of a comparison, with the second `=`
  glued to the front. Any value that BEGINS with an equals sign is now declined, which is
  the whole family (`==`, `is None` written as `==None`, and the rest). Measured on an
  installed Python tree: this and its siblings are why a scan of library source came back
  noisier than the log the tool is named for. A value that merely CONTAINS an equals sign
  is untouched, deliberately — that is base64 padding, and declining it would silently
  unredact every padded secret in every log.

## 1.2.0

- **PGP secret keys.** `gpg --export-secret-keys --armor` writes a header ending in
  `PRIVATE KEY BLOCK-----`; every other armour type ends at `PRIVATE KEY-----`. The private
  key detector required the latter, so an armoured OpenPGP secret key — a whole keyring,
  not one key — passed through the entire detector set and came back clean. `BLOCK` is now
  optional in the header. `-----BEGIN PGP PUBLIC KEY BLOCK-----` is still untouched, and
  that edge is pinned in the false-positive corpus, because a public keyring is in every
  release-verification README there is.

- **Wallet seed phrases.** `MNEMONIC=<twelve words>` used to come back clean: no rule in
  this tool had the word `mnemonic` in it, so a BIP-39 seed phrase — the one credential
  here that cannot be rotated after it leaks — passed through untouched and unmentioned.
  There is now a detector for it, tagged `MNEMONIC`, over the usual key names (`mnemonic`,
  `seed_phrase`, `recovery phrase`, `seed_words`, and prefixed or suffixed forms of them) in
  every position: dotenv, YAML, JSON, quoted and bare.
  It is **all or nothing**. A phrase is replaced only at a word count BIP-39 actually uses —
  12, 15, 18, 21 or 24 — and any other count is declined WHOLE rather than clipped to
  twelve, because redacting twelve words of thirteen reports a finding you would read as
  handled while the seed is still on the line. A partial redaction of a seed phrase is worse
  than a miss.
  So that the decline is not silent, an illegal count now raises a **second look** row
  naming the word count and saying plainly that nothing was replaced. No BIP-39 word list
  ships: the key name carries the precision, which means a bare phrase with no key beside it
  is still invisible, and that limit is stated rather than papered over.

- **One tool instead of two.** `redactkit` was a second free CLI built from this same
  detector engine, reachable only as a tarball on one page — so a stranger who found both
  found two half-answers to one question. Its entire CLI now runs here, over `logscrub`'s
  library: one engine, one library, one command. Maps written by the old tool
  (`"kind": "redactkit-map"`) still restore, because a file someone already has must keep
  working.
- **A redaction you can undo.** `-m, --map FILE` writes the reverse map beside the output,
  and `--restore --map FILE` turns a redacted log back into the original — so you can share
  the scrubbed log, read the reply that quotes `[AWS_KEY_1]` back at you, and get your own
  values returned. The map is the one artefact `logscrub` writes that holds real
  credentials: it is written mode `600` and says so on stderr.
- **The second look.** A secret inside a base64 or hex run is invisible to every detector
  here, so the old answer was "nothing found" printed over a live token with `--check`
  exiting `0`. Each run that was not already redacted is now decoded, re-scanned with the
  same detectors and named by line. `--check` exits `1` on these too. It is on by default;
  `--no-review` turns it off and `--review-all` adds the noisier tier of long random
  strings and UUIDs — measured, over 116 credential-free formats, at
  105 rows across 41 of them, against zero for the
  default tier; leave it off in `--check`. It never prints the encoded run or the decoded value — only the file,
  the line, the encoding, the length, the tag and the detector. The absorbed tool printed
  28 characters of the run to help you find the blob; 28 characters of base64 over a live
  token is the front of that token in a scrollback, and the line number finds it anyway.
- **A policy file.** `--config FILE`, or `.logscrubrc.json` when one is present, so a repo
  says "this project does not care about phone numbers" once instead of in every hook
  invocation. Known keys are `enable`, `disable`, `prefix`, `numbered`, `review` and
  `reviewAll`; an unknown key is a hard error and exits `2`, because a typo silently
  ignored is a rule you believe is on and is not. Command-line flags win over the file, so
  a file nobody remembered can never override what the person at the terminal just typed.
- **New library exports** alongside `detect`, `redact` and `detectors`: `redactRun(chunks,
  opts)` for one pass over many named chunks with the numbering shared across all of them,
  `buildMap(result, meta)`, `restore(text, map)`, `effectiveDetectors(opts)`,
  `sniffBytes(bytes)` and `MAP_KINDS`. `redactRun`'s `findings` and `review` deliberately
  carry **no** `value` field — every consumer of those shapes writes them into a CI
  artifact or a scrollback. `entries` is the one place a real value appears, because that
  is the reverse map and its whole job is to hold them.

### CLI behaviour

- **A log piped in from a slow producer is now actually read.** `kubectl logs pod |
  logscrub`, `tail -f app.log | logscrub`, `docker logs -f web | logscrub` -- anything that
  produces output more slowly than this reads it -- used to print `nothing was replaced` and
  exit `0` having read none of the stream. Merely asking whether stdin was a terminal
  constructed a stream over file descriptor 0, which puts that descriptor into non-blocking
  mode for the whole process; the read then failed with `EAGAIN` the first moment the pipe
  was empty, and that failure was being swallowed into an empty input. An empty input is a
  clean verdict, so the worst outcome a redactor has -- calling a log safe to share without
  reading it -- was the outcome for the commonest way a log arrives. `cat big.log | logscrub`
  could never show it, because `cat` keeps the pipe full and no read ever finds it empty.
  stdin is now read in a loop that treats `EAGAIN` as "not yet" rather than as end of input,
  and any error that is genuinely an error exits `2` instead of reporting nothing found.

- **An empty input is no longer reported as a clean one.** The other half of the same
  failure: when the producer never wrote anything at all — `kubectl logs pod | logscrub >
  safe.log` where the command failed and put its diagnosis on its own stderr — the run
  printed `nothing was replaced; 34 of 37 rules ran` and exited `0`, and you walked away
  holding an empty file you believed had been scanned. Nothing on stdin in a run that owes
  you a redacted copy is now an error, exit `2`. A gate (`--check`) with nothing in front of
  it, and an empty file you NAMED, still exit `0` — an empty file leaks nothing and a
  pre-commit hook over a newly staged one must not fail — but both say `nothing was
  scanned. That is not a clean result, it is no result.` on stderr instead of the summary,
  and they say it even under `-q`.

- **Input is read as bytes, not as UTF-8, and the bytes decide.** A log PowerShell wrote
  with `>` is UTF-16; it used to be refused, and is now **decoded and scanned**, with a
  note on stderr saying what it was. Bytes that are not text at all — gzip, zip, PDF, an
  ELF binary — are refused by name and given the command that fixes them, rather than
  scanned into a meaningless all-clear. Bytes that are text in a legacy single-byte
  encoding are refused with the flag that reads them, because decoding them as UTF-8
  replaces every non-ASCII byte before the scan runs: the secrets are still found and the
  log around them is already destroyed. `-e, --encoding LABEL` forces the choice. Output is
  always UTF-8.
- **Four flag combinations that were silently ignored are now refusals**, exit `2`: `--out`
  with `--check`, which has no redacted text to write; `--map` with `--check`, which
  replaces nothing and so has nothing to map back; `--restore` with `--check`, which are
  opposite jobs; and a run where **every** detector is switched off, because an empty
  result there would not mean the input is clean — it would mean nothing looked, and with
  `-q` it would pass a pre-commit gate in silence. Each of these was a request the user
  made, got no error for, and believed had happened.
- **The `--json` payloads carry the second look and no longer carry `hazard`.** `--check`
  emits `{count, findings, review}`; a redacting run emits
  `{count, tags, findings, review, text}`. The encoding question is settled on the bytes
  before any scan starts, so there is no hazard left to report after one.

## 1.1.0

- **The CLI ships in the npm tarball for the first time.** `bin/logscrub.mjs` was in the
  repository but not in the published package, so `npx logscrub` reached a library-only
  tarball. `npm install logscrub` and `npx logscrub` now both give you the command, the
  pre-commit hook and the library from one install.
- **The package ships its own `npm test`**, so the examples in the README are executed
  against the code they document rather than asserted by hand.
- **Detector fixes from the false-positive corpus are folded in.** The rules are measured
  against `116` credential-free log and build formats, and every hit against that
  corpus is a false positive; this release carries the corrections that census produced.

### CLI behaviour

- `--check` with neither file arguments nor piped stdin is now a usage error and exits `2`,
  instead of blocking on a TTY waiting for input that was never coming.
- Placeholder numbering is **shared across multiple input files**, so the same secret carries
  the same number in every file of a multi-file run. It used to restart per file, which made
  a multi-file report impossible to correlate.
- A failed `--out` write now exits `2`, matching the other I/O failures, rather than `1` —
  which a `--check` caller would have read as "secrets found".

## 1.0.12

- **Connection strings whose username is itself an email address.** Cloud SQL IAM, Snowflake,
  Azure SQL and Databricks all authenticate this way, so the userinfo half holds an `@`
  before the one that ends it. The passwords-in-URLs rule forbade `@` there and could not see
  the password at all: `postgres://svc@x.iam.gserviceaccount.com:PASSWORD@10.9.8.7/app` came
  back with the password in the clear under an `EMAIL` tag. Both that rule and the email rule
  that guards its position were widened.

## 1.0.11

- **`detect()` gained a `.hazard` channel.** Before this it had none, so the obvious one-line
  gate — `if (detect(payload).length) throw` — waved through a UTF-16 log holding a live key.
  `.hazard` is non-enumerable, so the value is still a plain findings array to
  `JSON.stringify`, `for…in` and everything else.
- **Four ways a secret is plainly visible to a person and invisible to a scanner reading the
  bytes literally.** A colour escape in the middle of a token; a zero-width or other
  no-advance-width character between two halves of a key; a Cyrillic `а` or fullwidth `Ａ`
  standing in for the Latin letter. All three render to a reader as one unbroken secret and
  used to match nothing; each is now folded away before the detectors run, and a finding's
  `start`/`end` still point at the real span in the text you passed in.
- **Logs that had already been through another redactor.** Another tool's `[REDACTED]` and
  `****` placeholders were being reported as findings of their own, inflating the count on a
  log that was already clean. They no longer are, and a live secret sitting beside them is
  still caught.

## 1.0.10

- **A `Public by design` group.** Some values are shaped like credentials, named like
  credentials, and published on purpose — a Stripe or Clerk `pk_` publishable key, a Mapbox
  `pk.` token, a PostHog `phc_` project key, a Sentry DSN. They ship inside the JavaScript
  bundle of every page that uses them. They are still redacted, because a publishable key
  names your account, but they are tagged `PUBLISHABLE_KEY` rather than given a credential
  tag: reporting a published value as a leak makes the tool look better than it is, and the
  only person misled is the one reading the output.
- The rule reads the `pk_` / `pk.` convention, so it works for vendors it was never told
  about. What it cannot decide, it says so rather than guessing: a Google `AIza` key is
  byte-for-byte the same shape whether it is a browser key or a server key, and a Supabase
  anon key carries its public role inside the encoded JWT payload, so both stay under
  credentials — the safe direction to be wrong in.

## 1.0.9

- **Tokens in the `<slug>_live_` / `<slug>_test_` convention** that Stripe popularised and
  hundreds of APIs copied: one lowercase slug, an environment word, then the entropy. A list
  of vendor prefixes can only ever know vendors that already shipped; this rule reads the
  shape, so a key from a vendor nobody has heard of is caught the same way, including your
  own internal one. Narrowed against the false-positive corpus rather than by guesswork: the
  slug must be a single snake segment, `dev` is excluded as an environment word because it is
  too common in ordinary names, and the tail must pass the entropy check.
- **A Sentry DSN is no longer reported as a credential.** The key half of a modern DSN is
  public — it ships in the browser bundle of every site that uses Sentry — so it moved out of
  the credential group and its tag became `SENTRY_DSN`. It is still redacted by default, for
  the reason an IP address is: it names your organisation and project.

## 1.0.4

- **Encoding hazards are reported instead of scanned silently.** A log saved as UTF-16 — what
  Windows PowerShell writes from `>` and `Out-File` by default — stores every secret with a
  zero byte between each character, so nothing matches and the scan finds nothing. `hazard`
  is now set on both `redact()` and the CLI, which exits `2`. A blind scan and a clean scan
  produce the same empty output, and only one of them is good news.
