/* GENERATED FILE -- do not edit.
 *
 * Source: the second look inside https://levain.bmac.io/redact.html, the free browser
 * tool. Extracted by extract-secondlook.mjs, copied here by build-logscrub.mjs.
 * source sha256: 4af670f9a470fce3
 *
 * The page, the library and the CLI answer this by the same code, by construction.
 */

import { collect, DETECTORS, blankAnsi } from "./detectors.mjs";

/* ---- the second look --------------------------------------------------
 * Every detector above has to be precise enough to REPLACE with, because a
 * rule that fires wrongly rewrites a log somebody still has to read. That bar
 * disqualifies a whole class of real signal: things right often enough to
 * point at, and not often enough to act on. The precision a rule needs is set
 * by its CONSEQUENCE, not by how good the rule is -- so a heuristic that is
 * too eager to redact with can be exactly right to review with. Nothing below
 * ever edits the output. It produces a list to read.
 *
 * The first rule is the one that matters. A secret inside a base64 or hex run
 * is invisible to every detector above, because none of them are looking at
 * the text that run decodes to. Paste a Kubernetes Secret, a docker config, a
 * base64-wrapped .env out of a CI job, and this page reports nothing found
 * over a live credential -- the same clean bill of health over a blind scan
 * that the encoding warning exists to prevent, except in ordinary UTF-8 where
 * nothing looks wrong. So: decode the run, scan what comes out with the same
 * detectors, and if one fires in there, name it. One level of decoding, never
 * two, and a run whose decode is not text is dropped.
 */

/* Worth naming when it turns up INSIDE a decoded run. Personal data and the
   public-by-design tags are left out: they are worth replacing where they sit
   in the open, and not worth an alarm about the contents of a blob. */
var DECODED_TAGS = /^(?:AUTH_TOKEN|AWS_KEY|AZURE_KEY|BOT_TOKEN|CARD|GCP_SA_KEY|GITHUB_TOKEN|GOOGLE_API_KEY|JWT|K8S_SECRET|LLM_API_KEY|PACKAGE_TOKEN|PASSWORD|PRIVATE_KEY|SECRET|SLACK_TOKEN|STRIPE_KEY|VENDOR_TOKEN)$/;

/* Off-by-default detectors that earn a place in the review list. `phone` is
   deliberately not here: its false-alarm rate on log lines, version strings
   and timestamps is high enough to bury everything else in the panel, and a
   review list nobody reads is worse than no review list. */
var REVIEW_OFF = {hexblob:1, uuid:1};

/* Ceilings, so a large log cannot turn the review pass into a hang. */
var SL_MAX_RUNS = 600, SL_MAX_DECODED = 262144;

function mostlyText(s){
  if(s.length < 12) return false;
  var ok=0, letters=0, i, c;
  for(i=0;i<s.length;i++){
    c=s.charCodeAt(i);
    if(c===9||c===10||c===13||(c>=32&&c<127)) ok++;
    if((c>=65&&c<91)||(c>=97&&c<123)) letters++;
  }
  return ok >= s.length*0.9 && letters >= 4;
}

function b64decode(s){
  var t=s.replace(/-/g,"+").replace(/_/g,"/").replace(/=+$/,"");
  if(t.length % 4 === 1) return null;
  while(t.length % 4) t += "=";
  try { return atob(t); } catch(e){ return null; }
}

function hexdecode(s){
  if(s.length % 2) return null;
  var out="", i;
  for(i=0;i<s.length;i+=2) out += String.fromCharCode(parseInt(s.substr(i,2),16));
  return out;
}

function lineIndex(text){
  var starts=[0], i=text.indexOf("\n");
  while(i>=0){ starts.push(i+1); i=text.indexOf("\n", i+1); }
  return starts;
}
function lineAt(starts, pos){
  var lo=0, hi=starts.length-1;
  while(lo<hi){ var mid=(lo+hi+1)>>1; if(starts[mid]<=pos) lo=mid; else hi=mid-1; }
  return lo+1;
}

function labelFor(id){
  for(var i=0;i<DETECTORS.length;i++) if(DETECTORS[i].id === id) return DETECTORS[i].label;
  return id;
}

/* text: what the reader is about to share. spans: what was already replaced,
   so nothing already handled is raised twice. active: detector ids the reader
   has switched on, so a rule that is redacting is never also reviewed. */
function secondLook(text, spans, active){
  if(!text) return [];
  /* Same reason as collect(): a colour code is base64-legal on its face. The
     `3`, `2` and `m` of ESC[32m sit flush against the run they colour, so the
     run decodes to garbage and a named secret degrades into an anonymous
     "long random string". blankAnsi, not stripAnsi: this function is handed
     spans already measured against the original text, so its copy must keep
     every offset where it was. */
  text = blankAnsi(text);
  active = active || {};
  var cov = (spans||[]).map(function(s){ return [s.start, s.end]; })
                       .sort(function(a,b){ return a[0]-b[0]; });
  function covered(s,e){
    var lo=0, hi=cov.length-1;
    while(lo<=hi){
      var mid=(lo+hi)>>1;
      if(cov[mid][1] <= s) lo=mid+1;
      else if(cov[mid][0] >= e) hi=mid-1;
      else return true;
    }
    return false;
  }

  var starts = lineIndex(text), out = [], seen = {}, runs = 0, decoded = 0;

  /* A run that has already been raised must not be raised again by a broader
     rule. The high-entropy shape matches a UUID whole, and it matches the
     base64 run whose CONTENTS were just named -- and "long random string" is
     strictly less use to a reader than "this decodes to a GitHub token".
     Rules are applied most specific first and each claims its range. */
  var claimed = [];
  function taken(s,e){
    for(var i=0;i<claimed.length;i++) if(claimed[i][0] < e && claimed[i][1] > s) return true;
    return false;
  }

  function push(f){
    claimed.push([f.start, f.end]);
    var k = f.kind + " " + f.tag + " " + f.value;
    if(seen[k]){ seen[k].count++; return; }
    seen[k] = f; f.count = 1; out.push(f);
  }

  /* --- encoded runs -------------------------------------------------- */
  var ENCODED = [
    [/[A-Za-z0-9+\/_-]{24,}={0,2}/g, b64decode, "base64"],
    [/\b(?:[0-9a-fA-F]{2}){12,}\b/g, hexdecode, "hex"]
  ];
  for(var ei=0; ei<ENCODED.length; ei++){
    var re = ENCODED[ei][0], dec = ENCODED[ei][1], enc = ENCODED[ei][2], m;
    re.lastIndex = 0;
    while((m = re.exec(text)) !== null){
      if(runs++ > SL_MAX_RUNS || decoded > SL_MAX_DECODED) break;
      if(!m[0]){ re.lastIndex++; continue; }
      var s = m.index, e = s + m[0].length;
      if(covered(s,e) || taken(s,e)) continue;
      var plain = dec(m[0]);
      if(!plain || !mostlyText(plain)) continue;
      decoded += plain.length;
      var inner = collect(plain);
      for(var k=0; k<inner.length; k++){
        if(!DECODED_TAGS.test(inner[k].tag)) continue;
        push({kind:"decoded", enc:enc, tag:inner[k].tag, line:lineAt(starts, s),
              value:m[0].slice(0,28), start:s, end:e,
              detLabel:labelFor(inner[k].det)});
        break;   /* one row per run; the tag names what is in there */
      }
    }
  }

  /* --- a seed phrase whose word count BIP-39 does not use ------------- *
   * The mnemonic detector is ALL OR NOTHING: 12/15/18/21/24 words in full, or
   * nothing, because a partial redaction of a seed phrase reads to the user as
   * handled. That rule is right, and on its own it is HALF AN ANSWER. A value
   * sitting after `MNEMONIC=` with thirteen words is not a phrase this tool can
   * safely replace, and it is very obviously not nothing -- yet the run exits
   * clean, and an empty result looks like success in every language (060). So
   * the decline is REPORTED here instead of swallowed. Nothing is rewritten:
   * this is the channel for signal too imprecise to act on and too strong to
   * drop. A legal count never reaches this rule, because the detector already
   * claimed the span and covered() sees it.
   * The window is 8-32 words. Below eight there is nothing to distinguish from
   * a short sentence; above thirty-two nothing plausible is left. */
  var PHRASE_KEY = /\b(?<!\$)[A-Za-z0-9_.-]*(?:mnemonic|(?:seed|recovery|secret|backup|wallet)[ _-]?phrase|seed[ _-]?words)[A-Za-z0-9_.-]*(?:\\?")?[ \t]*[:=]>?[ \t]*["']?((?:[a-z]{3,8} ){7,31}[a-z]{3,8})(?![a-z])/gi;
  var BIP39_COUNTS = {12:1, 15:1, 18:1, 21:1, 24:1};
  PHRASE_KEY.lastIndex = 0;
  var pm;
  while((pm = PHRASE_KEY.exec(text)) !== null){
    if(!pm[0]){ PHRASE_KEY.lastIndex++; continue; }
    var pv = pm[1], pn = pv.split(" ").length;
    if(BIP39_COUNTS[pn]) continue;
    var ps = pm.index + pm[0].length - pv.length, pe = ps + pv.length;
    if(covered(ps, pe) || taken(ps, pe)) continue;
    push({kind:"phrase", tag:"MNEMONIC", det:"mnemonic", detLabel:"Wallet seed phrases (BIP-39 word counts)",
          words:pn, line:lineAt(starts, ps), value:pv, start:ps, end:pe});
  }

  /* --- what the redactor declined to act on -------------------------- */
  DETECTORS.forEach(function(d){
    if(d.on || active[d.id] || !REVIEW_OFF[d.id]) return;
    var re = new RegExp(d.re.source, d.re.flags), mm;
    while((mm = re.exec(text)) !== null){
      if(!mm[0]){ re.lastIndex++; continue; }
      var v = mm[0];
      if(covered(mm.index, mm.index + v.length) || taken(mm.index, mm.index + v.length)) continue;
      if(d.validate && !d.validate(v)) continue;
      if(d.skip && d.skip.test(v)) continue;
      push({kind:"unclaimed", tag:d.tag, det:d.id, detLabel:d.label,
            line:lineAt(starts, mm.index), value:v,
            start:mm.index, end:mm.index + v.length});
    }
  });

  out.sort(function(a,b){
    if(a.kind !== b.kind) return a.kind === "decoded" ? -1 : 1;
    return a.start - b.start;
  });
  return out;
}




export { secondLook, REVIEW_OFF, DECODED_TAGS };
