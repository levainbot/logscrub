/* GENERATED FILE -- do not edit.
 *
 * Source: the byte sniffer inside https://levain.bmac.io/redact.html, the free browser
 * tool. Extracted by extract-sniff.mjs, copied here by build-logscrub.mjs.
 * source sha256: b453c3e87ceb822b
 *
 * The page, the library and the CLI answer this by the same code, by construction.
 */

var MAGIC = [
  [[0x1f,0x8b], "gzip"],
  [[0x50,0x4b,0x03,0x04], "zip"],
  [[0x42,0x5a,0x68], "bzip2"],
  [[0xfd,0x37,0x7a,0x58,0x5a], "xz"],
  [[0x28,0xb5,0x2f,0xfd], "zstd"],
  [[0x7f,0x45,0x4c,0x46], "an ELF binary"],
  [[0x89,0x50,0x4e,0x47], "a PNG image"],
  [[0x25,0x50,0x44,0x46], "a PDF"],
  [[0x45,0x6c,0x66,0x46], "a Windows .evtx event log"],
  [[0x53,0x51,0x4c,0x69,0x74,0x65], "an SQLite database"]
];

function magicOf(b){
  for(var i=0;i<MAGIC.length;i++){
    var m=MAGIC[i][0], ok=b.length>=m.length;
    for(var j=0; ok && j<m.length; j++) if(b[j]!==m[j]) ok=false;
    if(ok) return MAGIC[i][1];
  }
  return null;
}

function utf8Ok(b){
  try { new TextDecoder("utf-8", {fatal:true}).decode(b); return true; }
  catch(e){ return false; }
}

/* Returns {enc, label, why, forced} -- forced means the bytes told us, so the
   picker starts there instead of at UTF-8 and the reason is stated. */
function sniff(b){
  if(b.length>=3 && b[0]===0xEF && b[1]===0xBB && b[2]===0xBF)
    return {enc:"utf-8", label:"UTF-8", why:"A UTF-8 byte-order mark starts the file.", forced:true};
  if(b.length>=2 && b[0]===0xFF && b[1]===0xFE)
    return {enc:"utf-16le", label:"UTF-16 LE", why:"A little-endian UTF-16 byte-order mark starts the file. This is what Windows PowerShell writes from > and Out-File. Read as UTF-8 it would look empty of secrets while being full of them; it has been decoded properly instead.", forced:true};
  if(b.length>=2 && b[0]===0xFE && b[1]===0xFF)
    return {enc:"utf-16be", label:"UTF-16 BE", why:"A big-endian UTF-16 byte-order mark starts the file. It has been decoded properly rather than scanned as bytes.", forced:true};
  var m=magicOf(b);
  if(m) return {enc:null, label:m, why:"This is " + m + ", not text. A pattern scanner reads nothing useful inside it, so a clean result would be meaningless. Decompress or export it to text first.", forced:true};
  var n=Math.min(b.length, 8192), even=0, odd=0, k;
  for(k=0;k<n;k++) if(b[k]===0){ if(k%2) odd++; else even++; }
  if(even+odd > n*0.2){
    if(odd > even*3) return {enc:"utf-16le", label:"UTF-16 LE", why:"Every other byte is zero, in the pattern little-endian UTF-16 makes. There is no byte-order mark, so nothing but the byte layout says so. Read as UTF-8 this file matches nothing at all.", forced:true};
    if(even > odd*3) return {enc:"utf-16be", label:"UTF-16 BE", why:"Every other byte is zero, in the pattern big-endian UTF-16 makes, with no byte-order mark to announce it.", forced:true};
    return {enc:null, label:"binary", why:"Zero bytes are scattered through this file in no text-like pattern. It is binary, and scanning it would prove nothing.", forced:true};
  }
  if(utf8Ok(b)) return {enc:"utf-8", label:"UTF-8", why:"", forced:false};
  return {enc:"windows-1252", label:"not UTF-8", forced:true,
    why:"These bytes are not valid UTF-8, so this is a legacy single- or double-byte encoding. Decoding it as UTF-8 would replace every non-ASCII character before the scan ever ran: the secrets would still be found and the surrounding log would already be destroyed, so saving the result over the original would lose it. Pick the encoding it was written in; Windows-1252 is the guess until you say otherwise."};
}


export { MAGIC, magicOf, utf8Ok, sniff };
