// Caratteri sosia (ispirato a Unicode TR39 "skeleton").
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  const UNICODE_MAP = {
    // Cirillico
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ӏ": "l", "ԁ": "d", "һ": "h", "ԛ": "q",
    "ԝ": "w", "к": "k",
    // Armeno
    "ո": "n", "ս": "u", "օ": "o", "ց": "g", "զ": "q", "հ": "h",
    // Latino "speciale" non decomponibile con NFD
    "ʏ": "y", "ɡ": "g", "ɑ": "a", "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h",
    "ƅ": "b", "ɩ": "i", "ȷ": "j", "ꞵ": "b",
    // Greco
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "χ": "x",
    "ω": "w", "ε": "e", "τ": "t", "η": "n", "ϲ": "c", "ϳ": "j",
    // Fullwidth e numeri romani
    "ａ": "a", "ｅ": "e", "ｏ": "o", "ⅼ": "l", "ⅰ": "i", "ⅽ": "c", "ⅾ": "d", "ⅿ": "m"
  };

  // Cifre e simboli usati come lettere nei typosquat ASCII ("1" è gestito a parte).
  const LEET = { "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a" };

  function scriptOf(ch) {
    const cp = ch.codePointAt(0);
    if ((cp >= 0x30 && cp <= 0x39) || ch === "-" || ch === "_") return null; // cifre e trattini: neutri
    if ((cp >= 0x61 && cp <= 0x7a) || (cp >= 0xc0 && cp <= 0x24f) || (cp >= 0x1e00 && cp <= 0x1eff) ||
        cp === 0x251 || cp === 0x261 || cp === 0x269) return "Latin";
    if (cp >= 0x400 && cp <= 0x52f) return "Cyrillic";
    if (cp >= 0x370 && cp <= 0x3ff) return "Greek";
    if (cp >= 0x530 && cp <= 0x58f) return "Armenian";
    if (cp >= 0x13a0 && cp <= 0x13ff) return "Cherokee";
    if (cp >= 0xff00 && cp <= 0xffef) return "Fullwidth";
    if (cp >= 0x4e00 && cp <= 0x9fff) return "Han";
    if (cp >= 0x3040 && cp <= 0x30ff) return "Kana";
    if (cp >= 0xac00 && cp <= 0xd7af) return "Hangul";
    if (cp >= 0x600 && cp <= 0x6ff) return "Arabic";
    if (cp >= 0x590 && cp <= 0x5ff) return "Hebrew";
    return "Other";
  }

  // Insieme degli alfabeti presenti in un'etichetta: { "Latin", "Cyrillic" } = misto.
  function scriptsIn(label) {
    const s = new Set();
    for (const ch of label) {
      const sc = scriptOf(ch);
      if (sc) s.add(sc);
    }
    return s;
  }

  // Unicode -> skeleton latino. `complete` = ogni carattere non ASCII aveva un sosia,
  // cioè l'intera etichetta può passare per latina.
  function unicodeSkeleton(label) {
    let out = "";
    let complete = true;
    for (const ch of label.toLowerCase()) {
      if (ch.charCodeAt(0) < 0x80) { out += ch; continue; }
      if (UNICODE_MAP[ch]) { out += UNICODE_MAP[ch]; continue; }
      const stripped = ch.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // é -> e
      if (stripped.length && stripped.charCodeAt(0) < 0x80) { out += stripped; continue; }
      out += ch;
      complete = false;
    }
    return { skeleton: out, complete };
  }

  // Tutte le "letture" plausibili di un'etichetta: "paypa1" -> [..., "paypal", "paypai"]
  function readingVariants(label) {
    const { skeleton } = unicodeSkeleton(label);
    const base = skeleton.replace(/[0345789$@]/g, (c) => LEET[c] || c);
    const variants = new Set([skeleton, base]);
    variants.add(base.replace(/1/g, "l"));
    variants.add(base.replace(/1/g, "i"));
    variants.add(base.replace(/rn/g, "m"));
    variants.add(base.replace(/vv/g, "w"));
    variants.add(base.replace(/1/g, "l").replace(/rn/g, "m").replace(/vv/g, "w"));
    variants.add(base.replace(/1/g, "i").replace(/rn/g, "m").replace(/vv/g, "w"));
    return [...variants];
  }

  BB.scriptsIn = scriptsIn;
  BB.unicodeSkeleton = unicodeSkeleton;
  BB.readingVariants = readingVariants;
})();