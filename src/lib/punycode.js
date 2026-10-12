// Decoder Punycode (RFC 3492): "xn--80ak6aa92e" -> "аррӏе"
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;

  function adapt(delta, numPoints, firstTime) {
    let k = 0;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) {
      delta = Math.floor(delta / (base - tMin));
    }
    return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
  }

  function digitOf(cp) {
    if (cp >= 48 && cp <= 57) return cp - 22;   // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65;   // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97;  // a-z -> 0-25
    return base;
  }

  function decode(input) {
    const output = [];
    let i = 0, n = initialN, bias = initialBias;
    let basic = input.lastIndexOf("-");
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      const cp = input.charCodeAt(j);
      if (cp >= 0x80) throw new Error("invalid punycode");
      output.push(cp);
    }
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) throw new Error("invalid punycode");
        const digit = digitOf(input.charCodeAt(idx++));
        if (digit >= base) throw new Error("invalid punycode");
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  BB.punycodeToUnicodeLabel = function (label) {
    if (!label.startsWith("xn--")) return label;
    try { return decode(label.slice(4)); } catch (e) { return label; } // input malformato: lascialo com'è
  };

  BB.hostToUnicode = function (host) {
    return String(host).split(".").map(BB.punycodeToUnicodeLabel).join(".");
  };
})();