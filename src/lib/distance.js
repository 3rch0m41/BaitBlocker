// Distanza OSA: Levenshtein + trasposizioni adiacenti ("gogole" vs "google" = 1).
(function () {
  const BB = (globalThis.BB = globalThis.BB || {});

  function osaDistance(a, b, max = Infinity) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > max) return max + 1; // impossibile stare sotto soglia
    const n = b.length;
    let prev2 = new Array(n + 1).fill(0);                    // riga i-2 (serve alle trasposizioni)
    let prev = Array.from({ length: n + 1 }, (_, j) => j);   // riga i-1
    let cur = new Array(n + 1);                              // riga i
    for (let i = 1; i <= a.length; i++) {
      cur[0] = i;
      let rowMin = cur[0];
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        let v = Math.min(
          prev[j] + 1,        // cancellazione
          cur[j - 1] + 1,     // inserimento
          prev[j - 1] + cost  // sostituzione
        );
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          v = Math.min(v, prev2[j - 2] + 1); // trasposizione
        }
        cur[j] = v;
        if (v < rowMin) rowMin = v;
      }
      if (rowMin > max) return max + 1; // le righe successive non possono scendere: esci
      [prev2, prev, cur] = [prev, cur, prev2];
    }
    return prev[n];
  }

  function typoThreshold(len) {
    if (len <= 4) return 0;
    if (len <= 7) return 1;
    return 2;
  }

  BB.osaDistance = osaDistance;
  BB.typoThreshold = typoThreshold;
})();