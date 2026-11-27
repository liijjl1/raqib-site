/* Raqib engine. Runs inside a Web Worker (or inline as a fallback).
   Holds the traffic simulator, the three detectors and all evaluation,
   so the interface thread only has to draw. */
function ENGINE(scope) {
  'use strict';

  const now = () => (typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now());
  const post = (msg, transfer) => scope.postMessage(msg, transfer || []);

  /* ------------------------------------------------------------------ *
   * Seeded random numbers                                              *
   * ------------------------------------------------------------------ */
  function makeRng(seed) {
    let s = (seed >>> 0) || 1;
    function next() {
      s = (s + 0x6D2B79F5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }
    let spare = NaN;
    function normal() {
      if (spare === spare) { const v = spare; spare = NaN; return v; }
      let u, v, q;
      do { u = next() * 2 - 1; v = next() * 2 - 1; q = u * u + v * v; } while (q === 0 || q >= 1);
      const f = Math.sqrt(-2 * Math.log(q) / q);
      spare = v * f;
      return u * f;
    }
    function gamma(k) {
      if (k < 1) return gamma(k + 1) * Math.pow(next() || 1e-12, 1 / k);
      const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d);
      for (;;) {
        let x, v;
        do { x = normal(); v = 1 + c * x; } while (v <= 0);
        v = v * v * v;
        const u = next();
        if (u < 1 - 0.0331 * x * x * x * x) return d * v;
        if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
      }
    }
    return {
      next,
      normal,
      int: (n) => Math.floor(next() * n),
      lognormal: (median, sigma) => median * Math.exp(sigma * normal()),
      beta: (a, b) => { const x = gamma(a), y = gamma(b); return x / (x + y); },
      poisson: (lam) => {
        if (lam <= 0) return 0;
        if (lam < 30) { const L = Math.exp(-lam); let k = 0, p = 1; do { k++; p *= next(); } while (p > L); return k - 1; }
        return Math.max(0, Math.round(lam + Math.sqrt(lam) * normal()));
      },
    };
  }

  function shuffleInPlace(a, rng) {
    for (let i = a.length - 1; i > 0; i--) { const j = rng.int(i + 1); const t = a[i]; a[i] = a[j]; a[j] = t; }
    return a;
  }
  function sampleRows(rows, k, rng) {
    if (rows.length <= k) return rows;
    const a = Int32Array.from(rows);
    for (let i = 0; i < k; i++) { const j = i + rng.int(a.length - i); const t = a[i]; a[i] = a[j]; a[j] = t; }
    return a.slice(0, k);
  }
  function percentile(sorted, p) {
    const n = sorted.length;
    if (!n) return 0;
    const pos = (p / 100) * (n - 1), lo = Math.floor(pos), hi = Math.min(n - 1, lo + 1);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
  }
  function gather(X, d, rows) {
    const out = new Float32Array(rows.length * d);
    for (let r = 0; r < rows.length; r++) {
      const src = rows[r] * d, dst = r * d;
      for (let j = 0; j < d; j++) out[dst + j] = X[src + j];
    }
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Traffic model (identical to the research notebook)                 *
   * ------------------------------------------------------------------ */
  const DEV_TYPES = ['camera', 'thermostat', 'smart_plug'];
  const PROTOS = ['TCP', 'UDP', 'ICMP'];
  const NUM_COLS = ['packet_rate', 'avg_packet_size', 'byte_rate', 'flow_duration', 'unique_dst_ports',
    'syn_ratio', 'failed_conn_ratio', 'telnet_ratio', 'outbound_ratio'];
  const CLASSES = ['Normal', 'DDoS', 'PortScan', 'BruteForce', 'Exfiltration'];

  // protocols, rate, size, duration = (median, spread) of log-normals; ports = Poisson mean; ratios = Beta(a, b)
  const P = (protos, rate, size, dur, ports, syn, failed, telnet, out) =>
    ({ protos: protos.map((p) => PROTOS.indexOf(p)), rate, size, dur, ports, syn, failed, telnet, out });
  const NORMAL = [
    P(['UDP', 'TCP'], [150, 0.5], [900, 0.25], [60, 0.8], 0, [1, 30], [1, 50], [1, 300], [9, 1]),
    P(['TCP'], [2, 0.7], [180, 0.35], [5, 0.7], 0, [2, 20], [1, 40], [1, 300], [5, 5]),
    P(['TCP', 'UDP'], [5, 0.7], [120, 0.35], [3, 0.7], 0, [2, 20], [1, 40], [1, 300], [4, 6]),
  ];
  const ATTACK = {
    1: [P(['TCP', 'UDP', 'ICMP'], [3000, 0.6], [70, 0.2], [20, 0.6], 0, [8, 2], [5, 5], [1, 300], [19, 1]),
      P(['TCP', 'UDP'], [60, 0.7], [150, 0.4], [20, 0.6], 0, [3, 8], [2, 15], [1, 300], [8, 2])],
    2: [P(['TCP'], [80, 0.6], [60, 0.15], [2, 0.6], 300, [9, 1], [8, 2], [1, 50], [6, 4]),
      P(['TCP'], [6, 0.7], [100, 0.3], [3, 0.7], 3, [3, 10], [2, 12], [1, 100], [5, 5])],
    3: [P(['TCP'], [40, 0.5], [90, 0.3], [10, 0.7], 1, [4, 4], [7, 3], [8, 2], [5, 5]),
      P(['TCP'], [5, 0.7], [120, 0.35], [4, 0.7], 0, [2, 15], [2, 15], [2, 20], [4, 6])],
    4: [P(['TCP'], [60, 0.6], [700, 0.3], [30, 0.8], 0, [2, 20], [1, 40], [1, 300], [9, 1]),
      P(['TCP'], [6, 0.7], [250, 0.35], [8, 0.8], 0, [2, 20], [1, 40], [1, 300], [7, 3])],
  };

  function sampleFlow(rng, prof, out) {
    const r = rng.lognormal(prof.rate[0], prof.rate[1]);
    const s = rng.lognormal(prof.size[0], prof.size[1]);
    out[0] = r;
    out[1] = s;
    out[2] = r * s;
    out[3] = rng.lognormal(prof.dur[0], prof.dur[1]);
    out[4] = rng.poisson(prof.ports) + 1;
    out[5] = rng.beta(prof.syn[0], prof.syn[1]);
    out[6] = rng.beta(prof.failed[0], prof.failed[1]);
    out[7] = rng.beta(prof.telnet[0], prof.telnet[1]);
    out[8] = rng.beta(prof.out[0], prof.out[1]);
    return prof.protos[rng.int(prof.protos.length)];
  }

  function emptySynthDs(n) {
    const cols = [
      { name: 'device_type', kind: 'cat', data: new Int32Array(n), cats: DEV_TYPES.slice() },
      { name: 'protocol', kind: 'cat', data: new Int32Array(n), cats: PROTOS.slice() },
    ];
    for (const nm of NUM_COLS) cols.push({ name: nm, kind: 'num', data: new Float32Array(n) });
    return { n, cols, label: new Int32Array(n), classes: CLASSES.slice(), normalClass: 0 };
  }

  // Same proportions as generate_iot_traffic() in the notebook.
  function makeSynthetic(seed, nNormal, nAttack) {
    const rng = makeRng(seed);
    const plan = [];
    const k = Math.floor(nNormal / 3);
    for (let t = 0; t < 3; t++) for (let i = 0; i < k; i++) plan.push([0, t, 0]);
    const a = Math.floor(nAttack / 4), loud = Math.floor(a * 0.7);
    for (let c = 1; c <= 4; c++) {
      for (let i = 0; i < a; i++) plan.push([c, c === 4 ? 1 + rng.int(2) : rng.int(3), i < loud ? 0 : 1]);
    }
    shuffleInPlace(plan, rng);
    const ds = emptySynthDs(plan.length);
    const vals = new Float64Array(9);
    for (let i = 0; i < plan.length; i++) {
      const [c, dev, st] = plan[i];
      const proto = sampleFlow(rng, c === 0 ? NORMAL[dev] : ATTACK[c][st], vals);
      ds.cols[0].data[i] = dev;
      ds.cols[1].data[i] = proto;
      for (let j = 0; j < 9; j++) ds.cols[2 + j].data[i] = vals[j];
      ds.label[i] = c;
    }
    return ds;
  }

  /* ------------------------------------------------------------------ *
   * Preprocessing: one-hot, log(1+x), standardisation (train rows only) *
   * ------------------------------------------------------------------ */
  function fitFeatures(ds, rows, exclude, rng) {
    const feats = [], dropped = [];
    ds.cols.forEach((col, c) => {
      if (exclude && exclude.has(c)) return;
      if (col.kind === 'num') feats.push({ c, oh: -1, name: col.name, col: col.name });
      else if (col.cats.length <= 20) col.cats.forEach((v, k) => feats.push({ c, oh: k, name: col.name + '=' + v, col: col.name, cat: v }));
      else dropped.push(col.name);
    });
    const d = feats.length;
    const med = new Float64Array(d), logf = new Uint8Array(d), mean = new Float64Array(d), std = new Float64Array(d);
    const samp = sampleRows(rows, 20000, rng);
    for (let j = 0; j < d; j++) {
      const f = feats[j];
      if (f.oh >= 0) { logf[j] = 1; continue; }
      const data = ds.cols[f.c].data, tmp = [];
      for (let r = 0; r < samp.length; r++) { const v = data[samp[r]]; if (Number.isFinite(v)) tmp.push(v); }
      tmp.sort((x, y) => x - y);
      med[j] = tmp.length ? tmp[tmp.length >> 1] : 0;
      let mn = Infinity;
      for (let r = 0; r < rows.length; r++) {
        let v = data[rows[r]];
        if (!Number.isFinite(v)) v = med[j];
        if (v < mn) mn = v;
      }
      logf[j] = mn >= 0 ? 1 : 0;
    }
    const fs = { d, feats, dropped, med, logf, mean, std, names: feats.map((f) => f.name) };
    const row = new Float64Array(d);
    const sum = new Float64Array(d), sq = new Float64Array(d);
    for (let r = 0; r < rows.length; r++) {
      rawRow(fs, ds, rows[r], row);
      for (let j = 0; j < d; j++) { sum[j] += row[j]; sq[j] += row[j] * row[j]; }
    }
    for (let j = 0; j < d; j++) {
      mean[j] = sum[j] / rows.length;
      const v = sq[j] / rows.length - mean[j] * mean[j];
      std[j] = v > 1e-12 ? Math.sqrt(v) : 1;
    }
    return fs;
  }
  function rawRow(fs, ds, i, out) {
    for (let j = 0; j < fs.d; j++) {
      const f = fs.feats[j], data = ds.cols[f.c].data;
      let v;
      if (f.oh >= 0) v = data[i] === f.oh ? 1 : 0;
      else { v = data[i]; if (!Number.isFinite(v)) v = fs.med[j]; }
      out[j] = fs.logf[j] ? Math.log1p(v > 0 ? v : 0) : v;
    }
  }
  const tmpRow = { buf: new Float64Array(0) };
  function transformRow(fs, ds, i, X, off) {
    if (tmpRow.buf.length < fs.d) tmpRow.buf = new Float64Array(fs.d);
    const row = tmpRow.buf;
    rawRow(fs, ds, i, row);
    for (let j = 0; j < fs.d; j++) X[off + j] = (row[j] - fs.mean[j]) / fs.std[j];
  }
  function transformAll(fs, ds) {
    const X = new Float32Array(ds.n * fs.d);
    for (let i = 0; i < ds.n; i++) transformRow(fs, ds, i, X, i * fs.d);
    return X;
  }

  /* ------------------------------------------------------------------ *
   * Isolation Forest                                                   *
   * ------------------------------------------------------------------ */
  function cFactor(n) {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    return 2 * (Math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n;
  }
  function trainIF(X, d, rows, opt) {
    const rng = makeRng(opt.seed || 11);
    const T = opt.trees || 200;
    const m = Math.min(opt.psi || 256, rows.length);
    const maxDepth = Math.ceil(Math.log2(Math.max(2, m)));
    const cap = T * 2 * m + 4;
    const feat = new Int16Array(cap), thr = new Float32Array(cap), left = new Int32Array(cap),
      right = new Int32Array(cap), size = new Int32Array(cap), roots = new Int32Array(T);
    const idx = new Int32Array(m);
    const stN = new Int32Array(2 * m + 8), stS = new Int32Array(2 * m + 8), stE = new Int32Array(2 * m + 8), stD = new Int32Array(2 * m + 8);
    const picked = new Set();
    let nn = 0;
    for (let t = 0; t < T; t++) {
      if (m === rows.length) { for (let i = 0; i < m; i++) idx[i] = rows[i]; }
      else {
        picked.clear();
        let c = 0;
        while (c < m) { const r = rows[rng.int(rows.length)]; if (!picked.has(r)) { picked.add(r); idx[c++] = r; } }
      }
      const root = nn++;
      roots[t] = root;
      let sp = 0;
      stN[sp] = root; stS[sp] = 0; stE[sp] = m; stD[sp] = 0; sp++;
      while (sp > 0) {
        sp--;
        const node = stN[sp], s = stS[sp], e = stE[sp], depth = stD[sp], cnt = e - s;
        if (depth >= maxDepth || cnt <= 1) { left[node] = -1; size[node] = cnt; continue; }
        let f = -1, lo = 0, hi = 0;
        for (let tries = 0; tries < d; tries++) {
          const ff = rng.int(d);
          let mn = Infinity, mx = -Infinity;
          for (let p = s; p < e; p++) { const v = X[idx[p] * d + ff]; if (v < mn) mn = v; if (v > mx) mx = v; }
          if (mx > mn) { f = ff; lo = mn; hi = mx; break; }
        }
        if (f < 0) { left[node] = -1; size[node] = cnt; continue; }
        const split = Math.fround(lo + rng.next() * (hi - lo));
        let i = s, j = e - 1;
        while (i <= j) {
          if (X[idx[i] * d + f] < split) i++;
          else { const tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; j--; }
        }
        if (i === s || i === e) { left[node] = -1; size[node] = cnt; continue; }
        feat[node] = f;
        thr[node] = split;
        const L = nn++, R = nn++;
        left[node] = L;
        right[node] = R;
        stN[sp] = L; stS[sp] = s; stE[sp] = i; stD[sp] = depth + 1; sp++;
        stN[sp] = R; stS[sp] = i; stE[sp] = e; stD[sp] = depth + 1; sp++;
      }
    }
    const cTab = new Float32Array(m + 1);
    for (let k = 0; k <= m; k++) cTab[k] = cFactor(k);
    return { T, m, feat, thr, left, right, size, roots, cTab, norm: cFactor(m), nodes: nn };
  }
  function ifScore(M, X, off) {
    const { T, feat, thr, left, right, size, roots, cTab } = M;
    let sum = 0;
    for (let t = 0; t < T; t++) {
      let node = roots[t], depth = 0;
      while (left[node] !== -1) { node = X[off + feat[node]] < thr[node] ? left[node] : right[node]; depth++; }
      sum += depth + cTab[size[node]];
    }
    return Math.pow(2, -(sum / T) / M.norm);
  }

  /* ------------------------------------------------------------------ *
   * Autoencoder  d -> 32 -> 16 -> 8 -> 16 -> 32 -> d  (Adam, MSE)      *
   * ------------------------------------------------------------------ */
  function makeAE(d, hidden, seed) {
    const rng = makeRng(seed || 5);
    const sizes = [d].concat(hidden, [d]);
    const L = sizes.length - 1;
    const W = [], b = [];
    for (let l = 0; l < L; l++) {
      const nin = sizes[l], nout = sizes[l + 1], lim = Math.sqrt(6 / (nin + nout));
      const w = new Float32Array(nin * nout);
      for (let i = 0; i < w.length; i++) w[i] = (rng.next() * 2 - 1) * lim;
      W.push(w);
      b.push(new Float32Array(nout));
    }
    return { d, sizes, L, W, b, acts: sizes.map((s) => new Float32Array(s)) };
  }
  function aeForward(ae, X, off) {
    const { sizes, L, W, b, acts } = ae;
    const a0 = acts[0];
    for (let i = 0; i < sizes[0]; i++) a0[i] = X[off + i];
    for (let l = 0; l < L; l++) {
      const nin = sizes[l], nout = sizes[l + 1], w = W[l], bb = b[l], ain = acts[l], aout = acts[l + 1], relu = l < L - 1;
      for (let j = 0; j < nout; j++) {
        let z = bb[j];
        const base = j * nin;
        for (let i = 0; i < nin; i++) z += w[base + i] * ain[i];
        aout[j] = relu && z < 0 ? 0 : z;
      }
    }
    return acts[L];
  }
  function aeError(ae, X, off, perFeat) {
    const out = aeForward(ae, X, off), d = ae.d;
    let s = 0;
    for (let i = 0; i < d; i++) {
      const e = out[i] - X[off + i], e2 = e * e;
      s += e2;
      if (perFeat) perFeat[i] = e2;
    }
    return s / d;
  }
  function adamStep(p, g, m, v, lr, c1, c2) {
    for (let i = 0; i < p.length; i++) {
      const gi = g[i];
      const mi = (m[i] = 0.9 * m[i] + 0.1 * gi);
      const vi = (v[i] = 0.999 * v[i] + 0.001 * gi * gi);
      p[i] -= (lr * (mi / c1)) / (Math.sqrt(vi / c2) + 1e-7);
    }
  }
  function trainAE(ae, X, rows, opt, onEpoch) {
    const d = ae.d, { sizes, L, W, b, acts } = ae;
    const rng = makeRng(opt.seed || 9);
    const all = shuffleInPlace(Int32Array.from(rows), rng);
    const nVal = Math.max(1, Math.floor(all.length * 0.1));
    const Xval = gather(X, d, all.subarray(0, nVal));
    const Xtr = gather(X, d, all.subarray(nVal));
    const nTr = all.length - nVal;
    const gW = W.map((w) => new Float32Array(w.length)), gb = b.map((x) => new Float32Array(x.length));
    const mW = W.map((w) => new Float32Array(w.length)), vW = W.map((w) => new Float32Array(w.length));
    const mb = b.map((x) => new Float32Array(x.length)), vb = b.map((x) => new Float32Array(x.length));
    const delta = sizes.map((s) => new Float32Array(s));
    const B = opt.batch || 128, lr = opt.lr || 1e-3, patience = opt.patience || 4;
    const order = new Int32Array(nTr);
    for (let i = 0; i < nTr; i++) order[i] = i;
    const history = { loss: [], val: [] };
    let step = 0, best = Infinity, bestW = null, bestB = null, bad = 0, bestEpoch = 0;
    for (let ep = 0; ep < opt.epochs; ep++) {
      shuffleInPlace(order, rng);
      let epLoss = 0;
      for (let s0 = 0; s0 < nTr; s0 += B) {
        const s1 = Math.min(nTr, s0 + B), scale = 2 / (d * (s1 - s0));
        for (let l = 0; l < L; l++) { gW[l].fill(0); gb[l].fill(0); }
        for (let s = s0; s < s1; s++) {
          const off = order[s] * d;
          const out = aeForward(ae, Xtr, off);
          const dl = delta[L];
          for (let i = 0; i < d; i++) { const e = out[i] - Xtr[off + i]; epLoss += e * e; dl[i] = e * scale; }
          for (let l = L - 1; l >= 0; l--) {
            const nin = sizes[l], nout = sizes[l + 1], w = W[l], g = gW[l], gbl = gb[l], ain = acts[l], dout = delta[l + 1];
            for (let j = 0; j < nout; j++) {
              const dj = dout[j];
              if (dj === 0) continue;
              gbl[j] += dj;
              const base = j * nin;
              for (let i = 0; i < nin; i++) g[base + i] += dj * ain[i];
            }
            if (l > 0) {
              const din = delta[l];
              for (let i = 0; i < nin; i++) {
                if (ain[i] <= 0) { din[i] = 0; continue; }
                let acc = 0;
                for (let j = 0; j < nout; j++) acc += w[j * nin + i] * dout[j];
                din[i] = acc;
              }
            }
          }
        }
        step++;
        const c1 = 1 - Math.pow(0.9, step), c2 = 1 - Math.pow(0.999, step);
        for (let l = 0; l < L; l++) { adamStep(W[l], gW[l], mW[l], vW[l], lr, c1, c2); adamStep(b[l], gb[l], mb[l], vb[l], lr, c1, c2); }
      }
      let vl = 0;
      for (let r = 0; r < nVal; r++) vl += aeError(ae, Xval, r * d);
      vl /= nVal;
      const tl = epLoss / (nTr * d);
      history.loss.push(tl);
      history.val.push(vl);
      if (onEpoch) onEpoch(ep + 1, tl, vl);
      if (vl < best - 1e-6) { best = vl; bestEpoch = ep + 1; bad = 0; bestW = W.map((w) => w.slice()); bestB = b.map((x) => x.slice()); }
      else if (++bad >= patience) break;
    }
    if (bestW) for (let l = 0; l < L; l++) { W[l].set(bestW[l]); b[l].set(bestB[l]); }
    return { history, bestEpoch, epochs: history.loss.length, nTrain: nTr };
  }

  /* ------------------------------------------------------------------ *
   * Random Forest (histogram splits on quantised features, Gini)       *
   * ------------------------------------------------------------------ */
  function makeBins(X, d, rows, maxBins, rng) {
    const samp = sampleRows(rows, 20000, rng);
    const tmp = new Float32Array(samp.length);
    const edges = [];
    for (let f = 0; f < d; f++) {
      for (let i = 0; i < samp.length; i++) tmp[i] = X[samp[i] * d + f];
      tmp.sort();
      const e = [];
      for (let q = 1; q < maxBins; q++) {
        const v = tmp[Math.floor((q * tmp.length) / maxBins)];
        if (!e.length || v > e[e.length - 1]) e.push(v);
      }
      if (e.length && e[e.length - 1] >= tmp[tmp.length - 1]) e.pop();
      edges.push(Float32Array.from(e));
    }
    return edges;
  }
  function binCode(edges, x) {
    let lo = 0, hi = edges.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (edges[mid] < x) lo = mid + 1; else hi = mid; }
    return lo;
  }
  function makeCodes(X, d, n, edges) {
    const C = new Uint8Array(n * d);
    for (let f = 0; f < d; f++) {
      const e = edges[f], base = f * n;
      for (let i = 0; i < n; i++) C[base + i] = binCode(e, X[i * d + f]);
    }
    return C;
  }
  function trainRF(C, n, d, edges, rows, y, K, opt) {
    const rng = makeRng(opt.seed || 21);
    const T = opt.trees || 60, maxDepth = opt.maxDepth || 14, minLeaf = opt.minLeaf || 2;
    const mtry = Math.max(1, Math.round(Math.sqrt(d)));
    const nb = edges.map((e) => e.length + 1), maxNb = Math.max.apply(null, nb);
    const cnt = new Float64Array(K);
    for (let r = 0; r < rows.length; r++) cnt[y[rows[r]]]++;
    const w = new Float64Array(K);
    for (let k = 0; k < K; k++) w[k] = cnt[k] > 0 ? rows.length / (K * cnt[k]) : 0;

    let cap = 1 << 12, pcap = 1 << 12;
    let feat = new Int16Array(cap), bin = new Uint8Array(cap), left = new Int32Array(cap), right = new Int32Array(cap), leaf = new Int32Array(cap);
    let probs = new Float32Array(pcap * K);
    let nn = 0, np = 0;
    function alloc() {
      if (nn >= cap) {
        cap *= 2;
        const f2 = new Int16Array(cap); f2.set(feat); feat = f2;
        const b2 = new Uint8Array(cap); b2.set(bin); bin = b2;
        const l2 = new Int32Array(cap); l2.set(left); left = l2;
        const r2 = new Int32Array(cap); r2.set(right); right = r2;
        const v2 = new Int32Array(cap); v2.set(leaf); leaf = v2;
      }
      return nn++;
    }
    const tot = new Float64Array(K), lc = new Float64Array(K);
    function makeLeaf(node, W) {
      left[node] = -1;
      if (np >= pcap) { pcap *= 2; const p2 = new Float32Array(pcap * K); p2.set(probs); probs = p2; }
      leaf[node] = np;
      for (let k = 0; k < K; k++) probs[np * K + k] = W > 0 ? tot[k] / W : 0;
      np++;
    }
    const roots = new Int32Array(T);
    const imp = new Float64Array(d), treeImp = new Float64Array(d);
    const N = rows.length, idx = new Int32Array(N);
    const hist = new Float64Array(maxNb * K), hcnt = new Int32Array(maxNb);
    const fidx = new Int32Array(d);
    for (let f = 0; f < d; f++) fidx[f] = f;
    const stack = [];
    for (let t = 0; t < T; t++) {
      for (let i = 0; i < N; i++) idx[i] = rows[rng.int(N)];
      treeImp.fill(0);
      const root = alloc();
      roots[t] = root;
      stack.push(root, 0, N, 0);
      while (stack.length) {
        const depth = stack.pop(), e = stack.pop(), s = stack.pop(), node = stack.pop();
        tot.fill(0);
        for (let p = s; p < e; p++) { const k = y[idx[p]]; tot[k] += w[k]; }
        let W = 0, sq = 0, nz = 0;
        for (let k = 0; k < K; k++) { W += tot[k]; sq += tot[k] * tot[k]; if (tot[k] > 0) nz++; }
        const count = e - s;
        if (depth >= maxDepth || count < 2 * minLeaf || nz <= 1 || W <= 0) { makeLeaf(node, W); continue; }
        const parent = sq / W;
        let bestGain = 1e-9, bestF = -1, bestB = -1;
        for (let a = 0; a < mtry; a++) { const j = a + rng.int(d - a); const tmp = fidx[a]; fidx[a] = fidx[j]; fidx[j] = tmp; }
        for (let a = 0; a < mtry; a++) {
          const f = fidx[a], B = nb[f];
          if (B < 2) continue;
          const base = f * n;
          hist.fill(0, 0, B * K);
          hcnt.fill(0, 0, B);
          for (let p = s; p < e; p++) { const r = idx[p], c = C[base + r], k = y[r]; hist[c * K + k] += w[k]; hcnt[c]++; }
          lc.fill(0);
          let WL = 0, nL = 0, sqL = 0, sqR = sq;
          for (let bb = 0; bb < B - 1; bb++) {
            if (hcnt[bb] === 0) continue;
            const hb = bb * K;
            for (let k = 0; k < K; k++) {
              const h = hist[hb + k];
              if (h === 0) continue;
              const l0 = lc[k], r0 = tot[k] - l0, l1 = l0 + h, r1 = r0 - h;
              sqL += l1 * l1 - l0 * l0;
              sqR += r1 * r1 - r0 * r0;
              lc[k] = l1;
              WL += h;
            }
            nL += hcnt[bb];
            if (nL < minLeaf) continue;
            if (count - nL < minLeaf) break;
            const WR = W - WL;
            if (WL <= 0 || WR <= 0) continue;
            const gain = sqL / WL + sqR / WR - parent;
            if (gain > bestGain) { bestGain = gain; bestF = f; bestB = bb; }
          }
        }
        if (bestF < 0) { makeLeaf(node, W); continue; }
        const base = bestF * n;
        let i = s, j = e - 1;
        while (i <= j) {
          if (C[base + idx[i]] <= bestB) i++;
          else { const tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; j--; }
        }
        feat[node] = bestF;
        bin[node] = bestB;
        leaf[node] = -1;
        treeImp[bestF] += bestGain;
        const Lc = alloc(), Rc = alloc();
        left[node] = Lc;
        right[node] = Rc;
        stack.push(Lc, s, i, depth + 1, Rc, i, e, depth + 1);
      }
      let sImp = 0;
      for (let f = 0; f < d; f++) sImp += treeImp[f];
      if (sImp > 0) for (let f = 0; f < d; f++) imp[f] += treeImp[f] / sImp;
    }
    for (let f = 0; f < d; f++) imp[f] /= T;
    return { T, K, roots, feat, bin, left, right, leaf, probs, importance: imp, nodes: nn };
  }
  function rfProba(M, C, n, r, out) {
    const { T, K, roots, feat, bin, left, right, leaf, probs } = M;
    out.fill(0);
    for (let t = 0; t < T; t++) {
      let node = roots[t];
      while (left[node] !== -1) node = C[feat[node] * n + r] <= bin[node] ? left[node] : right[node];
      const o = leaf[node] * K;
      for (let k = 0; k < K; k++) out[k] += probs[o + k];
    }
    for (let k = 0; k < K; k++) out[k] /= T;
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Threshold-free evaluation                                          *
   * ------------------------------------------------------------------ */
  function aucRoc(y, s, points) {
    const n = y.length;
    const idx = new Int32Array(n);
    for (let i = 0; i < n; i++) idx[i] = i;
    idx.sort((a, b) => s[b] - s[a]);
    let P = 0;
    for (let i = 0; i < n; i++) P += y[i];
    const N = n - P;
    if (!P || !N) return { auc: NaN, roc: [[0, 0], [1, 1]] };
    let tp = 0, fp = 0, auc = 0, prevFpr = 0, prevTpr = 0;
    const roc = [[0, 0]];
    const every = Math.max(1, Math.floor(n / (points || 160)));
    let i = 0, step = 0;
    while (i < n) {
      let j = i;
      const v = s[idx[i]];
      while (j < n && s[idx[j]] === v) { if (y[idx[j]]) tp++; else fp++; j++; }
      const fpr = fp / N, tpr = tp / P;
      auc += (fpr - prevFpr) * (tpr + prevTpr) / 2;
      prevFpr = fpr;
      prevTpr = tpr;
      step += j - i;
      if (step >= every || j === n) { roc.push([fpr, tpr]); step = 0; }
      i = j;
    }
    return { auc, roc };
  }

  /* ------------------------------------------------------------------ *
   * Full training + evaluation pipeline (shared by demo data and CSV)  *
   * ------------------------------------------------------------------ */
  function runPipeline(ds, cfg, progress) {
    const t0 = now();
    const rng = makeRng(cfg.seed || 42);
    const n = ds.n, K = ds.classes.length;
    const yBin = new Uint8Array(n);
    let usable = [];
    for (let i = 0; i < n; i++) {
      if (ds.label[i] < 0) continue;
      usable.push(i);
      yBin[i] = ds.label[i] === ds.normalClass ? 0 : 1;
    }
    usable = Int32Array.from(usable);
    // stratified 70 / 30 split
    const pos = [], neg = [];
    for (let r = 0; r < usable.length; r++) (yBin[usable[r]] ? pos : neg).push(usable[r]);
    shuffleInPlace(pos, rng);
    shuffleInPlace(neg, rng);
    const tp = Math.round(pos.length * 0.3), tn = Math.round(neg.length * 0.3);
    let test = Int32Array.from(pos.slice(0, tp).concat(neg.slice(0, tn)));
    const train = shuffleInPlace(Int32Array.from(pos.slice(tp).concat(neg.slice(tn))), rng);
    if (cfg.testMax && test.length > cfg.testMax) test = sampleRows(test, cfg.testMax, rng);
    const trainNormal = [];
    for (let r = 0; r < train.length; r++) if (!yBin[train[r]]) trainNormal.push(train[r]);
    if (trainNormal.length < 30) throw new Error('NOT_ENOUGH_NORMAL');
    if (tp < 1) throw new Error('NO_ANOMALIES');
    const trainNormalArr = Int32Array.from(trainNormal);

    progress('prep', 0);
    const tp0 = now();
    const fs = fitFeatures(ds, train, cfg.exclude, rng);
    if (!fs.d) throw new Error('NO_FEATURES');
    const X = transformAll(fs, ds);
    const tPrep = now() - tp0;
    const d = fs.d;

    // Isolation Forest — trained on normal traffic only
    progress('if', 0);
    const ti0 = now();
    const ifm = trainIF(X, d, trainNormalArr, { trees: 200, psi: 256, seed: 11 });
    const tIF = now() - ti0;
    const nScore = sampleRows(trainNormalArr, cfg.normScoreMax || 20000, rng);
    const ifTrain = new Float32Array(nScore.length);
    for (let r = 0; r < nScore.length; r++) ifTrain[r] = ifScore(ifm, X, nScore[r] * d);
    const ifTest = new Float32Array(test.length);
    const tis = now();
    for (let r = 0; r < test.length; r++) ifTest[r] = ifScore(ifm, X, test[r] * d);
    const usIF = ((now() - tis) * 1000) / Math.max(1, test.length);

    // Autoencoder — trained on normal traffic only
    progress('ae', 0);
    const ta0 = now();
    const ae = makeAE(d, [32, 16, 8, 16, 32], 5);
    const aeRows = sampleRows(trainNormalArr, cfg.aeMax || 8000, rng);
    const aeEpochs = cfg.aeEpochs || 30;
    const aeInfo = trainAE(ae, X, aeRows, { epochs: aeEpochs, batch: cfg.aeBatch || 128, lr: cfg.aeLr || 1e-3, patience: 4, seed: 9 },
      (ep, tl, vl) => progress('ae', ep / aeEpochs, { epoch: ep, epochs: aeEpochs, loss: tl, val: vl }));
    const tAE = now() - ta0;
    const aeTrain = new Float32Array(nScore.length);
    for (let r = 0; r < nScore.length; r++) aeTrain[r] = aeError(ae, X, nScore[r] * d);
    const aeTest = new Float32Array(test.length);
    const tas = now();
    for (let r = 0; r < test.length; r++) aeTest[r] = aeError(ae, X, test[r] * d);
    const usAE = ((now() - tas) * 1000) / Math.max(1, test.length);

    // Random Forest — supervised, class-balanced
    progress('rf', 0);
    const tr0 = now();
    const edges = makeBins(X, d, train, 32, rng);
    const C = makeCodes(X, d, n, edges);
    const multi = !!cfg.multiClass;
    const yRF = multi ? ds.label : new Int32Array(n);
    if (!multi) for (let i = 0; i < n; i++) yRF[i] = yBin[i];
    const KRF = multi ? K : 2;
    const normalRF = multi ? ds.normalClass : 0;
    const rfRows = cfg.rfMax && train.length > cfg.rfMax ? sampleRows(train, cfg.rfMax, rng) : train;
    const rf = trainRF(C, n, d, edges, rfRows, yRF, KRF, { trees: cfg.rfTrees || 60, maxDepth: 14, minLeaf: 2, seed: 21 });
    const tRF = now() - tr0;
    const pr = new Float64Array(KRF);
    const rfTest = new Float32Array(test.length);
    const trs = now();
    for (let r = 0; r < test.length; r++) { rfProba(rf, C, n, test[r], pr); rfTest[r] = 1 - pr[normalRF]; }
    const usRF = ((now() - trs) * 1000) / Math.max(1, test.length);

    // Zero-day experiment: hide one attack type from the Random Forest
    progress('zd', 0);
    const tz0 = now();
    const typeCount = new Map();
    for (let r = 0; r < train.length; r++) { const c = ds.label[train[r]]; if (c !== ds.normalClass) typeCount.set(c, (typeCount.get(c) || 0) + 1); }
    const zdTypes = Array.from(typeCount.entries()).sort((a, b) => b[1] - a[1]).slice(0, cfg.zdMax || 6).map((e) => e[0]);
    const zeroDay = [];
    zdTypes.forEach((cls, zi) => {
      const keep = [];
      for (let r = 0; r < rfRows.length; r++) if (ds.label[rfRows[r]] !== cls) keep.push(rfRows[r]);
      const m2 = trainRF(C, n, d, edges, Int32Array.from(keep), yRF, KRF, { trees: cfg.zdTrees || 30, maxDepth: 14, minLeaf: 2, seed: 31 + zi });
      let hit = 0, tot = 0;
      for (let r = 0; r < test.length; r++) {
        if (ds.label[test[r]] !== cls) continue;
        rfProba(m2, C, n, test[r], pr);
        tot++;
        if (1 - pr[normalRF] >= 0.5) hit++;
      }
      zeroDay.push({ cls, rf: tot ? hit / tot : NaN, n: tot });
      progress('zd', (zi + 1) / zdTypes.length);
    });
    const tZD = now() - tz0;

    const yTest = new Uint8Array(test.length), typeTest = new Int32Array(test.length);
    for (let r = 0; r < test.length; r++) { yTest[r] = yBin[test[r]]; typeTest[r] = ds.label[test[r]]; }
    const ev = { if: aucRoc(yTest, ifTest, 160), ae: aucRoc(yTest, aeTest, 160), rf: aucRoc(yTest, rfTest, 160) };
    ifTrain.sort();
    aeTrain.sort();
    const imp = Array.from(rf.importance).map((v, j) => ({ name: fs.names[j], value: v })).sort((a, b) => b.value - a.value).slice(0, 12);

    const report = {
      title: cfg.title || '',
      n, nTrain: train.length, nTest: test.length, nNormalTrain: trainNormal.length, d,
      featNames: fs.names, dropped: fs.dropped, excludedNames: cfg.excludedNames || [],
      classes: ds.classes, normalClass: ds.normalClass,
      yTest, typeTest,
      scores: { if: ifTest, ae: aeTest, rf: rfTest },
      trainNorm: { if: ifTrain, ae: aeTrain },
      auc: { if: ev.if.auc, ae: ev.ae.auc, rf: ev.rf.auc },
      roc: { if: ev.if.roc, ae: ev.ae.roc, rf: ev.rf.roc },
      importance: imp,
      ae: { history: aeInfo.history, bestEpoch: aeInfo.bestEpoch, epochs: aeInfo.epochs, nTrain: aeInfo.nTrain },
      rfInfo: { trees: rf.T, nodes: rf.nodes, multi, nTrain: rfRows.length },
      ifInfo: { trees: ifm.T, psi: ifm.m },
      zeroDay,
      timing: { prep: tPrep, if: tIF, ae: tAE, rf: tRF, zd: tZD, total: now() - t0 },
      us: { prep: (tPrep * 1000) / n, if: usIF, ae: usAE, rf: usRF },
    };
    const models = { fs, X, ifm, ae, rf, edges, KRF, normalRF, ifTrainSorted: ifTrain, aeTrainSorted: aeTrain };
    return { report, models };
  }
  function reportTransfer(r) {
    return [r.yTest.buffer, r.typeTest.buffer, r.scores.if.buffer, r.scores.ae.buffer, r.scores.rf.buffer, r.trainNorm.if.buffer, r.trainNorm.ae.buffer];
  }
  function cloneReport(r) {
    return Object.assign({}, r, {
      yTest: r.yTest.slice(), typeTest: r.typeTest.slice(),
      scores: { if: r.scores.if.slice(), ae: r.scores.ae.slice(), rf: r.scores.rf.slice() },
      trainNorm: { if: r.trainNorm.if.slice(), ae: r.trainNorm.ae.slice() },
    });
  }

  /* ------------------------------------------------------------------ *
   * Live monitoring                                                    *
   * ------------------------------------------------------------------ */
  const LIVE = {
    ready: false, running: false, timer: null, speed: 2, policy: 'majority', pct: 99.5, auto: true,
    tick: 0, t0: Date.now(), devices: [], rng: makeRng(2026), models: null, thr: null,
    incidents: [], incSeq: 0, nextAuto: 8,
    m: { tp: 0, fp: 0, fn: 0, tn: 0, records: 0, incTrue: 0, incFalse: 0, launched: 0, detected: 0, missed: 0, ttdSum: 0, ttdN: 0 },
    perf: { us: 0, n: 0 },
    batch: null, Xb: null, Cb: null, pr: null, perFeat: null, raw: null,
  };

  const DEMO_CFG = () => ({ seed: 42, multiClass: true, aeMax: 6000, aeEpochs: 20, aeLr: 2e-3, rfTrees: 60, zdTrees: 30, zdMax: 4, title: 'demo' });

  function labReport(msg) {
    const ds = makeSynthetic(42, 21000, 6000);
    const { report } = runPipeline(ds, Object.assign(DEMO_CFG(), msg.cfg || {}),
      (stage, pct, extra) => post({ type: 'progress', job: 'lab', stage, pct, extra }));
    post({ type: 'labReport', report }, reportTransfer(report));
  }

  function calib(sorted, pct) {
    const thr = percentile(sorted, pct);
    const med = percentile(sorted, 50);
    const lr = Math.log(med / thr);
    const k = lr < -1e-9 ? -2.1972 / lr : 8;
    return { thr, k };
  }
  function setThresholds() {
    const M = LIVE.models;
    LIVE.thr = { if: calib(M.ifTrainSorted, LIVE.pct), ae: calib(M.aeTrainSorted, LIVE.pct) };
  }
  function riskOf(c, s) {
    if (!(s > 0)) return 0;
    return 100 / (1 + Math.pow(s / c.thr, -c.k));
  }
  function aggregate(r) {
    const a = r[0], b = r[1], c = r[2];
    switch (LIVE.policy) {
      case 'any': return Math.max(a, b, c);
      case 'all': return Math.min(a, b, c);
      case 'if': return a;
      case 'ae': return b;
      case 'rf': return c;
      default: return Math.max(Math.min(a, b), Math.min(Math.max(a, b), c));
    }
  }

  function initLive(msg) {
    const t0 = now();
    const ds = makeSynthetic(42, 21000, 6000);
    const { report, models } = runPipeline(ds, Object.assign(DEMO_CFG(), { zdMax: 0 }, msg.cfg || {}),
      (stage, pct, extra) => post({ type: 'progress', job: 'live', stage, pct, extra }));
    // per-device-type baseline (median of each raw numeric feature over normal training traffic)
    const baseline = DEV_TYPES.map((_, t) => NUM_COLS.map((_, j) => {
      const vals = [];
      for (let i = 0; i < ds.n && vals.length < 4000; i++) if (ds.label[i] === 0 && ds.cols[0].data[i] === t) vals.push(ds.cols[2 + j].data[i]);
      vals.sort((a, b) => a - b);
      return vals.length ? vals[vals.length >> 1] : 0;
    }));
    LIVE.models = models;
    LIVE.devices = (msg.devices || []).map((type, i) => ({ i, type, attack: null, recent: [], inc: null }));
    const nd = LIVE.devices.length, d = models.fs.d;
    LIVE.batch = emptySynthDs(nd);
    LIVE.Xb = new Float32Array(nd * d);
    LIVE.Cb = new Uint8Array(nd * d);
    LIVE.pr = new Float64Array(models.KRF);
    LIVE.perFeat = new Float32Array(d);
    LIVE.raw = new Float64Array(9);
    if (msg.pct) LIVE.pct = msg.pct;
    if (msg.policy) LIVE.policy = msg.policy;
    if (msg.speed) LIVE.speed = msg.speed;
    if (typeof msg.auto === 'boolean') LIVE.auto = msg.auto;
    setThresholds();
    LIVE.ready = true;
    LIVE.t0 = Date.now();
    const featMeta = models.fs.feats.map((f) => ({ name: f.name, col: f.col, oh: f.oh, cat: f.cat || null, num: f.oh < 0 ? NUM_COLS.indexOf(f.col) : -1 }));
    const quick = runBench(8000);
    const out = cloneReport(report);
    post({ type: 'ready', report: out, featMeta, baseline, numCols: NUM_COLS, classes: CLASSES, bootMs: now() - t0, t0: LIVE.t0, bench: quick }, reportTransfer(out));
    setRunning(msg.run !== false);
  }

  function setRunning(on) {
    LIVE.running = !!on && LIVE.ready;
    if (LIVE.timer) { clearTimeout(LIVE.timer); LIVE.timer = null; }
    if (LIVE.running) LIVE.timer = setTimeout(loop, 0);
    post({ type: 'state', running: LIVE.running });
  }
  function loop() {
    LIVE.timer = null;
    if (!LIVE.running) return;
    const t = now();
    liveTick();
    const iv = 1000 / LIVE.speed;
    LIVE.timer = setTimeout(loop, Math.max(0, iv - (now() - t)));
  }

  function launchAttack(dev, kind, stealth, duration, first) {
    const D = LIVE.devices[dev];
    if (!D || kind < 1 || kind > 4) return;
    const start = first || LIVE.tick + 1;
    if (D.attack) endAttack(D);
    D.attack = { kind, stealth: stealth ? 1 : 0, start, end: start + Math.max(3, duration | 0) - 1, detected: false };
    LIVE.m.launched++;
  }
  function endAttack(D) {
    if (D.attack.detected) LIVE.m.detected++; else LIVE.m.missed++;
    D.attack = null;
  }

  function liveTick() {
    const L = LIVE, M = L.models, fs = M.fs, d = fs.d, nd = L.devices.length, rng = L.rng;
    const tick = ++L.tick;
    // auto demo: keep a couple of attacks going
    if (L.auto && tick >= L.nextAuto) {
      const active = L.devices.filter((D) => D.attack).length;
      if (active < 2) {
        const kind = 1 + rng.int(4);
        const pool = L.devices.filter((D) => !D.attack && (kind !== 4 || D.type !== 0));
        if (pool.length) {
          const D = pool[rng.int(pool.length)];
          launchAttack(D.i, kind, rng.next() < 0.3, 14 + rng.int(14), tick);
        }
      }
      L.nextAuto = tick + 16 + rng.int(22);
    }
    // 1. generate one flow record per device
    const B = L.batch, raw = L.raw;
    const truth = new Int32Array(nd), rawAll = new Float32Array(nd * 9);
    for (let i = 0; i < nd; i++) {
      const D = L.devices[i];
      if (D.attack && tick > D.attack.end) endAttack(D);
      const prof = D.attack ? ATTACK[D.attack.kind][D.attack.stealth] : NORMAL[D.type];
      const proto = sampleFlow(rng, prof, raw);
      B.cols[0].data[i] = D.type;
      B.cols[1].data[i] = proto;
      for (let j = 0; j < 9; j++) { B.cols[2 + j].data[i] = raw[j]; rawAll[i * 9 + j] = raw[j]; }
      truth[i] = D.attack ? D.attack.kind : 0;
    }
    // 2. preprocess + score with the three detectors
    const ts = now();
    for (let i = 0; i < nd; i++) transformRow(fs, B, i, L.Xb, i * d);
    for (let f = 0; f < d; f++) { const e = M.edges[f]; for (let i = 0; i < nd; i++) L.Cb[f * nd + i] = binCode(e, L.Xb[i * d + f]); }
    const out = [];
    for (let i = 0; i < nd; i++) {
      const sIF = ifScore(M.ifm, L.Xb, i * d);
      const sAE = aeError(M.ae, L.Xb, i * d, L.perFeat);
      rfProba(M.rf, L.Cb, nd, i, L.pr);
      const pNormal = L.pr[M.normalRF];
      let pred = -1, best = 0;
      for (let k = 0; k < M.KRF; k++) if (k !== M.normalRF && L.pr[k] > best) { best = L.pr[k]; pred = k; }
      if (best < 0.15) pred = -1;
      const r = [riskOf(L.thr.if, sIF), riskOf(L.thr.ae, sAE), 100 * (1 - pNormal)];
      // top contributing features (autoencoder reconstruction error)
      let tot = 0;
      for (let j = 0; j < d; j++) tot += L.perFeat[j];
      const top = [], chosen = [];
      for (let q = 0; q < 3; q++) {
        let bj = -1, bv = -1;
        for (let j = 0; j < d; j++) {
          if (chosen.indexOf(j) >= 0) continue;
          if (L.perFeat[j] > bv) { bv = L.perFeat[j]; bj = j; }
        }
        if (bj < 0) break;
        chosen.push(bj);
        top.push(bj, tot > 0 ? bv / tot : 0);
      }
      out.push({ r, pred, top, sIF, sAE });
    }
    const usRec = ((now() - ts) * 1000) / nd;
    L.perf.us = L.perf.n ? L.perf.us * 0.9 + usRec * 0.1 : usRec;
    L.perf.n++;

    // 3. decide, correlate into incidents, track live accuracy
    const changed = [];
    const devs = [];
    for (let i = 0; i < nd; i++) {
      const D = L.devices[i], o = out[i];
      const agg = aggregate(o.r);
      const dec = agg >= 50 ? 1 : 0;
      const flags = (o.r[0] >= 50 ? 1 : 0) | (o.r[1] >= 50 ? 2 : 0) | (o.r[2] >= 50 ? 4 : 0);
      const isAtt = truth[i] > 0 ? 1 : 0;
      L.m.records++;
      if (dec && isAtt) L.m.tp++; else if (dec) L.m.fp++; else if (isAtt) L.m.fn++; else L.m.tn++;
      D.recent.push(dec);
      if (D.recent.length > 3) D.recent.shift();
      const hits = D.recent.reduce((a, b) => a + b, 0);
      if (!D.inc) {
        if (hits >= 2) {
          const back = D.recent.length - 1 - D.recent.indexOf(1);
          const inc = {
            id: ++L.incSeq, dev: i, start: tick - back, last: tick, end: 0, records: hits, peak: agg,
            hits: [o.r[0] >= 50 ? 1 : 0, o.r[1] >= 50 ? 1 : 0, o.r[2] >= 50 ? 1 : 0],
            votes: [0, 0, 0, 0, 0], unknown: 0, status: 'active', truth: isAtt, truthKind: truth[i], quiet: 0,
          };
          if (o.pred > 0) inc.votes[o.pred]++; else inc.unknown++;
          D.inc = inc;
          L.incidents.push(inc);
          if (L.incidents.length > 400) L.incidents.splice(0, L.incidents.length - 400);
          if (isAtt) L.m.incTrue++; else L.m.incFalse++;
          changed.push(inc);
        }
      } else {
        const inc = D.inc;
        inc.last = tick;
        if (dec) {
          inc.records++;
          inc.quiet = 0;
          if (o.r[0] >= 50) inc.hits[0]++;
          if (o.r[1] >= 50) inc.hits[1]++;
          if (o.r[2] >= 50) inc.hits[2]++;
          if (o.pred > 0) inc.votes[o.pred]++; else inc.unknown++;
        } else inc.quiet++;
        if (agg > inc.peak) inc.peak = agg;
        if (isAtt && !inc.truth) { inc.truth = 1; inc.truthKind = truth[i]; L.m.incTrue++; L.m.incFalse = Math.max(0, L.m.incFalse - 1); }
        if (inc.quiet >= 3) { inc.status = 'resolved'; inc.end = tick; D.inc = null; }
        changed.push(inc);
      }
      if (D.attack && !D.attack.detected && D.inc && dec) {
        D.attack.detected = true;
        L.m.ttdSum += tick - D.attack.start + 1;
        L.m.ttdN++;
      }
      const state = D.inc ? 2 : flags ? 1 : 0;
      devs.push({
        r: o.r, agg, flags, dec, state, pred: o.pred, truth: truth[i], top: o.top,
        raw: Array.from(rawAll.subarray(i * 9, i * 9 + 9)), inc: D.inc ? D.inc.id : 0,
        att: D.attack ? { kind: D.attack.kind, stealth: D.attack.stealth, left: D.attack.end - tick + 1, detected: D.attack.detected } : null,
      });
    }
    post({
      type: 'tick', tick, time: L.t0 + tick * 1000, devs,
      incidents: changed.map((x) => Object.assign({}, x, { hits: x.hits.slice(), votes: x.votes.slice() })),
      m: Object.assign({}, L.m), perf: { us: L.perf.us },
    });
  }

  function benchmark(n) {
    const r = runBench(n);
    if (r) post(Object.assign({ type: 'bench' }, r));
  }
  function runBench(n) {
    const M = LIVE.models;
    if (!M) return null;
    const rng = makeRng(77);
    const ds = emptySynthDs(n);
    const vals = new Float64Array(9);
    for (let i = 0; i < n; i++) {
      const dev = rng.int(3), att = rng.next() < 0.2 ? 1 + rng.int(4) : 0;
      const proto = sampleFlow(rng, att ? ATTACK[att][rng.int(2)] : NORMAL[dev], vals);
      ds.cols[0].data[i] = dev;
      ds.cols[1].data[i] = proto;
      for (let j = 0; j < 9; j++) ds.cols[2 + j].data[i] = vals[j];
    }
    const d = M.fs.d;
    const t0 = now();
    const X = new Float32Array(n * d);
    for (let i = 0; i < n; i++) transformRow(M.fs, ds, i, X, i * d);
    const t1 = now();
    let acc = 0;
    for (let i = 0; i < n; i++) acc += ifScore(M.ifm, X, i * d);
    const t2 = now();
    for (let i = 0; i < n; i++) acc += aeError(M.ae, X, i * d);
    const t3 = now();
    const C = makeCodes(X, d, n, M.edges);
    const pr = new Float64Array(M.KRF);
    for (let i = 0; i < n; i++) acc += rfProba(M.rf, C, n, i, pr)[0];
    const t4 = now();
    const total = t4 - t0;
    return {
      n, total, rps: (n / total) * 1000, perRecord: (total * 1000) / n,
      us: { prep: ((t1 - t0) * 1000) / n, if: ((t2 - t1) * 1000) / n, ae: ((t3 - t2) * 1000) / n, rf: ((t4 - t3) * 1000) / n },
      check: acc > 0,
    };
  }

  /* ------------------------------------------------------------------ *
   * CSV reading (streamed, reservoir-sampled)                          *
   * ------------------------------------------------------------------ */
  let PARSED = null;
  const LABEL_NAMES = ['label', 'class', 'attack', 'attack_cat', 'attack_type', 'attack_label', 'category', 'type', 'target', 'y',
    'subcategory', 'detailed-label', 'detailed_label', 'binary_label', 'is_attack', 'malicious'];
  const ID_LIKE = /^(unnamed: ?0|id|index|no\.?|row|ts|timestamp|time|stime|ltime|date|datetime|frame\.time.*|flow_id|flow id)$/i;

  async function parseCsv(blob, name, maxRows) {
    const t0 = now();
    const rng = makeRng(99);
    const CHUNK = 8 << 20;
    const dec = new TextDecoder('utf-8');
    let offset = 0, carry = '', pending = '', header = null, delim = ',';
    let seen = 0;
    const buffered = [];
    let cols = null;
    const cap = maxRows;
    function inferAndAlloc() {
      cols = header.map((h, c) => {
        let numeric = 0, nonEmpty = 0;
        for (const row of buffered) {
          const v = row[c];
          if (v === undefined) continue;
          const s = v.trim();
          if (s === '') continue;
          nonEmpty++;
          if (!Number.isNaN(+s)) numeric++;
        }
        const isNum = nonEmpty === 0 || numeric / nonEmpty >= 0.95;
        return isNum
          ? { name: h, kind: 'num', data: new Float32Array(cap), uniq: new Set(), many: false }
          : { name: h, kind: 'cat', data: new Int32Array(cap), dict: new Map(), cats: [], high: false };
      });
    }
    function store(row) {
      let slot;
      if (seen < cap) slot = seen;
      else { const j = rng.int(seen + 1); slot = j < cap ? j : -1; }
      seen++;
      if (slot < 0) return;
      for (let c = 0; c < cols.length; c++) {
        const col = cols[c];
        const s = row[c] === undefined ? '' : row[c];
        if (col.kind === 'num') {
          const t = s.trim();
          const v = t === '' ? NaN : +t;
          const fv = Number.isFinite(v) ? v : NaN;
          col.data[slot] = fv;
          if (!col.many && fv === fv) { col.uniq.add(fv); if (col.uniq.size > 40) col.many = true; }
        } else {
          const t = s.trim();
          let code = col.dict.get(t);
          if (code === undefined) {
            if (col.cats.length >= 5000) { col.high = true; code = -1; }
            else { code = col.cats.length; col.dict.set(t, code); col.cats.push(t); }
          }
          col.data[slot] = code;
        }
      }
    }
    function splitQuoted(line) {
      const out = [];
      let cur = '', inQ = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (inQ) {
          if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false; }
          else cur += ch;
        } else if (ch === '"') inQ = true;
        else if (ch === delim) { out.push(cur); cur = ''; }
        else cur += ch;
      }
      out.push(cur);
      return out;
    }
    function onLine(line) {
      if (line.charCodeAt(line.length - 1) === 13) line = line.slice(0, -1);
      if (pending) { line = pending + '\n' + line; pending = ''; }
      if (line.indexOf('"') !== -1) {
        let q = 0;
        for (let i = 0; i < line.length; i++) if (line.charCodeAt(i) === 34) q++;
        if (q % 2 === 1) { pending = line; return; }
      }
      if (!header) {
        const first = line.replace(/^﻿/, '');
        const counts = [',', ';', '\t', '|'].map((c) => first.split(c).length);
        delim = [',', ';', '\t', '|'][counts.indexOf(Math.max.apply(null, counts))];
        header = (first.indexOf('"') !== -1 ? splitQuoted(first) : first.split(delim)).map((h, i) => h.trim() || 'column_' + (i + 1));
        return;
      }
      if (line.trim() === '') return;
      const row = line.indexOf('"') !== -1 ? splitQuoted(line) : line.split(delim);
      if (!cols) {
        buffered.push(row);
        if (buffered.length >= 500) { inferAndAlloc(); for (const r of buffered) store(r); buffered.length = 0; }
        return;
      }
      store(row);
    }
    while (offset < blob.size) {
      const end = Math.min(blob.size, offset + CHUNK);
      const buf = await blob.slice(offset, end).arrayBuffer();
      offset = end;
      const text = carry + dec.decode(buf, { stream: offset < blob.size });
      const lines = text.split('\n');
      carry = offset < blob.size ? lines.pop() : '';
      for (let i = 0; i < lines.length; i++) onLine(lines[i]);
      post({ type: 'csvProgress', stage: 'parse', pct: offset / blob.size, rows: seen });
    }
    if (carry) onLine(carry);
    if (pending) { const p = pending; pending = ''; onLine(p.replace(/"/g, '')); }
    if (!header) throw new Error('EMPTY_FILE');
    if (!cols) { inferAndAlloc(); for (const r of buffered) store(r); buffered.length = 0; }
    const n = Math.min(seen, cap);
    if (n < 50) throw new Error('TOO_FEW_ROWS');
    for (const col of cols) col.data = col.data.slice(0, n);
    const ds = { n, cols: cols.map((c) => (c.kind === 'num' ? { name: c.name, kind: 'num', data: c.data, many: c.many, uniq: c.uniq } : { name: c.name, kind: 'cat', data: c.data, cats: c.cats, high: c.high })) };
    // label candidates
    const cands = [];
    ds.cols.forEach((c, i) => {
      if (c.kind === 'cat' && !c.high && c.cats.length >= 2 && c.cats.length <= 200) cands.push(i);
      else if (c.kind === 'num' && !c.many && c.uniq.size >= 2 && c.uniq.size <= 40) cands.push(i);
    });
    const candInfo = cands.map((ci) => ({ col: ci, name: ds.cols[ci].name, values: valueCounts(ds, ci).slice(0, 60) }));
    let guess = -1;
    for (const nm of LABEL_NAMES) {
      const hit = cands.find((ci) => ds.cols[ci].name.trim().toLowerCase() === nm);
      if (hit !== undefined) { guess = hit; break; }
    }
    if (guess < 0) { const cat = cands.filter((ci) => ds.cols[ci].kind === 'cat'); guess = cat.length ? cat[cat.length - 1] : cands.length ? cands[cands.length - 1] : -1; }
    let normalGuess = null;
    if (guess >= 0) {
      const vals = valueCounts(ds, guess);
      const pick = vals.find((v) => /^(benign|benigntraffic|normal|legitimate|0)$/i.test(v.v)) || vals.find((v) => /benign|normal/i.test(v.v)) || vals[0];
      normalGuess = pick ? pick.v : null;
    }
    PARSED = ds;
    post({
      type: 'csvParsed', name, size: blob.size, rowsTotal: seen, rowsKept: n, ms: now() - t0, delim,
      columns: ds.cols.map((c) => ({ name: c.name, kind: c.kind, cats: c.kind === 'cat' ? c.cats.length : 0, high: !!c.high })),
      candidates: candInfo, guess: { col: guess, normal: normalGuess },
    });
  }
  function labelStrings(ds, ci) {
    const c = ds.cols[ci], out = new Array(ds.n);
    if (c.kind === 'cat') for (let i = 0; i < ds.n; i++) out[i] = c.data[i] >= 0 ? c.cats[c.data[i]] : '(other)';
    else for (let i = 0; i < ds.n; i++) out[i] = Number.isFinite(c.data[i]) ? String(c.data[i]) : '(missing)';
    return out;
  }
  function valueCounts(ds, ci) {
    const m = new Map();
    for (const s of labelStrings(ds, ci)) m.set(s, (m.get(s) || 0) + 1);
    return Array.from(m.entries()).map(([v, n]) => ({ v, n })).sort((a, b) => b.n - a.n);
  }

  function analyzeCsv(labelCol, normalValue) {
    const ds0 = PARSED;
    if (!ds0) throw new Error('NO_FILE');
    const labs = labelStrings(ds0, labelCol);
    const counts = new Map();
    for (const s of labs) counts.set(s, (counts.get(s) || 0) + 1);
    const classes = Array.from(counts.keys()).sort((a, b) => counts.get(b) - counts.get(a));
    const normalClass = classes.indexOf(String(normalValue));
    if (normalClass < 0) throw new Error('NOT_ENOUGH_NORMAL');
    const cIdx = new Map(classes.map((c, i) => [c, i]));
    const label = new Int32Array(ds0.n);
    for (let i = 0; i < ds0.n; i++) label[i] = labs[i] === '(missing)' ? -1 : cIdx.get(labs[i]);
    const exclude = new Set([labelCol]);
    const excludedNames = [];
    ds0.cols.forEach((c, i) => {
      const nm = c.name.trim();
      if (i !== labelCol && (LABEL_NAMES.indexOf(nm.toLowerCase()) >= 0 || ID_LIKE.test(nm))) { exclude.add(i); excludedNames.push(c.name); }
    });
    const ds = { n: ds0.n, cols: ds0.cols, label, classes, normalClass };
    const { report } = runPipeline(ds, {
      seed: 42, multiClass: false, aeMax: 6000, aeEpochs: 25, rfTrees: 60, rfMax: 40000, testMax: 40000,
      zdTrees: 30, zdMax: 6, normScoreMax: 20000, exclude, excludedNames, title: 'csv',
    }, (stage, pct, extra) => post({ type: 'csvProgress', stage, pct, extra }));
    post({ type: 'csvReport', report }, reportTransfer(report));
  }

  function sampleCsvBlob() {
    const ds = makeSynthetic(7, 15000, 5000);
    const lines = ['device_type,protocol,' + NUM_COLS.join(',') + ',label'];
    for (let i = 0; i < ds.n; i++) {
      const parts = [DEV_TYPES[ds.cols[0].data[i]], PROTOS[ds.cols[1].data[i]]];
      for (let j = 0; j < 9; j++) { const v = ds.cols[2 + j].data[i]; parts.push(j === 4 ? String(v) : v.toFixed(4)); }
      parts.push(CLASSES[ds.label[i]] === 'Normal' ? 'BenignTraffic' : CLASSES[ds.label[i]]);
      lines.push(parts.join(','));
    }
    return new Blob([lines.join('\n')], { type: 'text/csv' });
  }

  /* ------------------------------------------------------------------ *
   * Messages                                                           *
   * ------------------------------------------------------------------ */
  scope.onmessage = async (ev) => {
    const m = ev.data || {};
    try {
      switch (m.type) {
        case 'hello': post({ type: 'hello' }); break;
        case 'init': initLive(m); break;
        case 'run': setRunning(m.on); break;
        case 'speed': LIVE.speed = Math.max(0.5, Math.min(20, +m.value || 1)); break;
        case 'policy': LIVE.policy = m.value; break;
        case 'pct': LIVE.pct = +m.value; if (LIVE.models) setThresholds(); break;
        case 'auto': LIVE.auto = !!m.on; if (LIVE.auto) LIVE.nextAuto = LIVE.tick + 3; break;
        case 'attack': launchAttack(m.dev, m.kind, m.stealth, m.duration); break;
        case 'stopAttacks': LIVE.devices.forEach((D) => { if (D.attack) endAttack(D); }); break;
        case 'resetStats':
          Object.keys(LIVE.m).forEach((k) => { LIVE.m[k] = 0; });
          break;
        case 'bench': benchmark(m.n || 50000); break;
        case 'labReport': labReport(m); break;
        case 'csvFile': await parseCsv(m.file, m.name || 'file.csv', m.maxRows || 100000); break;
        case 'csvSample': await parseCsv(sampleCsvBlob(), 'sample-iot-traffic.csv', m.maxRows || 100000); break;
        case 'csvAnalyze': analyzeCsv(m.labelCol, m.normalValue); break;
        default: break;
      }
    } catch (err) {
      post({ type: 'error', where: m.type, code: String((err && err.message) || err) });
    }
  };
}
