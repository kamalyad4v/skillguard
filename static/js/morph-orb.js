/**
 * SkillGuard // MorphOrb Native Engine
 * Port of MorphOrb React component to high-performance Vanilla JS
 * Handles 3D dotted canvas orb, dual-pass spherical projection,
 * Bézier flight physics, comet trail ghosts, and card unfolding.
 */

(function (global) {
  'use strict';

  /* ───────────────────────────── COPY ───────────────────────────── */
  const COPY = {
    placeholder: "Enter target URL (e.g. http://testphp.vulnweb.com)...",
    labels: [
      "Passive Reconnaissance",
      "AI Attack Planning",
      "Probing Vulnerabilities",
      "Correlating Findings",
      "Synthesizing Security Report"
    ],
    done: "Audit Completed",
    answerTitle: "Security Verdict",
    answerBody: "Penetration audit complete. Risk assessment and vulnerability breakdown available below.",
    reset: "New Audit Target",
    send: "Launch",
  };

  /* ─────────────────────────── GEOMETRY ─────────────────────────── */
  const PILL_H = 60, BALL_SMALL = 60, ORB_D = 132, ORB_R = 66, CANVAS = 220;
  const CARD_H = 112;
  const FLY_D = 138;
  const pillW = () => Math.min(580, window.innerWidth - 48);
  const cardW = () => Math.min(380, window.innerWidth - 48);
  const homeDy = () => 140;

  /* ───────────────────────── MATH & EASING ───────────────────────── */
  const clamp01 = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);
  const lerp = (a, b, t) => a + (b - a) * t;
  const fmt = (v) => String(Math.round(v * 1e4) / 1e4);
  const TAU = Math.PI * 2;

  function mulberry32(a) {
    return function () {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function cubicBezier(x1, y1, x2, y2) {
    const cx = 3 * x1, bx = 3 * (x2 - x1) - cx, ax = 1 - cx - bx;
    const cy = 3 * y1, by = 3 * (y2 - y1) - cy, ay = 1 - cy - by;
    const sx = (t) => ((ax * t + bx) * t + cx) * t;
    const sy = (t) => ((ay * t + by) * t + cy) * t;
    const dx = (t) => (3 * ax * t + 2 * bx) * t + cx;
    const solve = (x) => {
      let t = x;
      for (let i = 0; i < 8; i++) {
        const e = sx(t) - x;
        if (Math.abs(e) < 1e-6) return t;
        const d = dx(t);
        if (Math.abs(d) < 1e-6) break;
        t -= e / d;
      }
      let lo = 0, hi = 1;
      t = x;
      for (let i = 0; i < 40; i++) {
        const e = sx(t);
        if (Math.abs(e - x) < 1e-6) break;
        if (x > e) lo = t; else hi = t;
        t = (hi - lo) / 2 + lo;
      }
      return t;
    };
    return (x) => (x <= 0 ? 0 : x >= 1 ? 1 : sy(solve(x)));
  }

  const E = {
    out: cubicBezier(0.22, 1, 0.36, 1),
    io: cubicBezier(0.65, 0, 0.35, 1),
    in: cubicBezier(0.4, 0, 1, 1),
    fly: cubicBezier(0.5, 0, 0.1, 1),
    grow: cubicBezier(0.3, 0, 0.2, 1),
    vortex: cubicBezier(0.6, 0, 0.2, 1),
    spring: cubicBezier(0.34, 1.4, 0.64, 1),
    card: cubicBezier(0.65, 0, 0.2, 1),
    lin: (t) => t,
  };

  const bez = (t, p0, c, p2) => (1 - t) * (1 - t) * p0 + 2 * (1 - t) * t * c + t * t * p2;

  /* ───────────────────────── TIMELINE DATA ───────────────────────── */
  const T = (ch, from, to, t0, t1, ease = E.io) => ({ ch, from, to, t0, t1, ease });

  const launchTracks = (g) => [
    T("w", g.pw, g.pw - 12, 0, 100, E.out),
    T("oInput", 1, 0, 0, 160, E.in),
    T("inScale", 1, 0.6, 0, 160, E.in),
    T("oGlow", 1, 0, 0, 300, E.out),
    T("oAur", 1, 0, 0, 300, E.out),
    T("w", g.pw - 12, BALL_SMALL, 100, 560, E.io),
    T("h", PILL_H, PILL_H + 6, 380, 500, E.out),
    T("h", PILL_H + 6, BALL_SMALL, 500, 620, E.out),
    T("oPill", 1, 0, 300, 560, E.out),
    T("oBall", 0, 1, 300, 560, E.out),
    T("u", 0, 1, 620, 1500, E.fly),
    T("w", BALL_SMALL, FLY_D, 620, 1300, E.grow),
    T("h", BALL_SMALL, FLY_D, 620, 1300, E.grow),
    T("w", FLY_D, ORB_D, 1300, 1500, E.out),
    T("h", FLY_D, ORB_D, 1300, 1500, E.out),
    T("cHalo", 0, 0.6, 620, 1500, E.out),
    T("trail", 0, 1, 700, 800, E.out),
    T("trail", 1, 0, 1300, 1500, E.in),
  ];

  const ASSEMBLE = [
    T("oRing", 1, 0, 0, 300, E.out),
    T("oBall", 1, 0, 0, 260, E.out),
    T("orb.k", 0, 1, 0, 800, E.out),
    T("orb.alpha", 0, 1, 0, 800, E.out),
    T("orb.spin", 0, 0.9, 0, 800, E.out),
    T("orb.pop", 1, 1.05, 0, 420, E.out),
    T("orb.pop", 1.05, 1, 420, 800, E.io),
    T("sOp", 0, 1, 300, 620, E.out),
    T("sTy", 6, 0, 300, 620, E.out),
  ];

  const RESOLVE = [
    T("orb.sweep", 0, 1, 0, 700, E.io),
    T("orb.spin", 0.9, 0.3, 0, 700, E.out),
    T("orb.gain", 1, 0, 0, 700, E.out),
    T("orb.floor", 0, 0.95, 400, 900, E.out),
    T("orb.rad", 0, 0.15, 400, 900, E.out),
    T("orb.pop", 1, 1.04, 600, 800, E.out),
    T("orb.pop", 1.04, 1, 800, 900, E.out),
  ];

  const CONDENSE = [
    T("orb.pop", 1, 1.06, 0, 120, E.out),
    T("sOp", 1, 0, 0, 160, E.in),
    T("sTy", 0, -6, 0, 160, E.in),
    T("orb.k", 1, 0, 120, 640, E.vortex),
    T("orb.vortex", 0, 1.6, 120, 640, E.vortex),
    T("oGreen", 0, 1, 260, 700, E.spring),
    T("gs", 0.55, 1, 260, 700, E.spring),
    T("pulse", 0, 1, 320, 760, E.out),
    T("oHalo", 0, 0.35, 380, 700, E.out),
    T("orb.alpha", 1, 0, 500, 800, E.out),
  ];

  const unfoldTracks = (g, tw) => [
    T("w", ORB_D, 124, 0, 90, E.in),
    T("h", ORB_D, 124, 0, 90, E.in),
    T("w", 124, g.cw, 90, 700, E.card),
    T("h", 124, CARD_H, 90, 700, E.out),
    T("r", ORB_D / 2, 20, 90, 700, E.io),
    T("oGreen", 1, 0, 200, 560, E.out),
    T("oCard", 0, 1, 200, 560, E.out),
    T("oHalo", 0.35, 0, 300, 700, E.out),
    T("cHalo", 0.6, 0.22, 300, 700, E.out),
    T("hOp", 0, 1, 520, 840, E.out),
    T("dotS", 0, 1, 520, 840, E.spring),
    T("wp", 0, 1, 600, 600 + tw, E.lin),
    T("bloom", 1, 0.625, 700, 1200, E.io),
  ];

  const FADE = ["oGlow", "oAur", "oPill", "oBall", "oGreen", "oCard", "oRing", "oInput", "oHalo", "sOp", "orb.alpha", "trail"];

  const INIT = {
    h: PILL_H, r: 999, oGlow: 1, oHalo: 0, oPill: 1, oBall: 0, oGreen: 0, oCard: 0, oRing: 1, oInput: 1, inScale: 1, oAur: 1,
    gs: 0.55, cs: 1, hOp: 0, dotS: 0, bloom: 1, u: 0, yOff: 0, trail: 0, pulse: -1, sOp: 0, sTy: 6, cHalo: 0, wp: 0,
    "orb.k": 0, "orb.alpha": 0, "orb.spin": 0, "orb.pop": 1, "orb.sweep": 0, "orb.vortex": 0, "orb.gain": 1, "orb.floor": 0, "orb.rad": 0,
  };

  /* ───────────────────────────── DOTTED ORB ───────────────────────────── */
  const RINGS = 16;
  const DOT_LIST = (() => {
    const rand = mulberry32(7);
    const out = [];
    for (let k = 0; k < RINGS; k++) {
      const y = 1 - ((k + 0.5) / RINGS) * 2;
      const r = Math.sqrt(1 - y * y);
      const m = Math.max(4, Math.round(30 * r));
      for (let j = 0; j < m; j++) {
        const a = (j / m) * TAU + k * 0.35;
        out.push({ x: Math.cos(a) * r, y, z: Math.sin(a) * r, u: (1 - y) / 2, seed: rand() * 6.283 });
      }
    }
    return out;
  })();
  const N = DOT_LIST.length;
  const DX = Float32Array.from(DOT_LIST, (d) => d.x);
  const DY = Float32Array.from(DOT_LIST, (d) => d.y);
  const DZ = Float32Array.from(DOT_LIST, (d) => d.z);
  const DU = Float32Array.from(DOT_LIST, (d) => d.u);
  const DS = Float32Array.from(DOT_LIST, (d) => d.seed);

  const G_STEPS = 24, A_STEPS = 48;
  const COLORS = (() => {
    const out = [];
    for (let gi = 0; gi <= G_STEPS; gi++) {
      const g = gi / G_STEPS;
      // Interpolate from Cyan/White to Emerald
      const r = Math.round(lerp(0, 0, g)), gg = Math.round(lerp(229, 255, g)), b = Math.round(lerp(255, 157, g));
      for (let ai = 0; ai <= A_STEPS; ai++) out.push(`rgba(${r},${gg},${b},${(ai / A_STEPS).toFixed(3)})`);
    }
    return out;
  })();

  const ORB_KEYS = ["k", "alpha", "spin", "sweep", "pop", "vortex", "gain", "floor", "rad"];

  function createOrb(canvas) {
    const P = { k: 0, alpha: 0, spin: 0, rot: 0, sweep: 0, pop: 1, vortex: 0, gain: 1, floor: 0, rad: 0, prog: 0 };
    const ctx = canvas.getContext("2d");
    const lit = new Float32Array(N);
    const SX = new Float32Array(N), SY = new Float32Array(N), SR = new Float32Array(N), SD = new Float32Array(N);
    const SC = new Int16Array(N);
    const pw = [1, 0, 0, 0];
    let time = 0, raf = 0, last = 0, dead = false;

    const reset = () => {
      P.k = 0; P.alpha = 0; P.spin = 0; P.rot = 0; P.sweep = 0; P.pop = 1; P.vortex = 0; P.gain = 1; P.floor = 0; P.rad = 0; P.prog = 0;
      lit.fill(0);
      pw[0] = 1; pw[1] = 0; pw[2] = 0; pw[3] = 0;
      time = 0;
    };
    reset();

    if (!ctx) return { P, ensure() {}, reset, destroy() {} };

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(CANVAS * dpr);
    canvas.height = Math.round(CANVAS * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const S = 0.6, CP = Math.cos(0.35), SP = Math.sin(0.35), C0 = CANVAS / 2;

    const draw = (dt) => {
      ctx.clearRect(0, 0, CANVAS, CANVAS);
      time += dt;
      P.rot += P.spin * dt;
      const yaw = P.rot + P.vortex, cyw = Math.cos(yaw), syw = Math.sin(yaw);
      const stepW = dt / 0.35;
      for (let q = 0; q < 4; q++) {
        const d = (q === P.prog ? 1 : 0) - pw[q];
        pw[q] += Math.abs(d) <= stepW ? d : d > 0 ? stepW : -stepW;
      }
      const decay = Math.exp(-dt / 0.5);
      const h0 = (time * 300) % N, h3 = (time * 480) % N;
      const a1 = time * 0.8, b1 = Math.sin(time * 0.5) * 0.9;
      const f1x = Math.cos(b1) * Math.cos(a1), f1y = Math.sin(b1), f1z = Math.cos(b1) * Math.sin(a1);
      const a2 = time * 0.55 + 2.1, b2 = Math.cos(time * 0.42) * 0.9;
      const f2x = Math.cos(b2) * Math.cos(a2), f2y = Math.sin(b2), f2z = Math.cos(b2) * Math.sin(a2);
      const lat = Math.sin(time * 2.2);
      const swirlK = P.vortex * 1.5;

      for (let n = 0; n < N; n++) {
        const dx = DX[n], dy = DY[n], dz = DZ[n], u = DU[n];

        let pulse = 0;
        if (pw[0] > 0.001) {
          let dd = Math.abs(n - h0); if (dd > N - dd) dd = N - dd;
          const v = Math.max(0, 1 - dd / 16);
          pulse = Math.max(pulse, v * v * pw[0]);
        }
        if (pw[1] > 0.001) {
          const v1 = Math.max(0, (dx * f1x + dy * f1y + dz * f1z - 0.72) / 0.28);
          const v2 = Math.max(0, (dx * f2x + dy * f2y + dz * f2z - 0.72) / 0.28);
          const v = Math.max(v1, v2);
          pulse = Math.max(pulse, v * v * pw[1]);
        }
        if (pw[2] > 0.001) {
          const e = dy - lat;
          const v = Math.max(0, 1 - (e * e) / 0.02);
          pulse = Math.max(pulse, v * v * pw[2]);
        }
        if (pw[3] > 0.001) {
          let dd = Math.abs(n - h3); if (dd > N - dd) dd = N - dd;
          const v = Math.max(0, 1 - dd / 22);
          pulse = Math.max(pulse, v * v * pw[3]);
        }
        const l = Math.max(lit[n] * decay, pulse * P.gain);
        lit[n] = l;

        const ki = clamp01(P.k * (1 + S) - S * u);
        if (ki <= 0.001) { SC[n] = -1; continue; }
        const eo = E.out(ki), kk = eo * P.pop;

        const x1 = dx * cyw + dz * syw, z1 = -dx * syw + dz * cyw;
        const y2 = dy * CP - z1 * SP, z2 = dy * SP + z1 * CP;
        const f = 2.8 / (2.8 - z2), depth = (z2 + 1) / 2;
        let ox = x1 * ORB_R * kk * f, oy = -y2 * ORB_R * kk * f;
        if (swirlK > 0.001) {
          const sw = (1 - ki) * swirlK, cc = Math.cos(sw), ss = Math.sin(sw);
          const tx = ox * cc - oy * ss;
          oy = ox * ss + oy * cc;
          ox = tx;
        }

        const g = clamp01((P.sweep * 1.4 - u) / 0.4);
        let a = 0.1 + 0.035 * Math.sin(DS[n] + time * 1.6) * (1 - g) + 0.32 * depth * depth + 0.75 * l * (1 - g) + g * (0.55 + 0.4 * depth) + 2 * g * (1 - g);
        a = Math.max(a, P.floor * (0.7 + 0.3 * depth));
        if (a > 1) a = 1;
        a *= eo * P.alpha;

        SX[n] = C0 + ox;
        SY[n] = C0 + oy;
        SD[n] = depth;
        SR[n] = (1.15 * (0.45 + 0.75 * depth) * f + 0.9 * l + g * 0.25) * (1 + P.rad) * (0.4 + 0.6 * eo);
        const ai = Math.round(a * A_STEPS), gi = Math.round(g * G_STEPS);
        SC[n] = ai <= 0 ? -1 : gi * (A_STEPS + 1) + ai;
      }

      /* Dual pass: back half then front half */
      for (let pass = 0; pass < 2; pass++) {
        for (let n = 0; n < N; n++) {
          const c = SC[n];
          if (c < 0) continue;
          if ((SD[n] >= 0.5) !== (pass === 1)) continue;
          ctx.fillStyle = COLORS[c];
          ctx.beginPath();
          ctx.arc(SX[n], SY[n], SR[n], 0, TAU);
          ctx.fill();
        }
      }
    };

    const frame = (now) => {
      raf = 0;
      if (dead) return;
      const dt = Math.max(0, Math.min(0.05, (now - last) / 1000));
      last = now;
      draw(dt);
      if (P.alpha > 0.002) raf = requestAnimationFrame(frame);
      else ctx.clearRect(0, 0, CANVAS, CANVAS);
    };

    const ensure = () => {
      if (raf || dead || P.alpha <= 0.002) return;
      last = performance.now();
      raf = requestAnimationFrame(frame);
    };

    const destroy = () => {
      dead = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
    };

    return { P, ensure, reset, destroy };
  }

  /* ───────────────────────── RUNTIME CONTROLLER ───────────────────────── */
  function sampleAt(h, t, out) {
    const n = h.length;
    const copy = (s) => { out.x = s.x; out.y = s.y; out.d = s.d; };
    if (n === 0) { out.x = 0; out.y = 0; out.d = 0; return; }
    if (t <= h[0].t) return copy(h[0]);
    for (let i = n - 1; i > 0; i--) {
      const a = h[i - 1], b = h[i];
      if (t >= a.t) {
        if (t >= b.t) return copy(b);
        const k = (t - a.t) / (b.t - a.t || 1);
        out.x = lerp(a.x, b.x, k); out.y = lerp(a.y, b.y, k); out.d = lerp(a.d, b.d, k);
        return;
      }
    }
    copy(h[n - 1]);
  }

  function initMorphOrb(containerId, options = {}) {
    const container = document.getElementById(containerId);
    if (!container) return null;

    // Render HTML structure inside container
    container.innerHTML = `
      <div class="mo-root" data-phase="idle">
        <div class="mo-bg" aria-hidden="true"></div>
        <div class="mo-halo" aria-hidden="true"></div>

        <div class="mo-mover">
          <span class="mo-trail" aria-hidden="true"></span>
          <span class="mo-trail" aria-hidden="true"></span>
          <span class="mo-trail" aria-hidden="true"></span>
          <span class="mo-trail" aria-hidden="true"></span>
          <span class="mo-trail" aria-hidden="true"></span>
          <span class="mo-trail" aria-hidden="true"></span>

          <div class="mo-actor">
            <div class="mo-underglow" aria-hidden="true"></div>
            <div class="mo-halo-green" aria-hidden="true"></div>
            <div class="mo-surface" aria-hidden="true">
              <div class="mo-aurora"><i></i><i></i><i></i><i></i></div>
            </div>
            <div class="mo-ball" aria-hidden="true"></div>
            <div class="mo-green" aria-hidden="true"></div>
            <div class="mo-card" aria-hidden="true"></div>
            <div class="mo-ring" aria-hidden="true"></div>

            <form class="mo-input" autocomplete="off">
              <svg class="mo-spark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M10 3.5l1.7 4.8 4.8 1.7-4.8 1.7L10 16.5l-1.7-4.8L3.5 10l4.8-1.7L10 3.5z" />
                <path d="M18 14.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7.7-1.8z" />
              </svg>
              <input
                class="mo-field"
                type="text"
                placeholder="${COPY.placeholder}"
                aria-label="Target domain or pentest prompt"
                spellcheck="false"
              />
              <button type="submit" class="mo-send" aria-label="${COPY.send}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M12 19V5" />
                  <path d="M5.5 11.5L12 5l6.5 6.5" />
                </svg>
              </button>
            </form>

            <canvas class="mo-orb" aria-hidden="true"></canvas>
            <div class="mo-pulse" aria-hidden="true"></div>

            <div class="mo-answer" tabindex="-1" role="group" aria-label="${COPY.answerTitle}">
              <div class="mo-a-head">
                <i class="mo-a-dot" aria-hidden="true"></i>
                <span class="mo-a-title">${COPY.answerTitle}</span>
              </div>
              <p class="mo-a-body"></p>
            </div>
          </div>
        </div>

        <div class="mo-status" aria-hidden="true">
          <span class="mo-lab mo-in">
            <span class="mo-lab-t">${COPY.labels[0]}</span>
            <span class="mo-dots" aria-hidden="true"><i></i><i></i><i></i></span>
          </span>
        </div>

        <button type="button" class="mo-reset">${COPY.reset}</button>
      </div>
    `;

    // Cache elements
    const root = container.querySelector('.mo-root');
    const mover = container.querySelector('.mo-mover');
    const actor = container.querySelector('.mo-actor');
    const form = container.querySelector('.mo-input');
    const input = container.querySelector('.mo-field');
    const sendBtn = container.querySelector('.mo-send');
    const canvas = container.querySelector('.mo-orb');
    const pulse = container.querySelector('.mo-pulse');
    const status = container.querySelector('.mo-status');
    const answerEl = container.querySelector('.mo-answer');
    const bodyEl = container.querySelector('.mo-a-body');
    const resetBtn = container.querySelector('.mo-reset');
    const ghosts = Array.from(container.querySelectorAll('.mo-trail'));

    const geo = { pw: pillW(), cw: cardW(), H: homeDy(), dir: -1 };
    const orb = createOrb(canvas);
    const vals = {};
    const dirty = new Set();
    const CH = {};

    let busy = false, curX = 0, curY = 0, curD = BALL_SMALL, trailVis = 0, ghostsShown = false;
    let wStagger = 40, wDur = 300;
    const hist = [];
    const tmp = { t: 0, x: 0, y: 0, d: 0 };
    let currentAbort = null;

    // Channels
    ["oGlow", "oHalo", "oPill", "oBall", "oGreen", "oCard", "oRing", "oInput", "oAur", "gs", "cs", "hOp", "dotS", "bloom"].forEach((n) => {
      CH[n] = (v) => actor.style.setProperty("--" + n, fmt(v));
    });
    ["w", "h", "r"].forEach((n) => {
      CH[n] = (v) => {
        actor.style.setProperty("--" + n, fmt(v) + "px");
        if (n === "w") curD = v;
      };
    });
    CH.inScale = (v) => {
      actor.style.setProperty("--inScale", fmt(v));
      form.style.filter = v >= 0.999 ? "none" : `blur(${fmt((1 - v) * 15)}px)`;
    };
    CH.sOp = (v) => status.style.setProperty("--sOp", fmt(v));
    CH.sTy = (v) => status.style.setProperty("--sTy", fmt(v));
    CH.cHalo = (v) => root.style.setProperty("--oCenter", fmt(v));
    CH.u = () => applyPath();
    CH.yOff = () => applyPath();
    CH.trail = (v) => { trailVis = v; renderTrail(); };
    CH.pulse = (v) => {
      if (v < 0) { pulse.style.opacity = "0"; return; }
      pulse.style.opacity = fmt(0.5 * (1 - v));
      pulse.style.transform = `scale(${fmt(1 + v)})`;
    };
    CH.wp = (v) => applyWords(v);
    ORB_KEYS.forEach((name) => {
      CH["orb." + name] = (v) => {
        orb.P[name] = v;
        if (name === "alpha") orb.ensure();
      };
    });

    const set = (ch, v) => { vals[ch] = v; dirty.add(ch); };
    const flush = () => { dirty.forEach((ch) => CH[ch]?.(vals[ch])); dirty.clear(); };
    const setNow = (ch, v) => { vals[ch] = v; CH[ch]?.(v); };
    const resetChannels = () => {
      setNow("w", geo.pw);
      for (const ch of Object.keys(INIT)) setNow(ch, INIT[ch]);
    };

    const renderTrail = () => {
      if (trailVis <= 0.001) {
        if (ghostsShown) { ghosts.forEach((g) => (g.style.opacity = "0")); ghostsShown = false; }
        return;
      }
      ghostsShown = true;
      const now = performance.now();
      for (let i = 0; i < ghosts.length; i++) {
        sampleAt(hist, now - (i + 1) * 45, tmp);
        const k = (tmp.d * (1 - 0.08 * (i + 1))) / 100;
        const g = ghosts[i];
        g.style.transform = `translate3d(${(tmp.x - curX).toFixed(2)}px,${(tmp.y - curY).toFixed(2)}px,0) translate(-50%,-50%) scale(${k.toFixed(3)})`;
        g.style.opacity = (0.28 * Math.pow(1 - i / 6, 1.5) * trailVis).toFixed(3);
      }
    };

    const applyPath = () => {
      const u = vals.u ?? 0, H = geo.H;
      curX = bez(u, 0, geo.dir * 0.3 * H, 0);
      curY = bez(u, H, 0.6 * H, 0) + (vals.yOff ?? 0);
      mover.style.transform = `translate3d(${curX.toFixed(2)}px,${curY.toFixed(2)}px,0) translate(-50%,-50%)`;
      const now = performance.now();
      hist.push({ t: now, x: curX, y: curY, d: curD });
      while (hist.length > 2 && hist[0].t < now - 500) hist.shift();
      renderTrail();
    };

    const applyWords = (v) => {
      const nodes = bodyEl.querySelectorAll('.mo-w');
      const total = (nodes.length - 1) * wStagger + wDur;
      const time = v * total;
      nodes.forEach((el, i) => {
        const p = E.out(clamp01((time - i * wStagger) / wDur));
        el.style.opacity = fmt(p);
        el.style.transform = p >= 0.999 ? "none" : `translateY(${fmt((1 - p) * 4)}px)`;
        el.style.filter = p >= 0.999 ? "none" : `blur(${fmt((1 - p) * 4)}px)`;
      });
    };

    const play = (tracks) =>
      new Promise((res) => {
        const end = tracks.reduce((m, k) => Math.max(m, k.t1), 0);
        const done = new Set();
        let raf = 0, t = 0, last = performance.now();
        const finish = () => res();
        const step = (now) => {
          const dt = Math.max(0, Math.min(100, now - last));
          last = now;
          t += dt;
          for (const k of tracks) {
            if (done.has(k) || t < k.t0) continue;
            const p = Math.min(1, (t - k.t0) / Math.max(1, k.t1 - k.t0));
            set(k.ch, k.from + (k.to - k.from) * (k.ease ?? E.io)(p));
            if (p === 1) done.add(k);
          }
          flush();
          if (t >= end) finish(); else raf = requestAnimationFrame(step);
        };
        raf = requestAnimationFrame(step);
      });

    const setPhase = (p) => root.setAttribute('data-phase', p);

    const setStatusLabel = (text, isDone = false) => {
      status.innerHTML = `
        <span class="mo-lab mo-in">
          <span class="mo-lab-t ${isDone ? 'mo-lab-done' : ''}">${text}</span>
          ${isDone ? '' : '<span class="mo-dots" aria-hidden="true"><i></i><i></i><i></i></span>'}
        </span>
      `;
    };

    // Public controller methods
    async function launch(text, onStartAudit) {
      if (busy) return false;
      busy = true;
      geo.pw = pillW(); geo.cw = cardW(); geo.H = homeDy();
      geo.dir = -geo.dir;
      orb.reset();
      setNow("u", 0);

      setPhase("launch");
      hist.length = 0;
      await play(launchTracks(geo));
      setNow("r", ORB_D / 2);

      setPhase("assemble");
      await play(ASSEMBLE);

      setPhase("think");
      setStatusLabel(COPY.labels[0]);

      // Call external submission handler
      if (typeof onStartAudit === 'function') {
        onStartAudit(text, {
          updateLabel: (lbl) => {
            orb.P.prog = (orb.P.prog + 1) % 4;
            setStatusLabel(lbl);
          },
          complete: async (summaryText) => {
            const body = summaryText || COPY.answerBody;
            const words = body.split(/\s+/).filter(Boolean);
            const n = Math.max(1, words.length);

            setPhase("resolve");
            setStatusLabel(COPY.done, true);
            await play(RESOLVE);

            setPhase("condense");
            await play(CONDENSE);

            setPhase("unfold");
            wDur = 320;
            wStagger = n > 1 ? Math.min(45, 280 / (n - 1)) : 0;
            bodyEl.innerHTML = words.map(w => `<span class="mo-w">${w}</span> `).join('');
            await play(unfoldTracks(geo, (n - 1) * wStagger + wDur));

            setPhase("answered");
          }
        });
      }
      return true;
    }

    async function resetToIdle() {
      setPhase("reset");
      const out = [T("cHalo", vals.cHalo ?? 0, 0, 0, 240, E.out)];
      for (const ch of FADE) {
        const v = vals[ch] ?? 0;
        if (v > 0.001) out.push(T(ch, v, 0, 0, 240, E.out));
      }
      out.push(T("cs", 1, 0.98, 0, 240, E.out));
      await play(out);

      setNow("pulse", -1);
      bodyEl.innerHTML = '';
      input.value = '';
      orb.reset();
      hist.length = 0;
      geo.pw = pillW(); geo.cw = cardW(); geo.H = homeDy();
      resetChannels();

      const pillCh = ["oPill", "oInput", "oGlow", "oAur", "oRing"];
      pillCh.forEach((ch) => setNow(ch, 0));
      setNow("yOff", 8);
      const inn = pillCh.map((ch) => T(ch, 0, 1, 0, 420, E.out));
      inn.push(T("yOff", 8, 0, 0, 420, E.out));
      await play(inn);

      resetChannels();
      busy = false;
      setPhase("idle");
      input.focus({ preventScroll: true });
    }

    // Clicking anywhere on the pill focuses the input field
    actor.addEventListener('click', (e) => {
      if (root.getAttribute('data-phase') === 'idle') {
        if (!sendBtn.contains(e.target)) {
          input.focus();
        }
      }
    });

    // Input handlers
    input.addEventListener('input', (e) => {
      const hasText = e.target.value.trim().length > 0;
      if (hasText) sendBtn.setAttribute('data-ready', '');
      else sendBtn.removeAttribute('data-ready');
      actor.setAttribute('data-typing', '');
      clearTimeout(actor._typeTimer);
      actor._typeTimer = setTimeout(() => actor.removeAttribute('data-typing'), 300);
    });

    // Enter key submits target
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const text = input.value.trim();
        if (!text) {
          actor.setAttribute('data-shake', '');
          setTimeout(() => actor.removeAttribute('data-shake'), 260);
          return;
        }
        if (options.onSubmit) {
          launch(text, options.onSubmit);
        }
      }
    });

    // Send button click
    sendBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const text = input.value.trim();
      if (!text) {
        actor.setAttribute('data-shake', '');
        setTimeout(() => actor.removeAttribute('data-shake'), 260);
        return;
      }
      if (options.onSubmit) {
        launch(text, options.onSubmit);
      }
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) {
        actor.setAttribute('data-shake', '');
        setTimeout(() => actor.removeAttribute('data-shake'), 260);
        return;
      }
      if (options.onSubmit) {
        launch(text, options.onSubmit);
      }
    });

    resetBtn.addEventListener('click', () => {
      resetToIdle();
      if (options.onReset) options.onReset();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && root.getAttribute('data-phase') !== 'idle') {
        resetToIdle();
        if (options.onReset) options.onReset();
      }
    });

    window.addEventListener('resize', () => {
      if (!busy) {
        geo.pw = pillW(); geo.cw = cardW(); geo.H = homeDy();
        setNow("w", geo.pw);
        setNow("u", 0);
      }
    });

    resetChannels();

    return {
      launch,
      reset: resetToIdle,
      setInput: (val) => {
        input.value = val;
        if (val) sendBtn.setAttribute('data-ready', '');
        else sendBtn.removeAttribute('data-ready');
      },
      getInput: () => input.value.trim(),
      isBusy: () => busy,
    };
  }

  global.initMorphOrb = initMorphOrb;
})(window);
