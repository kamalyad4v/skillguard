/**
 * SkillGuard // Security Bento Telemetry Engine
 * High-performance native SVG & Canvas interactive engine adapted from Bento architecture
 * Real-time waveforms, half-gauge threat allocations, exploit telemetry & sparklines.
 */

(function (global) {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const el = (t, a = {}, p) => {
    const e = document.createElementNS(NS, t);
    for (const k in a) e.setAttribute(k, a[k]);
    if (p) p.appendChild(e);
    return e;
  };

  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const P2 = (r, a) => [r * Math.cos(a * Math.PI / 180), r * Math.sin(a * Math.PI / 180)];

  function smoothPath(P, move = true) {
    if (!P || P.length === 0) return '';
    let d = (move ? 'M' : 'L') + `${P[0][0]},${P[0][1]}`;
    for (let i = 0; i < P.length - 1; i++) {
      const p0 = P[i - 1] || P[i];
      const p1 = P[i];
      const p2 = P[i + 1];
      const p3 = P[i + 2] || p2;
      const k = 0.17;
      d += `C${p1[0] + (p2[0] - p0[0]) * k},${p1[1] + (p2[1] - p0[1]) * k} ${p2[0] - (p3[0] - p1[0]) * k},${p2[1] - (p3[1] - p1[1]) * k} ${p2[0]},${p2[1]}`;
    }
    return d;
  }

  /* ──────────────── Tooltip Controller ──────────────── */
  const tipEl = document.getElementById('secBentoTip') || (() => {
    const t = document.createElement('div');
    t.id = 'secBentoTip';
    t.className = 'sec-bento-tip';
    document.body.appendChild(t);
    return t;
  })();

  function showTip(x, y, title, rows) {
    if (!tipEl) return;
    tipEl.innerHTML = `<div class="tip-title">${title}</div>` +
      rows.map(([k, v, c]) => `
        <div class="tip-row">
          <span>${c ? `<i style="background:${c}"></i>` : ''}${k}</span>
          <b>${v}</b>
        </div>
      `).join('');
    tipEl.classList.add('active');
    const r = tipEl.getBoundingClientRect();
    let L = x + 16, T = y - r.height - 14;
    if (L + r.width > window.innerWidth - 8) L = x - r.width - 16;
    if (T < 8) T = y + 16;
    tipEl.style.left = L + 'px';
    tipEl.style.top = T + 'px';
  }

  function hideTip() {
    if (tipEl) tipEl.classList.remove('active');
  }

  /* ──────────────── Security Bento Controller ──────────────── */
  class SecurityBentoController {
    constructor() {
      this.state = {
        score: 100,
        grade: 'A',
        high: 0,
        med: 0,
        low: 0,
        info: 0,
        period: 'LIVE',
        probesCount: 0,
        attackVectors: {
          sqli: { name: 'SQL Injection', active: false, probes: 24, status: 'STANDBY', ohlc: [[12, 18, 10, 15], [15, 22, 14, 19], [19, 25, 18, 24], [24, 30, 22, 28], [28, 32, 26, 30]] },
          xss: { name: 'Cross-Site Scripting', active: false, probes: 32, status: 'STANDBY', ohlc: [[8, 14, 6, 12], [12, 19, 10, 16], [16, 21, 15, 20], [20, 28, 19, 25], [25, 34, 24, 32]] },
          dirbuster: { name: 'Directory Fuzzing', active: false, probes: 140, status: 'STANDBY', ohlc: [[40, 60, 35, 55], [55, 80, 50, 75], [75, 110, 70, 95], [95, 130, 90, 120], [120, 150, 115, 140]] },
          csrf: { name: 'CSRF & State Forms', active: false, probes: 12, status: 'STANDBY', ohlc: [[4, 8, 3, 6], [6, 10, 5, 8], [8, 12, 7, 10], [10, 14, 9, 11], [11, 15, 10, 12]] },
          auth: { name: 'Auth Brute-Force', active: false, probes: 50, status: 'STANDBY', ohlc: [[10, 20, 8, 18], [18, 28, 16, 25], [25, 35, 22, 32], [32, 42, 30, 38], [38, 52, 36, 50]] }
        }
      };

      this.streamData = this.generateInitialStreamData();
      this.init();
    }

    generateInitialStreamData() {
      const labels = ['T-0', 'Recon', 'Plan', 'Probe-1', 'Probe-2', 'Analyze', 'Audit'];
      return labels.map((l, i) => ({
        label: l,
        recon: 10 + i * 8 + Math.sin(i) * 3,
        fuzz: 5 + i * 15 + Math.cos(i) * 5,
        vulnerabilities: Math.max(0, (i > 3 ? (i - 3) * 6 : 0))
      }));
    }

    init() {
      this.initControls();
      this.drawThreatStream();
      this.drawVulnAllocation();
      this.drawPayloadFlow();
      this.drawVectorCandles();
      this.drawRunwayTicks();

      window.addEventListener('resize', () => {
        this.drawThreatStream();
        this.drawVulnAllocation();
        this.drawPayloadFlow();
        this.drawRunwayTicks();
      });
    }

    initControls() {
      const segPeriod = document.getElementById('secBentoPeriod');
      if (segPeriod) {
        segPeriod.querySelectorAll('button').forEach(btn => {
          btn.addEventListener('click', () => {
            segPeriod.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', 'false'));
            btn.setAttribute('aria-pressed', 'true');
            this.state.period = btn.textContent.trim();
            this.drawThreatStream();
            this.drawPayloadFlow();
          });
        });
      }
    }

    /* ── 1. Wave Stream Chart (Threat Velocity & Vector Depth) ── */
    drawThreatStream() {
      const svg = document.getElementById('secStreamSvg');
      const card = document.getElementById('secStreamCard');
      if (!svg || !card) return;

      const W = card.clientWidth || 600;
      const H = 220;
      const top = 20, bot = 25, mid = top + (H - top - bot) / 2;
      svg.setAttribute('width', W);
      svg.setAttribute('height', H);
      svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

      const D = this.streamData;
      const n = D.length;
      const tots = D.map(p => p.recon + p.fuzz + p.vulnerabilities);
      const mx = Math.max(...tots, 50);
      const mn = 0;
      const half = (H - top - bot) / 2;
      const k = p => ((p.recon + p.fuzz + p.vulnerabilities) / mx) * half * 1.8;
      const X = i => 20 + (i / (n - 1)) * (W - 40);

      const COL = {
        vuln: '#FF2A6D',
        fuzz: '#00F5FF',
        recon: '#A9B2FF'
      };

      const lay = D.map(p => {
        const q = k(p) / 2;
        const v = p.vulnerabilities * q;
        const f = p.fuzz * q;
        const r = p.recon * q;
        return { r, rf: r + f, rfv: r + f + v };
      });

      const band = key => {
        const T = D.map((p, i) => [X(i), mid - lay[i][key]]);
        const B = D.map((p, i) => [X(i), mid + lay[i][key]]).reverse();
        return smoothPath(T) + smoothPath(B, false) + 'Z';
      };

      svg.innerHTML = `
        <defs>
          <linearGradient id="secStreamGlow" x1="0" x2="1">
            <stop offset="0%" stop-color="#00F5FF" stop-opacity="0.2"/>
            <stop offset="100%" stop-color="#FF2A6D" stop-opacity="0.8"/>
          </linearGradient>
        </defs>
        <g>
          <path d="${band('rfv')}" fill="${COL.vuln}" opacity="0.9" />
          <path d="${band('rf')}" fill="${COL.fuzz}" opacity="0.85" />
          <path d="${band('r')}" fill="${COL.recon}" opacity="0.8" />
        </g>
        <line class="hl" y1="${top}" y2="${H - bot}" stroke="#00F5FF" stroke-width="1.5" stroke-dasharray="3,3" opacity="0"/>
        <rect width="${W}" height="${H}" fill="transparent" class="hit"/>
      `;

      const hit = svg.querySelector('.hit');
      const hl = svg.querySelector('.hl');

      hit.onpointermove = (e) => {
        const r = svg.getBoundingClientRect();
        const z = r.width / W;
        const x = (e.clientX - r.left) / z;
        const i = Math.max(0, Math.min(n - 1, Math.round(((x - 20) / (W - 40)) * (n - 1))));
        const p = D[i];

        hl.setAttribute('x1', X(i));
        hl.setAttribute('x2', X(i));
        hl.setAttribute('opacity', '1');

        showTip(
          r.left + X(i) * z,
          r.top + (mid - lay[i].rfv) * z,
          `Phase: ${p.label}`,
          [
            ['Exploit Surface', `${Math.round(p.vulnerabilities)} pts`, COL.vuln],
            ['Active Probing', `${Math.round(p.fuzz)} probes`, COL.fuzz],
            ['Recon Footprint', `${Math.round(p.recon)} targets`, COL.recon],
            ['Defenses', this.state.score >= 80 ? 'RESILIENT' : 'DEGRADED', this.state.score >= 80 ? '#00FF88' : '#FF2A6D']
          ]
        );
      };

      hit.onpointerleave = () => {
        hl.setAttribute('opacity', '0');
        hideTip();
      };
    }

    /* ── 2. Allocation Half-Gauge Arc with Tick Marks ── */
    drawVulnAllocation() {
      const svg = document.getElementById('secAllocSvg');
      if (!svg) return;

      const total = (this.state.high + this.state.med + this.state.low + this.state.info) || 1;
      const frHigh = this.state.high / total;
      const frMed = this.state.med / total;
      const frLow = (this.state.low + this.state.info) / total;

      const n = 48;
      let s = '';
      for (let i = 0; i <= n; i++) {
        const f = i / n;
        const a = 180 + f * 180;
        let col = '#00F5FF';
        if (total > 0 && (this.state.high > 0 || this.state.med > 0)) {
          if (f <= frHigh) col = '#FF2A6D';
          else if (f <= frHigh + frMed) col = '#FFA502';
          else col = '#00F5FF';
        } else {
          col = '#00FF88'; // Clean pristine state
        }

        const [x1, y1] = P2(118, a);
        const [x2, y2] = P2(i % 6 === 0 ? 98 : 104, a);
        s += `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" 
                   stroke="${col}" stroke-width="2.8" stroke-linecap="round" opacity="0.9"/>`;
      }

      svg.innerHTML = s;
    }

    /* ── 3. Mirrored Payload Flow Waves (Dispatched vs Blocked/Anomalies) ── */
    drawPayloadFlow() {
      const svg = document.getElementById('secPayloadFlowSvg');
      const card = document.getElementById('secPayloadFlowCard');
      if (!svg || !card) return;

      const W = card.clientWidth || 380;
      const H = 200;
      const L = 30, R = W - 25, mid = H / 2, lab = 12, amp = mid - lab - 10;
      svg.setAttribute('width', W);
      svg.setAttribute('height', H);
      svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

      const phases = ['DNS', 'HTTP', 'FUZZ', 'INJECT', 'PIVOT'];
      const sent = [12, 35, 88, 140, 95];
      const flags = [0, 2, 8, 22, 14];
      const maxVal = 150;

      const X = i => L + (i / (phases.length - 1)) * (R - L);
      const topWave = phases.map((_, i) => [X(i), mid - lab - (sent[i] / maxVal) * amp]);
      const botWave = phases.map((_, i) => [X(i), mid + lab + (flags[i] / maxVal) * amp]);

      let s = `
        <defs>
          <linearGradient id="flowTopGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#00F5FF" stop-opacity="0.3"/>
            <stop offset="100%" stop-color="#00F5FF" stop-opacity="0.0"/>
          </linearGradient>
          <linearGradient id="flowBotGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#FF2A6D" stop-opacity="0.0"/>
            <stop offset="100%" stop-color="#FF2A6D" stop-opacity="0.3"/>
          </linearGradient>
        </defs>
        <!-- Horizontal Grid Lines -->
        <line x1="${L}" x2="${R}" y1="${mid}" y2="${mid}" stroke="rgba(255,255,255,0.15)" stroke-dasharray="2,2"/>
        <line x1="${L}" x2="${R}" y1="${mid - lab - amp}" y2="${mid - lab - amp}" stroke="rgba(255,255,255,0.06)"/>
        <line x1="${L}" x2="${R}" y1="${mid + lab + amp}" y2="${mid + lab + amp}" stroke="rgba(255,255,255,0.06)"/>

        <!-- Phase Labels -->
        ${phases.map((p, i) => `<text x="${X(i)}" y="${mid + 4}" text-anchor="middle" font-size="9" font-weight="600" fill="rgba(255,255,255,0.5)" font-family="Geist Mono">${p}</text>`).join('')}

        <!-- Top Curve: Probes Dispatched -->
        <path d="${smoothPath(topWave)}" fill="none" stroke="#00F5FF" stroke-width="2" stroke-linecap="round"/>
        <!-- Bottom Curve: Flags / Anomalies -->
        <path d="${smoothPath(botWave)}" fill="none" stroke="#FF2A6D" stroke-width="2" stroke-linecap="round"/>

        <line class="flow-hl" y1="10" y2="${H - 10}" stroke="#fff" opacity="0"/>
        <rect class="flow-hit" x="${L - 10}" width="${R - L + 20}" height="${H}" fill="transparent"/>
      `;

      svg.innerHTML = s;
      const hit = svg.querySelector('.flow-hit');
      const hl = svg.querySelector('.flow-hl');

      hit.onpointermove = (e) => {
        const r = svg.getBoundingClientRect();
        const z = r.width / W;
        const x = (e.clientX - r.left) / z;
        const i = Math.max(0, Math.min(phases.length - 1, Math.round(((x - L) / (R - L)) * (phases.length - 1))));

        hl.setAttribute('x1', X(i));
        hl.setAttribute('x2', X(i));
        hl.setAttribute('opacity', '1');

        showTip(
          r.left + X(i) * z,
          r.top + (mid - lab - (sent[i] / maxVal) * amp) * z,
          `Vector Stage: ${phases[i]}`,
          [
            ['Payloads Dispatched', `${sent[i]} req`, '#00F5FF'],
            ['Anomalies / Hits', `${flags[i]} flags`, '#FF2A6D'],
            ['Filter Evasion', flags[i] > 0 ? 'ALERT' : 'CLEAN', flags[i] > 0 ? '#FFA502' : '#00FF88']
          ]
        );
      };

      hit.onpointerleave = () => {
        hl.setAttribute('opacity', '0');
        hideTip();
      };
    }

    /* ── 4. Attack Vector Sparkline Candles ── */
    drawVectorCandles() {
      const container = document.getElementById('secVectorCandlesList');
      if (!container) return;

      const vectors = [
        { id: 'sqli', name: 'SQL Injection (SQLi)', code: 'SQLI', count: this.state.high, status: this.state.high > 0 ? 'COMPROMISED' : 'TESTED', del: '+1.4%' },
        { id: 'xss', name: 'Cross-Site Scripting', code: 'XSS', count: this.state.med, status: this.state.med > 0 ? 'DETECTED' : 'ARMED', del: '+2.8%' },
        { id: 'dir', name: 'DirBuster Wordlist', code: 'DIRS', count: this.state.low, status: 'FUZZING', del: '+12.4%' },
        { id: 'csrf', name: 'CSRF & State Forms', code: 'CSRF', count: this.state.info, status: 'VERIFIED', del: '0.0%' }
      ];

      container.innerHTML = vectors.map((v, i) => {
        const sparklinePoints = [
          [2, 22], [24, 18], [48, 14], [72, 8], [94, v.count > 0 ? 4 : 12]
        ];
        const pathD = smoothPath(sparklinePoints);
        const col = v.count > 0 ? '#FF2A6D' : '#00F5FF';

        return `
          <div style="display:flex; align-items:center; justify-content:space-between; height:46px; ${i ? 'border-top:1px solid rgba(255,255,255,0.06);' : ''}">
            <div style="flex:1; min-width:0;">
              <div style="font-size:13px; font-weight:600; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${v.name}</div>
              <div class="mono muted" style="font-size:10.5px;">${v.code} · ${v.status}</div>
            </div>
            <div style="width:96px; height:28px; margin: 0 10px;">
              <svg width="96" height="28" viewBox="0 0 96 28">
                <path d="${pathD}" fill="none" stroke="${col}" stroke-width="1.8" stroke-linecap="round"/>
                <circle cx="94" cy="${v.count > 0 ? 4 : 12}" r="3" fill="${col}" stroke="#000" stroke-width="1"/>
              </svg>
            </div>
            <div style="width:70px; text-align:right;">
              <div class="mono" style="font-size:13px; font-weight:600; color:#fff;">${v.count} hits</div>
              <div class="mono" style="font-size:10.5px; color:${v.count > 0 ? 'var(--crit)' : 'var(--acc)'};">${v.del}</div>
            </div>
          </div>
        `;
      }).join('');
    }

    /* ── 5. Runway Ticks for Velocity Card ── */
    drawRunwayTicks() {
      const svg = document.getElementById('secVelocityTicksSvg');
      if (!svg) return;
      const W = svg.clientWidth || 180;
      const n = 28;
      let s = '';
      for (let i = 0; i < n; i++) {
        const x = 1 + i * (W - 2) / (n - 1);
        const on = i / (n - 1) <= 0.65;
        s += `<line x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="${i % 5 === 0 ? 0 : 4}" y2="14" 
                   stroke="${on ? 'var(--acc)' : 'rgba(255,255,255,0.18)'}" stroke-width="1.6" stroke-linecap="round"/>`;
      }
      svg.innerHTML = s;
    }

    /* ── Live Updates from SkillGuard Agent Execution ── */
    update(data) {
      if (!data) return;
      if (typeof data.score === 'number') this.state.score = data.score;
      if (data.grade) this.state.grade = data.grade;
      if (typeof data.high === 'number') this.state.high = data.high;
      if (typeof data.medium === 'number') this.state.med = data.medium;
      if (typeof data.low === 'number') this.state.low = data.low;
      if (typeof data.info === 'number') this.state.info = data.info;

      // Update resilience tile
      const resVal = document.getElementById('secResilienceVal');
      const resDelta = document.getElementById('secResilienceDelta');
      if (resVal) resVal.textContent = `${this.state.score}%`;
      if (resDelta) {
        if (this.state.score >= 90) {
          resDelta.textContent = '↑ OPTIMAL DEFENSE';
          resDelta.style.color = '#050810';
        } else if (this.state.score >= 70) {
          resDelta.textContent = '⚠ MINOR EXPOSURES';
          resDelta.style.color = '#050810';
        } else {
          resDelta.textContent = '⚡ CRITICAL COMPROMISE';
          resDelta.style.color = '#FF2A6D';
        }
      }

      // Re-render subcomponents
      this.drawVulnAllocation();
      this.drawVectorCandles();
      this.drawThreatStream();
    }
  }

  // Export singleton to global
  global.SkillGuardBento = new SecurityBentoController();

})(window);
