/* 态势星图：数据源是星，可信度是光，污染是红移（方案 §2-§3）
   实现：scatter 星点 + lines 连线（坐标系行为稳定），不用 graph 系列 */
(() => {
  const ACCENT = "#4dd0ff";
  const DANGER = "#ff5d6c";
  const PURPLE = "#b48cff";
  const DIM = "#9db3cf";

  const HOST_POS = {
    "lab-pc-01": [-330, -110],
    "lab-pc-02": [-170, 190],
    "srv-web-01": [280, -170],
    "srv-db-01": [330, 130],
    "ops-term-03": [-40, -270],
  };
  const KNOWN = Object.keys(HOST_POS);
  const CORE = "__core__";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const stats = {};   // host -> {scores, blocked, poisonedUntil, lastPayload}
  const pulseAt = {}; // host -> 上次脉冲时间（300ms 限流）

  function emptyStats() {
    return { scores: [], blocked: 0, poisonedUntil: 0, lastPayload: null };
  }

  function mean(arr) {
    return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
  }

  /* 未知主机（伪造名）→ 哈希到外环固定位，现形为"陌生星" */
  function posOf(host) {
    if (HOST_POS[host]) return HOST_POS[host];
    let h = 0;
    for (const ch of host) h = (h * 31 + ch.charCodeAt(0)) % 3600;
    const angle = (h / 3600) * Math.PI * 2;
    const r = 380 + (h % 90);
    return [Math.round(Math.cos(angle) * r), Math.round(Math.sin(angle) * r * 0.72)];
  }

  /* 装饰星空（确定性） */
  const deco = (() => {
    let s = 42;
    const rand = () => (s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296;
    const pts = [];
    for (let i = 0; i < 90; i++) {
      const x = Math.round((rand() - 0.5) * 1040);
      const y = Math.round((rand() - 0.5) * 680);
      if (Math.abs(x) < 60 && Math.abs(y) < 60) continue;
      pts.push({ value: [x, y], symbolSize: 1 + rand() * 1.8 });
    }
    return pts;
  })();

  const chart = echarts.init(document.getElementById("star-chart"));
  chart.setOption({
    animation: false,
    tooltip: {
      confine: true,
      backgroundColor: "rgba(16, 28, 44, 0.92)",
      borderColor: "rgba(255, 255, 255, 0.14)",
      textStyle: { color: "#eaf2ff", fontSize: 12 },
      extraCssText: "border-radius: 14px;",
    },
    xAxis: { min: -560, max: 560, show: false },
    yAxis: { min: -380, max: 380, show: false },
    series: [
      { // 主星与中心核
        type: "scatter", coordinateSystem: "cartesian2d", data: [],
        label: { show: true, position: "bottom", fontSize: 10, color: DIM, formatter: (p) => p.name },
        emphasis: { scale: 1.15 }, z: 4,
      },
      { // 星座连线（星 → 中心核）
        type: "lines", coordinateSystem: "cartesian2d", data: [],
        lineStyle: { color: "rgba(255,255,255,0.08)", width: 1, curveness: 0.12 }, z: 1,
      },
      { // 红移脉冲
        type: "effectScatter", coordinateSystem: "cartesian2d", data: [],
        symbolSize: 26, rippleEffect: { brushType: "stroke", scale: 3.2, period: 2.2 },
        itemStyle: { color: DANGER, shadowBlur: 16, shadowColor: DANGER }, z: 6, silent: true,
      },
      { // 装饰星空
        type: "scatter", coordinateSystem: "cartesian2d", data: deco,
        itemStyle: { color: "rgba(255,255,255,0.22)" }, z: 0, silent: true,
      },
    ],
  });

  chart.setOption({
    series: [{
      tooltip: {
        formatter: (p) => {
          const d = p.data;
          if (d.host === CORE) return "验证引擎核心";
          const s = stats[d.host] || emptyStats();
          const avg = mean(s.scores);
          return (
            `${d.host}${KNOWN.includes(d.host) ? "" : "（陌生源）"}<br>` +
            `近期均分 ${avg === null ? "—" : avg.toFixed(1)}<br>拦截 ${s.blocked} 条`
          );
        },
      },
    }],
  });

  function render() {
    const now = Date.now();
    const nodes = [{
      value: [0, 0], name: "验证引擎", host: CORE, symbolSize: 36,
      itemStyle: { color: ACCENT, shadowBlur: 32, shadowColor: "rgba(77,208,255,0.75)" },
      label: { show: true, position: "bottom", fontSize: 11, color: "#cfe9ff" },
    }];
    const lines = [];

    for (const [host, s] of Object.entries(stats)) {
      const [x, y] = posOf(host);
      const avg = mean(s.scores);
      const poisoned = s.poisonedUntil > now;
      let color = "rgba(157,179,207,0.45)"; // 待机灰
      if (avg !== null) color = poisoned ? DANGER : avg < 80 ? PURPLE : ACCENT;
      nodes.push({
        value: [x, y], name: host, host, symbolSize: avg === null ? 8 : 8 + (avg / 100) * 14,
        itemStyle: { color, shadowBlur: poisoned ? 26 : 14, shadowColor: color },
      });
      lines.push({
        coords: [[x, y], [0, 0]],
        lineStyle: {
          color: poisoned ? "rgba(255,93,108,0.55)" : "rgba(255,255,255,0.08)",
          width: poisoned ? 2 : 1,
        },
      });
    }
    for (const host of KNOWN) {
      if (!stats[host]) {
        const [x, y] = HOST_POS[host];
        nodes.push({
          value: [x, y], name: host, host, symbolSize: 8,
          itemStyle: { color: "rgba(157,179,207,0.45)", shadowBlur: 8 },
        });
        lines.push({ coords: [[x, y], [0, 0]] });
      }
    }
    chart.setOption({ series: [{ data: nodes }, { data: lines }, {}, {}] });
  }

  function pulse(host) {
    if (reduceMotion) return;
    const now = Date.now();
    if (now - (pulseAt[host] || 0) < 300) return;
    pulseAt[host] = now;
    const [x, y] = posOf(host);
    chart.setOption({ series: [{}, {}, { data: [{ value: [x, y] }] }, {}] });
    setTimeout(() => chart.setOption({ series: [{}, {}, { data: [] }, {}] }), 700);
  }

  function update(p) {
    const host = p.host || "unknown";
    const s = stats[host] || (stats[host] = emptyStats());
    s.scores.push(p.score);
    if (s.scores.length > 50) s.scores.shift();
    s.lastPayload = p;
    if (p.blocked) {
      s.blocked += 1;
      s.poisonedUntil = Date.now() + 5000;
      pulse(host);
    }
  }

  function reset() {
    for (const k of Object.keys(stats)) delete stats[k];
    render();
  }

  chart.on("click", (params) => {
    const d = params.data || {};
    if (!d.host || d.host === CORE) return;
    const s = stats[d.host];
    if (s && s.lastPayload && typeof window.updateExplain === "function") {
      window.updateExplain(s.lastPayload);
    }
  });

  window.StarMap = {
    update,
    render,
    reset,
    resize: () => chart.resize(),
  };
})();
