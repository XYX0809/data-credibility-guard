/* 数据可信度验证大屏：实时评分曲线 + 阈值告警（批量刷图表防闪烁） */
const chart = echarts.init(document.getElementById("chart"));
const ACCENT = "#4dd0ff";
const DANGER = "#ff5d6c";

const seriesData = [];
const option = {
  backgroundColor: "transparent",
  animation: false,
  grid: { left: 52, right: 28, top: 36, bottom: 44 },
  tooltip: {
    trigger: "item",
    backgroundColor: "rgba(16, 28, 44, 0.92)",
    borderColor: "rgba(255, 255, 255, 0.14)",
    textStyle: { color: "#eaf2ff", fontSize: 12 },
    extraCssText: "border-radius: 14px; box-shadow: 0 12px 32px rgba(0,0,0,.4);",
  },
  xAxis: {
    type: "value", name: "事件序号", min: 0, max: 320,
    nameTextStyle: { color: "#9db3cf" },
    axisLine: { lineStyle: { color: "rgba(255,255,255,0.15)" } },
    axisLabel: { color: "#9db3cf" },
    splitLine: { show: false },
  },
  yAxis: {
    type: "value", min: 0, max: 100, name: "可信分",
    nameTextStyle: { color: "#9db3cf" },
    axisLine: { show: false },
    axisLabel: { color: "#9db3cf" },
    splitLine: { lineStyle: { color: "rgba(255,255,255,0.06)" } },
  },
  series: [{
    type: "line",
    showSymbol: true,
    symbolSize: 5,
    data: seriesData,
    lineStyle: { width: 2, color: ACCENT },
    areaStyle: {
      color: {
        type: "linear", x: 0, y: 0, x2: 0, y2: 1,
        colorStops: [
          { offset: 0, color: "rgba(77, 208, 255, 0.22)" },
          { offset: 1, color: "rgba(77, 208, 255, 0)" },
        ],
      },
    },
    markLine: {
      silent: true,
      symbol: "none",
      data: [{
        yAxis: 60,
        label: { formatter: "阻断阈值 60", color: DANGER, position: "insideEndTop" },
        lineStyle: { color: DANGER, type: "dashed", width: 1.5 },
      }],
    },
    markArea: {
      silent: true,
      itemStyle: { color: "rgba(255, 93, 108, 0.06)" },
      data: [[{ yAxis: 0 }, { yAxis: 60 }]],
    },
  }],
};
chart.setOption(option);
window.addEventListener("resize", () => chart.resize());

const socket = io();
let total = 0;
let blockedCount = 0;
let pending = [];
const phaseEl = document.getElementById("phase");

/* 图表 200ms 批量刷新一次，避免逐点重绘闪烁 */
setInterval(() => {
  if (!pending.length) return;
  for (const p of pending) {
    total += 1;
    seriesData.push({
      value: [total, p.score],
      itemStyle: { color: p.blocked ? DANGER : ACCENT },
    });
  }
  pending = [];
  document.getElementById("n-total").textContent = total;
  chart.setOption({ series: [{ data: seriesData }] });
}, 200);

socket.on("connect", () => {
  if (phaseEl.textContent.startsWith("连接") || phaseEl.textContent.startsWith("已断开")) {
    phaseEl.textContent = "已连接 · 等待数据…";
  }
});
socket.on("disconnect", () => {
  phaseEl.textContent = "已断开 · 重连中…";
});

socket.on("round", () => {
  seriesData.length = 0;
  pending = [];
  total = 0;
  blockedCount = 0;
  document.getElementById("n-total").textContent = "0";
  document.getElementById("n-block").textContent = "0";
  document.getElementById("block-list").innerHTML =
    '<div class="empty">暂无阻断事件</div>';
  chart.setOption({ series: [{ data: seriesData }] });
});

socket.on("phase", (p) => {
  phaseEl.textContent = `当前阶段：${p.label}（${p.count} 条）`;
});

socket.on("score", (p) => {
  pending.push(p);
  const cur = document.getElementById("current");
  cur.textContent = p.score.toFixed(0);
  cur.classList.toggle("danger", p.score < 60);
});

socket.on("block", (p) => {
  blockedCount += 1;
  document.getElementById("n-block").textContent = blockedCount;
  const list = document.getElementById("block-list");
  const hint = list.querySelector(".empty");
  if (hint) hint.remove();

  const div = document.createElement("div");
  div.className = "block-item";
  const hits = p.rule_hits.length ? p.rule_hits.join(" / ") : "综合异常";
  div.innerHTML =
    `<div class="eid">#${p.seq_no} · ${p.event_id}</div>` +
    `<div class="meta"><span class="score">${p.score} 分</span> · ${hits}` +
    (p.veto ? " · 已否决" : "") + `</div>`;
  list.prepend(div);
  while (list.children.length > 8) list.removeChild(list.lastChild);
});

socket.on("feed_done", () => {
  const text = phaseEl.textContent.replace("当前阶段：", "");
  if (!text.endsWith("· 演示完成")) phaseEl.textContent = text + " · 演示完成";
});
