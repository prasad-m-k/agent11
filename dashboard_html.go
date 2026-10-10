package main

// dashboardHTML is the self-contained dashboard page: inline CSS and vanilla
// JS, no external resources (the page's own CSP forbids them). It fetches
// /api/metrics and /api/timeline and renders AI tool usage, agent activity,
// and data-protection decisions. It must contain no backtick characters.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent11 activity</title>
<style>
  :root {
    --bg: #f6f7f9; --panel: #ffffff; --ink: #1a1d24; --muted: #5a6473;
    --line: #e3e7ed; --accent: #2f6df6; --block: #d1453b; --warn: #c7820a; --ok: #2e8b57;
    --bar: #c6d2e6; --grid: #eef1f5;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0f1216; --panel: #171b21; --ink: #e8ecf1; --muted: #93a0b0; --line: #262c34;
      --accent: #5b8cff; --block: #ff6b5e; --warn: #e3a32a; --ok: #46c47e; --bar: #2b3a55; --grid: #1e242c;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  header { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between;
    padding: 16px 20px; border-bottom: 1px solid var(--line); background: var(--panel); position: sticky; top: 0; z-index: 5; }
  h1 { font-size: 16px; margin: 0; font-weight: 650; letter-spacing: .2px; }
  h1 small { color: var(--muted); font-weight: 400; margin-left: 8px; }
  .controls { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  button { font: inherit; color: var(--ink); background: var(--bg); border: 1px solid var(--line);
    border-radius: 7px; padding: 5px 11px; cursor: pointer; }
  button.on { background: var(--accent); color: #fff; border-color: var(--accent); }
  main { padding: 20px; max-width: 1180px; margin: 0 auto; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .tile { background: var(--panel); border: 1px solid var(--line); border-radius: 11px; padding: 14px 16px; }
  .tile .n { font-size: 24px; font-weight: 680; letter-spacing: -.3px; }
  .tile .l { color: var(--muted); font-size: 12px; margin-top: 2px; }
  .tile .s { font-size: 12px; margin-top: 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 16px; }
  section.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px 18px; }
  section.card.wide { grid-column: 1 / -1; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted);
    margin: 0 0 12px; font-weight: 650; }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--grid); white-space: nowrap; }
  th { color: var(--muted); font-weight: 550; font-size: 12px; }
  td.num, th.num { text-align: right; }
  td.name { max-width: 240px; overflow: hidden; text-overflow: ellipsis; }
  .bar { position: relative; background: var(--grid); border-radius: 5px; height: 9px; overflow: hidden; min-width: 60px; }
  .bar > span { position: absolute; left: 0; top: 0; bottom: 0; background: var(--bar); }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .pill.block { background: color-mix(in srgb, var(--block) 18%, transparent); color: var(--block); }
  .pill.warn { background: color-mix(in srgb, var(--warn) 20%, transparent); color: var(--warn); }
  .pill.ok { background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok); }
  .seg { display: flex; height: 22px; border-radius: 6px; overflow: hidden; border: 1px solid var(--line); }
  .seg > span { display: block; }
  .legend { display: flex; flex-wrap: wrap; gap: 10px 16px; margin-top: 10px; color: var(--muted); font-size: 12px; }
  .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: middle; }
  .muted { color: var(--muted); }
  .empty { color: var(--muted); font-style: italic; padding: 8px 0; }
  svg { display: block; width: 100%; height: 150px; }
  .foot { color: var(--muted); font-size: 12px; margin: 24px 4px 8px; }
  a { color: var(--accent); }
</style>
</head>
<body>
<header>
  <h1>agent11 activity <small id="window"></small></h1>
  <div class="controls">
    <span id="ranges"></span>
    <button id="refresh" title="Refresh now">Refresh</button>
    <button id="auto" title="Auto-refresh every 15s">Auto</button>
  </div>
</header>
<main>
  <div class="tiles" id="tiles"></div>
  <section class="card wide" style="margin-bottom:16px">
    <h2>Activity over time <span id="zoomnote" class="muted" style="text-transform:none;letter-spacing:0;font-weight:400"></span></h2>
    <div id="chart"></div>
    <div class="legend" id="chartlegend"></div>
    <div class="muted" style="font-size:11px;margin-top:4px">Drag across the chart to zoom to a time span. Click a legend to show or hide that series.</div>
  </section>
  <div class="grid" id="cards"></div>
  <section class="card wide" id="eventscard" style="margin-top:16px"></section>
  <div class="foot" id="foot"></div>
</main>
<script>
"use strict";
var state = { from: "24h", absFrom: null, absTo: null, auto: false, timer: null,
  series: { events: true, turns: true, blocked: true, sensitive: true },
  lastTimeline: null, eventsKind: "", eventsOffset: 0 };
var SERIES = [["events","--accent","events"],["turns","--ok","agent turns"],["blocked","--block","blocked"],["sensitive","--warn","sensitive"]];
var RANGES = [["1h","1h"],["6h","6h"],["24h","24h"],["7d","7d"],["30d","30d"]];

function el(tag, attrs, kids) {
  var e = document.createElement(tag);
  if (attrs) for (var k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
    else if (k === "text") e.textContent = attrs[k];
    else e.setAttribute(k, attrs[k]);
  }
  (kids || []).forEach(function(c){ if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
  return e;
}
function num(n){ return (n == null) ? "0" : n.toLocaleString(); }
function tok(n){ if (!n) return "0"; if (n >= 1e9) return (n/1e9).toFixed(1)+"B"; if (n >= 1e6) return (n/1e6).toFixed(1)+"M"; if (n >= 1e3) return (n/1e3).toFixed(1)+"K"; return String(n); }
function dur(ms){
  if (!ms || ms < 1000) return "0s";
  var s = Math.round(ms/1000), d = Math.floor(s/86400); s -= d*86400;
  var h = Math.floor(s/3600); s -= h*3600; var m = Math.floor(s/60);
  var out = [];
  if (d) out.push(d+"d"); if (h) out.push(h+"h"); if (m && !d) out.push(m+"m");
  if (!out.length) out.push(Math.round(ms/1000)+"s");
  return out.join(" ");
}
function mb(x){ return (x == null) ? "0" : x.toLocaleString(undefined,{maximumFractionDigits:0}) + " MB"; }
function pct(x){ return (x == null) ? "0%" : x.toLocaleString(undefined,{maximumFractionDigits:1}) + "%"; }
function fmtTime(ms){ var d = new Date(ms); return d.toLocaleString(); }

function sortedEntries(obj, drop){
  var out = [];
  for (var k in obj) { if (drop && drop.indexOf(k) >= 0) continue; if (obj[k]) out.push([k, obj[k]]); }
  out.sort(function(a,b){ return (typeof b[1] === "number" ? b[1]-a[1] : 0); });
  return out;
}

function tile(n, label, sub, cls){
  return el("div",{class:"tile"},[
    el("div",{class:"n"+(cls?" "+cls:""), text:n}),
    el("div",{class:"l", text:label}),
    sub ? el("div",{class:"s muted", text:sub}) : null
  ]);
}

function kvTable(cols, rows){
  if (!rows.length) return el("div",{class:"empty",text:"No activity in this window."});
  var head = el("tr",{}, cols.map(function(c){ return el("th",{class:c.num?"num":"", text:c.label}); }));
  var body = rows.map(function(r){
    return el("tr",{}, r.map(function(cell,i){
      if (cell && cell.bar !== undefined) {
        var b = el("div",{class:"bar"},[el("span",{style:"width:"+Math.min(100,cell.bar)+"%"+(cell.color?";background:"+cell.color:"")})]);
        return el("td",{}, [b]);
      }
      return el("td",{class:(cols[i].num?"num ":"")+(cols[i].name?"name":""), title:(cols[i].name?String(cell):""), text:String(cell)});
    }));
  });
  return el("table",{},[el("thead",{},[head]), el("tbody",{}, body)]);
}

function card(title, node, wide){
  return el("section",{class:"card"+(wide?" wide":"")},[el("h2",{text:title}), node]);
}

function barCell(v, maxv, color){ return {bar: maxv ? (100*v/maxv) : 0, color: color}; }

function stateSegments(tis){
  var order = [["working","var(--ok)"],["blocked","var(--warn)"],["idle","var(--bar)"],["error","var(--block)"],["unknown","var(--grid)"]];
  var total = 0; order.forEach(function(o){ total += (tis[o[0]]||0); });
  if (!total) return el("div",{class:"empty",text:"No agent sessions in this window."});
  var seg = el("div",{class:"seg"});
  order.forEach(function(o){
    var v = tis[o[0]]||0; if (!v) return;
    seg.appendChild(el("span",{style:"width:"+(100*v/total)+"%;background:"+o[1], title:o[0]+" "+dur(v)}));
  });
  var legend = el("div",{class:"legend"}, order.filter(function(o){return tis[o[0]];}).map(function(o){
    return el("span",{html:"<i style=\"background:"+o[1]+"\"></i>"+o[0]+" "+dur(tis[o[0]])});
  }));
  return el("div",{},[seg, legend]);
}

function cssVar(n){ return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }

function drawChart(tl){
  state.lastTimeline = tl;
  renderChartLegend();
  var box = document.getElementById("chart"); box.innerHTML = "";
  var pts = tl.points || [];
  if (pts.length < 2) { box.appendChild(el("div",{class:"empty",text:"Not enough data to chart."})); return; }
  var W = box.clientWidth || 1000, H = 150, pad = 4;
  var svg = document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox","0 0 "+W+" "+H); svg.setAttribute("preserveAspectRatio","none");
  svg.style.cursor = "crosshair";
  var active = SERIES.filter(function(s){ return state.series[s[0]]; }).map(function(s){ return s[0]; });
  var maxE = 1; pts.forEach(function(p){ active.forEach(function(k){ maxE = Math.max(maxE, p[k]); }); });
  function x(i){ return pad + i*(W-2*pad)/(pts.length-1); }
  function y(v){ return H-pad - v*(H-2*pad)/maxE; }
  if (state.series.events){
    var area = "M "+x(0)+" "+(H-pad);
    pts.forEach(function(p,i){ area += " L "+x(i)+" "+y(p.events); });
    area += " L "+x(pts.length-1)+" "+(H-pad)+" Z";
    svg.appendChild(mkPath(area, "none", cssVar("--accent")+"22"));
  }
  SERIES.forEach(function(s){ if (state.series[s[0]]) svg.appendChild(mkLine(pts, x, y, function(p){return p[s[0]];}, cssVar(s[1]))); });
  var sel = document.createElementNS("http://www.w3.org/2000/svg","rect");
  sel.setAttribute("y","0"); sel.setAttribute("height",String(H)); sel.setAttribute("fill",cssVar("--accent")+"33"); sel.setAttribute("visibility","hidden");
  svg.appendChild(sel);
  box.appendChild(svg);
  box.appendChild(el("div",{class:"legend"},[
    el("span",{class:"muted",text:fmtTime(tl.from_ms)}),
    el("span",{class:"muted",style:"margin-left:auto",text:fmtTime(tl.to_ms)})
  ]));
  attachBrush(svg, sel, tl);
}

// renderChartLegend draws clickable series toggles.
function renderChartLegend(){
  var lg = document.getElementById("chartlegend"); lg.innerHTML = "";
  SERIES.forEach(function(s){
    var on = state.series[s[0]];
    var item = el("span",{style:"cursor:pointer;user-select:none;opacity:"+(on?"1":"0.4"),
      html:"<i style=\"background:"+cssVar(s[1])+"\"></i>"+s[2]});
    item.onclick = function(){ state.series[s[0]] = !state.series[s[0]]; if (state.lastTimeline) drawChart(state.lastTimeline); };
    lg.appendChild(item);
  });
}

// attachBrush lets the user drag across the chart to zoom to a time span.
function attachBrush(svg, sel, tl){
  var startX = null, rect = null;
  function fx(ev){ rect = svg.getBoundingClientRect(); return (ev.clientX - rect.left) / rect.width; }
  function toMs(frac){ return Math.round(tl.from_ms + Math.max(0,Math.min(1,frac)) * (tl.to_ms - tl.from_ms)); }
  svg.addEventListener("mousedown", function(ev){ startX = fx(ev); sel.setAttribute("visibility","visible"); ev.preventDefault(); });
  svg.addEventListener("mousemove", function(ev){
    if (startX === null) return;
    var cur = fx(ev), a = Math.min(startX,cur), b = Math.max(startX,cur), W = svg.viewBox.baseVal.width;
    sel.setAttribute("x", String(a*W)); sel.setAttribute("width", String((b-a)*W));
  });
  window.addEventListener("mouseup", function(ev){
    if (startX === null) return;
    var cur = fx(ev), a = Math.min(startX,cur), b = Math.max(startX,cur); startX = null;
    sel.setAttribute("visibility","hidden");
    if (b - a < 0.02) return; // a click, not a drag
    state.absFrom = toMs(a); state.absTo = toMs(b); state.eventsOffset = 0;
    load();
  });
}
function mkPath(d, fill, stroke){
  var p = document.createElementNS("http://www.w3.org/2000/svg","path");
  p.setAttribute("d",d); p.setAttribute("fill",fill); if (stroke!=="none"){p.setAttribute("fill",stroke);} p.setAttribute("stroke","none");
  return p;
}
function mkLine(pts, x, y, val, color){
  var d = ""; pts.forEach(function(p,i){ d += (i?" L ":"M ")+x(i)+" "+y(val(p)); });
  var p = document.createElementNS("http://www.w3.org/2000/svg","path");
  p.setAttribute("d",d); p.setAttribute("fill","none"); p.setAttribute("stroke",color);
  p.setAttribute("stroke-width","1.8"); p.setAttribute("stroke-linejoin","round"); p.setAttribute("vector-effect","non-scaling-stroke");
  return p;
}

function render(m, tl){
  document.getElementById("window").textContent = fmtTime(m.window.from_ms) + "  to  " + fmtTime(m.window.to_ms)
    + "  (" + m.coverage.covered_hours + "h covered" + (m.coverage.incomplete ? ", partial" : "") + ")";
  var zn = document.getElementById("zoomnote"); zn.innerHTML = "";
  if (state.absFrom && state.absTo){
    zn.appendChild(document.createTextNode(" - zoomed  "));
    var rb = el("button",{text:"reset zoom",style:"padding:2px 8px"}); rb.onclick = clearZoom; zn.appendChild(rb);
  }

  var d = m.decisions, c = m.clipboard, ag = m.agents, res = m.resources || {};
  var toolCount = Object.keys(m.ai_usage.apps).length + Object.keys(m.ai_usage.sites).length;
  var tiles = document.getElementById("tiles"); tiles.innerHTML = "";
  [
    tile(num(m.coverage.events_in_window), "events", "dropped: "+num(m.coverage.dropped_events)),
    tile(num(d.total), "LLM requests", d.per_hour!=null ? d.per_hour+"/hr" : null),
    tile(num(d.blocked), "blocked", d.flagged_report_only+" would-block (report)", d.blocked?"block":null),
    tile(num(c.sensitive), "sensitive copies", c.guarded+" guarded", c.sensitive?"warn":null),
    tile(num(ag.sessions.seen), "agent sessions", ag.turns.started+" turns"),
    tile(num(toolCount), "AI tools seen", null),
    tile(tok(m.tokens.total_tokens), "tokens (proxied)", num(m.tokens.input_tokens)+" in / "+num(m.tokens.output_tokens)+" out")
  ].forEach(function(t){ tiles.appendChild(t); });

  drawChart(tl);

  var cards = document.getElementById("cards"); cards.innerHTML = "";

  // Agents and AI tools detected on this system
  var kinds = m.agents.sessions.by_agent_kind || {};
  var hookable = {};
  for (var kk in kinds) hookable[kk] = true;
  var usage = [];
  function statusCell(ongoing){
    return ongoing ? el("span",{class:"pill ok",text:"running"}) : el("span",{class:"pill",style:"color:var(--muted)",text:"seen"});
  }
  function pushUsage(map, kind){
    for (var name in map){ var u = map[name]; var r = res[name] || {};
      usage.push([name, kind, u.ongoing, dur(u.active_ms), u.sessions,
        r.rss_peak_mb?mb(r.rss_peak_mb):"-", r.cpu_peak_pct!=null?pct(r.cpu_peak_pct):"-", u.active_ms]); }
  }
  pushUsage(m.ai_usage.apps, "app / CLI"); pushUsage(m.ai_usage.sites, "browser");
  usage.sort(function(a,b){ if (a[2]!==b[2]) return a[2]?-1:1; return b[7]-a[7]; });
  var maxU = usage.reduce(function(x,r){return Math.max(x,r[7]);},1);
  var running = usage.filter(function(r){return r[2];}).length;
  var head = [{label:"agent / tool",name:true},{label:"type"},{label:"status"},{label:"active"},
    {label:"sessions",num:true},{label:"peak mem",num:true},{label:"peak cpu",num:true},{label:""}];
  var tbl = el("table",{});
  tbl.appendChild(el("thead",{},[el("tr",{}, head.map(function(c){return el("th",{class:c.num?"num":"",text:c.label});}))]));
  var tb = el("tbody",{});
  if (!usage.length) tb.appendChild(el("tr",{},[el("td",{class:"empty",colspan:"8",text:"No AI tools seen in this window."})]));
  usage.forEach(function(r){
    tb.appendChild(el("tr",{},[
      el("td",{class:"name",title:r[0],text:r[0]}), el("td",{text:r[1]}),
      el("td",{},[statusCell(r[2])]), el("td",{text:r[3]}), el("td",{class:"num",text:r[4]}),
      el("td",{class:"num",text:r[5]}), el("td",{class:"num",text:r[6]}),
      el("td",{},[el("div",{class:"bar"},[el("span",{style:"width:"+Math.min(100,maxU?100*r[7]/maxU:0)+"%"})])])
    ]));
  });
  tbl.appendChild(tb);
  cards.appendChild(card("Agents & AI tools on this system  (" + running + " running now, " + usage.length + " seen)", tbl, true));

  // Agent activity
  var agNode = el("div",{});
  agNode.appendChild(stateSegments(ag.time_in_state_ms));
  var ao = ag.operator_response;
  agNode.appendChild(el("table",{style:"margin-top:12px"},[el("tbody",{},[
    trkv("Turns", ag.turns.started+" started, "+ag.turns.completed+" completed"+(ag.turns.ambiguous?", "+ag.turns.ambiguous+" ambiguous":"")),
    trkv("Operator waits", ao.wait_count ? (ao.wait_count+" waits, avg "+dur(ao.wait_avg_ms)+", p95 "+dur(ao.wait_p95_ms)) : "none observed"),
    trkv("Blocked on", blockedText(ag.blocked_ms)),
    trkv("Errors", ag.errors.session_failure+" session, "+ag.errors.child_spawned+" subagents"),
    trkv("Stalls", ag.stalls.length ? ag.stalls.length+" (longest "+dur(Math.max.apply(null,ag.stalls.map(function(s){return s.duration_ms;})))+")" : "none"),
    trkv("Sessions", kvInline(ag.sessions.by_agent_kind) + (Object.keys(ag.sessions.by_model).length?"  ·  "+kvInline(ag.sessions.by_model):""))
  ])]));
  cards.appendChild(card("Agent activity", agNode));

  // Data protection
  cards.appendChild(card("Data protection", el("div",{},[
    subhead("Decisions by verdict"), miniBars(d.by_verdict, verdictColor),
    subhead("Classes flagged"), classTable(d.by_class),
    subhead("Rules matched"), miniBars(d.by_rule, function(){return "var(--warn)";}),
  ])));

  // Clipboard and intake
  cards.appendChild(card("Clipboard & intake", el("div",{},[
    el("table",{},[el("tbody",{},[
      trkv("Clipboard copies", c.copies+" ("+c.sensitive+" sensitive, "+c.guarded+" guarded)"),
      trkv("Intake scans", m.intake.scans+" ("+m.intake.flagged+" flagged)")
    ])]),
    subhead("Clipboard rules"), miniBars(c.by_rule, function(){return "var(--warn)";})
  ])));

  // Destinations and models
  cards.appendChild(card("Destinations & models", el("div",{},[
    subhead("Requests by provider"), miniBars(m.launches.requests_by_provider, function(){return "var(--accent)";}),
    subhead("Requests by model"), miniBars(m.launches.requests_by_model, function(){return "var(--accent)";}),
    subhead("Destination hosts"), miniBars(d.by_destination, function(){return "var(--bar)";})
  ])));

  // Token usage (proxy only)
  var tkn = m.tokens;
  var tknRows = Object.keys(tkn.by_model || {}).map(function(model){
    var p = tkn.by_model[model]; return [model, p.input, p.output, p.input+p.output, p.requests];
  });
  tknRows.sort(function(a,b){ return b[3]-a[3]; });
  var tknNode = el("div",{});
  if (!tkn.requests) {
    tknNode.appendChild(el("div",{class:"empty",text:"No proxied LLM requests with token usage in this window. Only requests routed through agent11 report tokens."}));
  } else {
    tknNode.appendChild(el("table",{},[el("tbody",{},[
      trkv("Total tokens", num(tkn.total_tokens) + " (" + num(tkn.input_tokens) + " in, " + num(tkn.output_tokens) + " out)"),
      trkv("Requests", num(tkn.requests))
    ])]));
    tknNode.appendChild(subhead("By model"));
    tknNode.appendChild(kvTable(
      [{label:"model",name:true},{label:"input",num:true},{label:"output",num:true},{label:"total",num:true},{label:"requests",num:true}],
      tknRows.map(function(r){ return [r[0], num(r[1]), num(r[2]), num(r[3]), r[4]]; })
    ));
  }
  cards.appendChild(card("Token usage  (proxied requests only)", tknNode));

  // Latency and app launches
  var lat = d.latency_ms;
  cards.appendChild(card("agent11 overhead", el("div",{},[
    el("table",{},[el("tbody",{},[
      trkv("Decision latency", lat.count ? "p50 "+lat.p50+"ms, p95 "+lat.p95+"ms, max "+lat.max+"ms ("+lat.count+")" : "no decisions"),
      trkv("Policy reloads", String(m.policy.reloads)),
      trkv("App launches", Object.keys(m.launches.app_starts).length ? kvInline(m.launches.app_starts) : "none")
    ])]),
    res["agent11"] ? el("div",{class:"muted",style:"margin-top:8px",text:"agent11 itself: "+pct(res["agent11"].cpu_avg_pct)+" avg cpu, "+mb(res["agent11"].rss_peak_mb)+" peak mem"}) : null
  ])));

  document.getElementById("foot").textContent = "agent11 metrics schema v"+m.schema_version
    + " · body-free: this dashboard shows counts, labels and timings only, never captured content.";
}

function trkv(k, v){ return el("tr",{},[el("th",{text:k}), el("td",{text:v})]); }
function subhead(t){ return el("div",{class:"muted",style:"margin:12px 0 6px;font-size:12px",text:t}); }
function kvInline(obj){ var e = sortedEntries(obj); return e.length ? e.map(function(x){return x[0]+" "+x[1];}).join(", ") : "none"; }
function blockedText(b){ var e = sortedEntries(b); if(!e.length) return "none"; return e.map(function(x){return x[0]+" "+dur(x[1]);}).join(", "); }
function verdictColor(k){ return k==="block"?"var(--block)":k==="hold"?"var(--warn)":k==="allow"?"var(--ok)":"var(--bar)"; }

function miniBars(obj, colorFn){
  var e = sortedEntries(obj, ["(none)"]);
  if (!e.length) return el("div",{class:"empty",text:"none"});
  var maxv = e[0][1];
  var t = el("table",{});
  var tb = el("tbody",{});
  e.slice(0,10).forEach(function(x){
    tb.appendChild(el("tr",{},[
      el("td",{class:"name", title:x[0], text:x[0]}),
      el("td",{style:"width:50%"},[el("div",{class:"bar"},[el("span",{style:"width:"+(100*x[1]/maxv)+"%;background:"+colorFn(x[0])})])]),
      el("td",{class:"num", text:num(x[1])})
    ]));
  });
  t.appendChild(tb); return t;
}
function classTable(byClass){
  var ids = Object.keys(byClass); if(!ids.length) return el("div",{class:"empty",text:"none"});
  ids.sort(function(a,b){ return byClass[b].decisions - byClass[a].decisions; });
  var rows = ids.map(function(id){ var c = byClass[id];
    var tag = c.blocked ? el("span",{class:"pill block",text:num(c.blocked)+" blocked"})
      : c.flagged_report_only ? el("span",{class:"pill warn",text:num(c.flagged_report_only)+" would-block"})
      : el("span",{class:"pill ok",text:"allowed"});
    return el("tr",{},[el("td",{class:"name",text:id}), el("td",{class:"num",text:num(c.decisions)}), el("td",{},[tag])]);
  });
  return el("table",{},[el("thead",{},[el("tr",{},[el("th",{text:"class"}),el("th",{class:"num",text:"decisions"}),el("th",{text:""})])]), el("tbody",{},rows)]);
}

function windowQS(){
  if (state.absFrom && state.absTo) return "?from=" + state.absFrom + "&to=" + state.absTo;
  return "?from=" + encodeURIComponent(state.from);
}
function load(){
  var qs = windowQS();
  Promise.all([
    fetch("/api/metrics"+qs).then(function(r){ if(!r.ok) throw new Error("metrics "+r.status); return r.json(); }),
    fetch("/api/timeline"+qs).then(function(r){ if(!r.ok) throw new Error("timeline "+r.status); return r.json(); })
  ]).then(function(res){ render(res[0], res[1]); loadEvents(); })
    .catch(function(e){ document.getElementById("foot").textContent = "Error: " + e.message; });
}
function setRange(v){
  state.from = v; state.absFrom = null; state.absTo = null; state.eventsOffset = 0;
  var rg = document.getElementById("ranges").children;
  for (var i=0;i<rg.length;i++){ rg[i].classList.toggle("on", rg[i].dataset.v===v); }
  load();
}
function clearZoom(){ state.absFrom = null; state.absTo = null; state.eventsOffset = 0; load(); }

// loadEvents fetches and renders the timestamped event list for the window.
function loadEvents(){
  var qs = windowQS() + "&limit=100&offset=" + state.eventsOffset + (state.eventsKind ? "&kind=" + encodeURIComponent(state.eventsKind) : "");
  fetch("/api/events"+qs).then(function(r){ return r.json(); }).then(renderEvents)
    .catch(function(e){ document.getElementById("eventscard").textContent = "Events error: " + e.message; });
}
function renderEvents(page){
  var card = document.getElementById("eventscard"); card.innerHTML = "";
  card.appendChild(el("h2",{text:"Events  (" + num(page.total) + " in window)"}));
  var kinds = ["", "decision", "token_usage", "clipboard", "clipboard_guarded", "intake",
    "ai_app_started", "ai_app_stopped", "ai_site_opened", "ai_site_closed", "resource_sample",
    "agent_session_started", "agent_turn_started", "agent_turn_completed", "agent_tool_activity",
    "agent_question_requested", "agent_approval_requested", "agent_error", "policy_reload"];
  var sel = el("select",{style:"font:inherit;padding:4px 8px;border-radius:7px;border:1px solid var(--line);background:var(--bg);color:var(--ink);margin-bottom:10px"});
  kinds.forEach(function(k){ var o = el("option",{value:k,text:k||"all kinds"}); if (k===state.eventsKind) o.selected=true; sel.appendChild(o); });
  sel.onchange = function(){ state.eventsKind = sel.value; state.eventsOffset = 0; loadEvents(); };
  card.appendChild(sel);
  if (!page.events.length){ card.appendChild(el("div",{class:"empty",text:"No events."})); return; }
  var rows = page.events.map(function(e){
    return el("tr",{},[
      el("td",{style:"white-space:nowrap;color:var(--muted)",text:fmtTime(e.t_ms)}),
      el("td",{style:"white-space:nowrap",text:e.kind}),
      el("td",{class:"name",title:e.detail,text:e.detail})
    ]);
  });
  card.appendChild(el("table",{},[
    el("thead",{},[el("tr",{},[el("th",{text:"time"}),el("th",{text:"kind"}),el("th",{text:"detail"})])]),
    el("tbody",{}, rows)
  ]));
  var shown = state.eventsOffset + page.events.length;
  var bar = el("div",{style:"margin-top:10px;display:flex;gap:8px;align-items:center"});
  bar.appendChild(el("span",{class:"muted",text:"showing "+(state.eventsOffset+1)+"-"+shown+" of "+page.total}));
  if (shown < page.total){
    var more = el("button",{text:"Load more"});
    more.onclick = function(){ state.eventsOffset += 100; loadEvents(); };
    bar.appendChild(more);
  }
  if (state.eventsOffset > 0){
    var top = el("button",{text:"Back to newest"});
    top.onclick = function(){ state.eventsOffset = 0; loadEvents(); };
    bar.appendChild(top);
  }
  card.appendChild(bar);
}
function setAuto(on){
  state.auto = on;
  document.getElementById("auto").classList.toggle("on", on);
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
  if (on) state.timer = setInterval(load, 15000);
}

(function init(){
  var rg = document.getElementById("ranges");
  RANGES.forEach(function(r){
    var b = el("button",{text:r[0]}); b.dataset.v = r[1];
    b.onclick = function(){ setRange(r[1]); };
    rg.appendChild(b);
  });
  document.getElementById("refresh").onclick = load;
  document.getElementById("auto").onclick = function(){ setAuto(!state.auto); };
  setRange("24h");
})();
</script>
</body>
</html>
`
