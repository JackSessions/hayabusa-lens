"""The single-page interface (plain HTML, CSS and JavaScript; no external files, nothing is fetched from the internet)."""

PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hayabusa Lens</title>
<style>
:root{color-scheme:dark;--bg:#07090c;--panel:#0d1217;--line:#1c252d;--text:#d7e3ea;--mut:#7fa7b5;--cy:#38d6ff;--am:#ffb02e;--l0:#6b7f8c;--l1:#38d6ff;--l2:#ffb02e;--l3:#ff7a2e;--l4:#ff2d6f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
main{max-width:88rem;margin:0 auto;padding:1.2rem 1rem 3rem}
h1{margin:0;font:800 clamp(1.6rem,4vw,2.3rem) ui-monospace,monospace;letter-spacing:.04em;background:linear-gradient(90deg,#ff5f6d,#ffb02e,#ffe14a,#4af0a2,#38d6ff,#8b7bff,#e04aff);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block}
.sub{color:var(--mut);font:12px ui-monospace,monospace;margin:.2rem 0 1rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.9rem}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.row+.row{margin-top:.6rem}
input[type=text],input[type=search],select{background:#05080b;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.5rem .65rem;font:13px ui-monospace,monospace}
input.path{flex:1 1 22rem}
button{background:transparent;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.45rem .85rem;font:inherit;cursor:pointer}button:hover{border-color:var(--cy);color:var(--cy)}
button.go{background:var(--cy);color:#03141a;border-color:var(--cy);font-weight:700}button.go:hover{color:#03141a;filter:brightness(1.1)}button:disabled{opacity:.5;cursor:default}
.tabs{display:flex;gap:.3rem;margin-bottom:.7rem}.tabs button.on{border-color:var(--cy);color:var(--cy)}
.hb{font:12px ui-monospace,monospace;padding:.2rem .6rem;border-radius:999px;border:1px solid var(--line);color:var(--mut)}.hb.ok{border-color:#4af0a2;color:#4af0a2}.hb.no{border-color:var(--l3);color:var(--l3)}
.run{margin-top:.8rem;display:none;border-left:3px solid var(--cy);padding:.5rem .8rem;background:#0a1015;border-radius:0 6px 6px 0}.run pre{margin:.3rem 0 0;color:var(--mut);font:12px ui-monospace,monospace;white-space:pre-wrap}
.err{border-left:4px solid var(--l4);background:#1a0c10;padding:.6rem .9rem;border-radius:0 8px 8px 0;margin-top:.8rem;display:none}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:.6rem;margin:1rem 0 .6rem}
.tile{border:1px solid var(--c);border-radius:8px;padding:.5rem;text-align:center;cursor:pointer;background:transparent;color:var(--text);opacity:.45}.tile.on{opacity:1;background:color-mix(in oklab,var(--c) 10%,transparent)}.tile b{display:block;font-size:1.5rem;color:var(--c)}.tile span{color:var(--mut);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}
canvas#tl{display:block;width:100%;height:150px;background:#05080b;border:1px solid var(--line);border-radius:6px;cursor:crosshair}
.tlnote{display:flex;justify-content:space-between;color:var(--mut);font:11px ui-monospace,monospace;margin:.25rem 0 .7rem}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 19rem;gap:1rem;align-items:start}@media(max-width:62rem){.layout{grid-template-columns:1fr}.tiles{grid-template-columns:repeat(5,1fr)}}
.bar{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-bottom:.6rem}.bar input{flex:1 1 14rem}
.chip{display:inline-flex;gap:.4rem;align-items:center;border:1px solid var(--cy);color:var(--cy);border-radius:999px;padding:.05rem .2rem .05rem .6rem;font:12px ui-monospace,monospace}.chip button{border:0;padding:0 .4rem;color:inherit}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.4rem .45rem;border-bottom:1px solid var(--line);vertical-align:top}th{font:11px ui-monospace,monospace;color:var(--mut);text-transform:uppercase;position:sticky;top:0;background:var(--bg)}
tr.ev{cursor:pointer}tr.ev:hover{background:#0b1218}td.t{white-space:nowrap;font:12px ui-monospace,monospace;color:var(--mut)}td.d{color:#9fb6bf;font:12px ui-monospace,monospace;word-break:break-all;max-width:34rem}td.d div{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.lv{display:inline-block;border:1px solid var(--c);color:var(--c);border-radius:999px;padding:0 .55rem;font:11px ui-monospace,monospace;text-transform:uppercase}
.side .panel{margin-bottom:.8rem;padding:.6rem .7rem}.side h3{margin:0 0 .4rem;font:600 11px ui-monospace,monospace;color:var(--mut);text-transform:uppercase;letter-spacing:.08em}
.fa{background:linear-gradient(90deg,rgba(56,214,255,.10) var(--w,0%),transparent var(--w,0%));display:flex;justify-content:space-between;gap:.5rem;padding:.18rem .3rem;border-radius:4px;cursor:pointer;font-size:.83rem}.fa:hover{background:#0b1218}.fa.on{background:#102028;color:var(--cy)}.fa span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fa b{color:var(--mut);font:12px ui-monospace,monospace}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:.4rem;background:var(--c)}
.pager{display:flex;gap:.6rem;align-items:center;justify-content:center;margin:.8rem 0;color:var(--mut);font:12px ui-monospace,monospace}
.dl a{color:var(--cy);margin-right:1rem;font:13px ui-monospace,monospace}
#drawer{position:fixed;top:0;right:0;bottom:0;width:min(42rem,100vw);background:#0a0f14;border-left:1px solid var(--line);padding:1rem 1.1rem;overflow:auto;transform:translateX(105%);transition:transform .2s;z-index:8;box-shadow:-10px 0 30px #0008}#drawer.open{transform:none}
#drawer h2{margin:.2rem 2rem .4rem 0;font-size:1.1rem}#drawer table td:first-child{color:var(--mut);font:12px ui-monospace,monospace;width:9rem;white-space:nowrap}#drawer td{border-bottom:1px solid var(--line);word-break:break-word}
#drawer .x{position:absolute;top:.7rem;right:.8rem}.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 .55rem;margin:.1rem .2rem .1rem 0;font:12px ui-monospace,monospace;color:var(--mut);text-decoration:none}a.tag:hover{border-color:var(--cy);color:var(--cy)}
.kv{margin:.5rem 0 1rem}.kv h4{margin:.8rem 0 .3rem;font:600 11px ui-monospace,monospace;color:var(--am);text-transform:uppercase;letter-spacing:.08em}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;place-items:center;z-index:9}#modal .box{width:min(42rem,94vw);max-height:80vh;display:flex;flex-direction:column}
#list{overflow:auto;border:1px solid var(--line);border-radius:6px;margin:.6rem 0}#list div{padding:.35rem .6rem;cursor:pointer;display:flex;justify-content:space-between;gap:1rem;font:13px ui-monospace,monospace}#list div:hover{background:#0b1218}
footer{margin-top:2rem;color:var(--mut);font-size:.82rem}footer a{color:var(--cy)}.mut{color:var(--mut)}
</style>
<main>
<h1>Hayabusa Lens</h1><div class="sub">v__VERSION__ | an unofficial point-and-click front end for Hayabusa by Yamato Security | everything stays on this computer</div>
<div class="panel">
  <div class="row" style="justify-content:space-between"><div class="tabs" id="tabs"><button data-t="scan" class="on">Scan logs</button><button data-t="open">Open results</button><button data-t="demo">Try the demo</button></div><span id="hb" class="hb">checking Hayabusa…</span></div>
  <div id="p-scan"><div class="row"><input class="path" id="spath" type="text" placeholder="A .evtx file or a folder of .evtx files (e.g. /cases/host1/Logs)" spellcheck="false"><button id="b1">Browse…</button></div>
    <div class="row"><label class="mut">Minimum level <select id="minl"><option value="informational">informational (everything)</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></label>
      <label class="mut"><input type="checkbox" id="noisy"> include noisy rules</label><button id="scan" class="go">Scan</button><button id="rules" title="Download the latest Hayabusa rules (needs internet)">Update rules</button></div></div>
  <div id="p-open" style="display:none"><div class="row"><input class="path" id="opath" type="text" placeholder="An existing Hayabusa timeline: .jsonl, .json or .csv" spellcheck="false"><button id="b2">Browse…</button><button id="open" class="go">Open</button></div></div>
  <div id="p-demo" style="display:none"><div class="row"><span class="mut">Loads clearly fictional sample detections so you can explore the interface without Hayabusa or any logs.</span><button id="demo" class="go">Load demo data</button></div></div>
  <div class="run" id="run"><b id="phase"></b> <span class="mut" id="el"></span><pre id="log"></pre></div>
</div>
<div class="err" id="err"></div>
<div id="out" style="display:none">
  <div class="row" style="margin-top:1rem;justify-content:space-between"><div class="mut" id="sum"></div><div class="dl" id="dl"></div></div>
  <div class="tiles" id="tiles"></div>
  <canvas id="tl"></canvas><div class="tlnote"><span id="tl1"></span><span id="tlmid">drag on the chart to zoom into a time range</span><span id="tl2"></span></div>
  <div class="bar"><input id="q" type="search" placeholder="Search rules, computers, command lines, users…" spellcheck="false"><select id="sort"><option value="time">oldest first</option><option value="-time">newest first</option><option value="level">highest severity first</option></select><span id="chips"></span><button id="clear">Clear filters</button></div>
  <div class="layout"><div><table><thead><tr><th>Time (UTC)</th><th>Level</th><th>Rule</th><th>Computer</th><th>Channel</th><th>EID</th><th>Details</th></tr></thead><tbody id="rows"></tbody></table>
    <div class="pager"><button id="prev">‹ Prev</button><span id="pg"></span><button id="next">Next ›</button></div></div>
  <div class="side" id="side"></div></div>
</div>
<footer>Created by <a href="__URL__" target="_blank" rel="noopener">Jack Sessions</a> | Hayabusa Lens __VERSION__ | MIT licence | an unofficial tool: <a href="https://github.com/Yamato-Security/hayabusa" target="_blank" rel="noopener">Hayabusa</a> is by Yamato Security (AGPL-3.0)</footer>
</main>
<div id="drawer"><button class="x" id="dx">Close ✕</button><div id="dbody"></div></div>
<div id="modal"><div class="panel box"><div class="row"><b>Choose</b><span class="mut" id="cwd" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span><button id="usef">Use this folder</button><button id="close">Close</button></div><div id="list"></div><small class="mut">Click a folder to open it, a file to select it.</small></div></div>
<script>
const Q=new URLSearchParams(location.search),TOKEN=Q.get('token'),$=id=>document.getElementById(id),H={'X-HL-Token':TOKEN};
const api=(u,o={})=>fetch(u,{...o,headers:{...H,...(o.headers||{})}}).then(r=>r.json());
const LV=['informational','low','medium','high','critical'],COL=['#6b7f8c','#38d6ff','#ffb02e','#ff7a2e','#ff2d6f'];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let job=null,timer=null,F={levels:new Set([1,2,3,4]),computer:'',rule:'',tactic:'',tag:'',eid:'',chan:'',q:'',frm:null,to:null,sort:'time',offset:0},TL=null,total=0,qt=null,pickTarget=null,PAGE=100;
function qs(extra={}){const p=new URLSearchParams({job,levels:[...F.levels].join(','),q:F.q,computer:F.computer,rule:F.rule,tactic:F.tactic,tag:F.tag,eid:F.eid,chan:F.chan,sort:F.sort,offset:F.offset,limit:PAGE,...extra});if(F.frm!=null)p.set('frm',F.frm);if(F.to!=null)p.set('to',F.to);return p}
// ---- setup / hayabusa status
function checkHb(){return api('/api/hayabusa').then(h=>{const e=$('hb');if(h.found){e.className='hb ok';e.textContent='Hayabusa '+h.version+(h.release?' · '+h.release:'')+(h.rules?'':' · rules folder missing');e.title=h.path}else{e.className='hb no';e.innerHTML='Hayabusa not found · <button id="inst" class="go" style="padding:.1rem .6rem">Download it for me</button> <span class="mut">(official release from GitHub, about 47 MB)</span>';e.title=h.error||'';$('inst').onclick=()=>start('/api/install')}});}
checkHb();
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('on',x===b));['scan','open','demo'].forEach(t=>$('p-'+t).style.display=t===b.dataset.t?'':'none')});
function showErr(m){const e=$('err');e.textContent=m;e.style.display='block'}
async function start(url,body){$('err').style.display='none';$('out').style.display='none';$('run').style.display='block';$('phase').textContent='starting…';$('log').textContent='';
  const r=await api(url,{method:'POST',body:JSON.stringify(body||{})});if(r.error){$('run').style.display='none';return showErr(r.error)}job=r.job;poll()}
async function poll(){const s=await api('/api/status?job='+job);$('phase').textContent=s.phase||'working';$('el').textContent=s.elapsed+'s';if(s.progress){$('el').textContent+=' · '+Math.round(s.progress*100)+'%'}$('log').textContent=(s.log||[]).join('\n');
  if(s.state==='running'){timer=setTimeout(poll,500);return}$('run').style.display='none';if(s.state==='error')return showErr(s.error||'Something went wrong');loaded(s.summary)}
$('scan').onclick=()=>{const p=$('spath').value.trim();if(!p)return showErr('Choose a .evtx file or folder first.');start('/api/scan',{path:p,minLevel:$('minl').value,noisy:$('noisy').checked})};
$('open').onclick=()=>{const p=$('opath').value.trim();if(!p)return showErr('Choose a results file first.');start('/api/open',{path:p})};
$('demo').onclick=()=>start('/api/demo');$('rules').onclick=()=>start('/api/update-rules');
// ---- results
function loaded(sum){if(sum&&sum.source==='installed'){checkHb();$('run').style.display='block';$('phase').textContent='Hayabusa installed. You can scan now.';$('log').textContent='';return}if(!sum||!sum.total){return showErr('No detections found in these logs (or the rules were just updated).')}
  F={levels:new Set(sum.levels.slice(1).some(x=>x>0)?[1,2,3,4]:[0,1,2,3,4]),computer:'',rule:'',tactic:'',tag:'',eid:'',chan:'',q:'',frm:null,to:null,sort:'time',offset:0};$('q').value='';$('sort').value='time';
  $('out').style.display='block';$('sum').innerHTML=`<b>${sum.total.toLocaleString()}</b> detections · ${sum.computers} computer(s) · ${sum.files||'?'} file(s) · ${esc(sum.first)} → ${esc(sum.last)}${sum.skipped?` · ${sum.skipped} unreadable row(s) skipped`:''}${/demo/i.test(sum.source)?' · <b style="color:var(--am)">DEMO DATA</b>':''}`;
  const T=encodeURIComponent(TOKEN);$('dl').innerHTML=['csv','json','html'].map(k=>`<a data-fmt="${k}" href="#">Export ${k.toUpperCase()}</a>`).join('');
  document.querySelectorAll('#dl a').forEach(a=>a.onclick=e=>{e.preventDefault();location.href='/api/export?'+qs({fmt:a.dataset.fmt,token:TOKEN})});refresh()}
async function refresh(){const r=await api('/api/query?'+qs());total=r.total;TL=r.timeline;
  $('tiles').innerHTML=[4,3,2,1,0].map(i=>`<button class="tile ${F.levels.has(i)?'on':''}" data-l="${i}" style="--c:${COL[i]}"><b>${r.counts[i].toLocaleString()}</b><span>${LV[i]}</span></button>`).join('');
  document.querySelectorAll('.tile').forEach(t=>t.onclick=()=>{const l=+t.dataset.l;F.levels.has(l)?F.levels.delete(l):F.levels.add(l);F.offset=0;refresh()});
  $('rows').innerHTML=r.rows.map(x=>`<tr class="ev" data-i="${x.i}"><td class="t">${esc(x.t)}</td><td><span class="lv" style="--c:${COL[x.lvl]}">${['info','low','med','high','crit'][x.lvl]}</span></td><td>${esc(x.title)}</td><td>${esc(x.comp)}</td><td class="mut">${esc(x.chan)}</td><td>${esc(x.eid)}</td><td class="d"><div>${esc(x.d)}</div></td></tr>`).join('')||'<tr><td colspan="7" class="mut">No events match these filters.</td></tr>';
  document.querySelectorAll('tr.ev').forEach(t=>t.onclick=()=>detail(+t.dataset.i));
  const pages=Math.max(1,Math.ceil(total/PAGE));$('pg').textContent=`${total.toLocaleString()} events · page ${Math.floor(F.offset/PAGE)+1} of ${pages}`;$('prev').disabled=F.offset<=0;$('next').disabled=F.offset+PAGE>=total;
  drawChips();facets(r.facets);drawTL()}
function drawChips(){const names={computer:'computer',rule:'rule',tactic:'tactic',tag:'technique',eid:'event ID',chan:'channel'};let h='';for(const k in names)if(F[k])h+=`<span class="chip">${names[k]}: ${esc(F[k])}<button data-k="${k}" aria-label="remove">✕</button></span> `;
  if(F.frm!=null)h+=`<span class="chip">time range<button data-k="time" aria-label="remove">✕</button></span>`;$('chips').innerHTML=h;
  document.querySelectorAll('#chips button').forEach(b=>b.onclick=()=>{if(b.dataset.k==='time'){F.frm=F.to=null}else F[b.dataset.k]='';F.offset=0;refresh()})}
function facets(f){const sec=(title,key,items,dot)=>`<div class="panel"><h3>${title}</h3>${items.map(x=>`<div class="fa ${F[key]===x.name?'on':''}" style="--w:${Math.round(100*x.count/Math.max(1,items[0].count))}%" data-k="${key}" data-v="${esc(x.name)}"><span>${dot?`<i class="dot" style="--c:${COL[x.lvl]}"></i>`:''}${esc(x.name||'(none)')}</span><b>${x.count.toLocaleString()}</b></div>`).join('')||'<span class="mut">none</span>'}</div>`;
  $('side').innerHTML=sec('Top rules','rule',f.rules,true)+sec('MITRE tactics','tactic',f.tactics)+sec('Techniques','tag',f.tags)+sec('Computers','computer',f.computers)+sec('Event IDs','eid',f.eids)+sec('Channels','chan',f.channels);
  document.querySelectorAll('.fa').forEach(d=>d.onclick=()=>{const k=d.dataset.k;F[k]=F[k]===d.dataset.v?'':d.dataset.v;F.offset=0;refresh()})}
// ---- timeline with drag-to-zoom
const cv=$('tl'),ctx=cv.getContext('2d');let brush=null;
function drawTL(){const dpr=devicePixelRatio||1,W=cv.clientWidth,Hh=cv.clientHeight;cv.width=W*dpr;cv.height=Hh*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,Hh);
  if(!TL||!TL.buckets.length){$('tl1').textContent=$('tl2').textContent='';return}
  const B=TL.buckets,n=B.length,bw=W/n,mx=Math.max(1,...B.map(b=>b.reduce((a,c)=>a+c,0)));
  B.forEach((b,i)=>{let y=Hh-4;for(let l=0;l<5;l++){if(!F.levels.has(l)&&F.levels.size)continue;const h=(b[l]/mx)*(Hh-14);if(h<=0)continue;ctx.fillStyle=COL[l];ctx.fillRect(i*bw+1,y-h,Math.max(1,bw-2),h);y-=h}});
  const f=t=>new Date(t).toISOString().replace('T',' ').slice(0,16);$('tl1').textContent=f(TL.start);$('tl2').textContent=f(TL.start+TL.step*n);
  if(brush){ctx.fillStyle='rgba(56,214,255,.18)';ctx.strokeStyle='#38d6ff';const a=Math.min(brush.a,brush.b),b=Math.max(brush.a,brush.b);ctx.fillRect(a,0,b-a,Hh);ctx.strokeRect(a,0,b-a,Hh)}}
cv.onpointerdown=e=>{if(!TL||!TL.buckets.length)return;const r=cv.getBoundingClientRect();brush={a:e.clientX-r.left,b:e.clientX-r.left};cv.setPointerCapture(e.pointerId)};
cv.onpointermove=e=>{if(!brush)return;brush.b=e.clientX-cv.getBoundingClientRect().left;drawTL()};
cv.onpointerup=e=>{if(!brush)return;const W=cv.clientWidth,n=TL.buckets.length,a=Math.min(brush.a,brush.b),b=Math.max(brush.a,brush.b);brush=null;if(b-a<6){drawTL();return}
  const i=Math.max(0,Math.floor(a/W*n)),j=Math.min(n,Math.ceil(b/W*n));F.frm=TL.start+i*TL.step;F.to=TL.start+j*TL.step;F.offset=0;refresh()};
addEventListener('resize',()=>{if(TL)drawTL()});
// ---- controls
$('q').oninput=()=>{clearTimeout(qt);qt=setTimeout(()=>{F.q=$('q').value;F.offset=0;refresh()},250)};$('sort').onchange=()=>{F.sort=$('sort').value;F.offset=0;refresh()};
$('clear').onclick=()=>{F={...F,computer:'',rule:'',tactic:'',tag:'',eid:'',chan:'',q:'',frm:null,to:null,offset:0,levels:new Set([1,2,3,4])};$('q').value='';refresh()};
$('prev').onclick=()=>{F.offset=Math.max(0,F.offset-PAGE);refresh()};$('next').onclick=()=>{F.offset+=PAGE;refresh()};
// ---- event drawer
const kv=(o)=>o&&typeof o==='object'?Object.entries(o).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(typeof v==='object'?JSON.stringify(v):v)}</td></tr>`).join(''):`<tr><td colspan="2">${esc(o)}</td></tr>`;
async function detail(i){const e=await api(`/api/event?job=${job}&i=${i}`);if(e.error)return;
  const tags=[...e.tactics.map(t=>`<span class="tag">${esc(t)}</span>`),...e.tags.map(t=>e.links[t]?`<a class="tag" href="${e.links[t]}" target="_blank" rel="noopener">${esc(t)} ↗</a>`:`<span class="tag">${esc(t)}</span>`),...e.other.map(t=>`<span class="tag">${esc(t)}</span>`)].join('');
  $('dbody').innerHTML=`<span class="lv" style="--c:${COL[LV.indexOf(e.level)]}">${esc(e.level)}</span><h2>${esc(e.title)}</h2><div class="mut">${esc(e.t)} UTC · ${esc(e.comp)} · ${esc(e.chan)} · EID ${esc(e.eid)} · record ${esc(e.rid)}</div><div class="kv">${tags}</div>
  <div class="kv"><h4>Details</h4><table>${kv(e.details)}</table><h4>Extra fields</h4><table>${kv(e.extra)}</table><h4>Source</h4><table><tr><td>Rule file</td><td>${esc(e.rulefile)}</td></tr><tr><td>Rule ID</td><td>${esc(e.ruleid)}</td></tr><tr><td>Log file</td><td>${esc(e.evtx)}</td></tr></table></div>
  <button id="cp">Copy as JSON</button>`;$('drawer').classList.add('open');$('cp').onclick=()=>{navigator.clipboard&&navigator.clipboard.writeText(JSON.stringify(e,null,2));$('cp').textContent='Copied ✓'}}
$('dx').onclick=()=>$('drawer').classList.remove('open');addEventListener('keydown',e=>{if(e.key==='Escape'){$('drawer').classList.remove('open');$('modal').style.display='none'}});
// ---- file browser
async function ls(p){const r=await api('/api/ls?path='+encodeURIComponent(p||''));$('cwd').textContent=r.path;$('cwd').dataset.p=r.path;
  const up=r.parent&&r.parent!==r.path?`<div data-p="${esc(r.parent)}" data-d="1"><span>⬑ ..</span></div>`:'';
  $('list').innerHTML=up+(r.error?`<div class="mut">${esc(r.error)}</div>`:'')+r.entries.map(e=>`<div data-p="${esc(r.path+(r.path.endsWith(r.sep)?'':r.sep)+e.name)}" data-d="${e.dir?1:0}"><span>${e.dir?'📁 ':'📄 '}${esc(e.name)}</span><span class="mut">${e.dir?'':(e.size/1048576).toFixed(1)+' MB'}</span></div>`).join('');
  $('list').querySelectorAll('div[data-p]').forEach(d=>d.onclick=()=>{if(d.dataset.d==='1')ls(d.dataset.p);else{$(pickTarget).value=d.dataset.p;$('modal').style.display='none'}})}
function browse(target){pickTarget=target;$('usef').style.display=target==='spath'?'':'none';$('modal').style.display='grid';ls($(target).value.trim().replace(/[\\/][^\\/]*$/,'')||'')}
$('b1').onclick=()=>browse('spath');$('b2').onclick=()=>browse('opath');$('close').onclick=()=>$('modal').style.display='none';$('usef').onclick=()=>{$('spath').value=$('cwd').dataset.p;$('modal').style.display='none'};
if(Q.get('demo')){$('demo').click()}else if(Q.get('path')){const p=Q.get('path');if(/\.(jsonl|json|csv)$/i.test(p)){$('opath').value=p;document.querySelector('[data-t=open]').click();$('open').click()}else{$('spath').value=p;$('scan').click()}}
</script></html>"""
