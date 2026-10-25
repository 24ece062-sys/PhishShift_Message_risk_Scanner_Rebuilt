const $ = (id) => document.getElementById(id);
document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === btn));
  document.querySelectorAll('.panel').forEach(x => x.classList.toggle('active', x.id === btn.dataset.panel));
}));
$('message-input').addEventListener('input', e => $('char-count').textContent = `${e.target.value.length} characters`);
$('csv-file').addEventListener('change', e => $('file-name').textContent = e.target.files[0]?.name || 'No file selected');
function escapeHtml(v){return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function pillClass(risk){return /high/i.test(risk)?'high':(/caution|medium/i.test(risk)?'caution':'low');}
function renderResult(el, data, type){
  el.classList.remove('hidden');
  if(data.error){el.innerHTML=`<h3>Could not complete scan</h3><p>${escapeHtml(data.error)}</p>`;return;}
  if(type==='csv'){
    const rows=data.results.map(r=>`<tr><td>${r.row}</td><td>${escapeHtml(r.label)}</td><td>${r.phishing_probability}%</td><td>${escapeHtml(r.message)}</td><td>${escapeHtml(r.reasons)}</td></tr>`).join('');
    el.innerHTML=`<h3>CSV scan complete</h3><div class="csv-summary"><div class="metric"><b>${data.count}</b><span>Messages scanned</span></div><div class="metric"><b>${data.phishing}</b><span>Flagged as phishing</span></div><div class="metric"><b>${data.count-data.phishing}</b><span>Likely legitimate</span></div></div><div class="table-wrap"><table><thead><tr><th>Row</th><th>Prediction</th><th>Phishing score</th><th>Message</th><th>Reason / notes</th></tr></thead><tbody>${rows}</tbody></table></div><p>Predictions are estimates. Review flagged messages manually; the model can make mistakes.</p><button class="primary" id="download-results">Download results CSV ↓</button>`;
    $('download-results').addEventListener('click',()=>{const csv=[['row','message','label','phishing_probability','reasons'],...data.results.map(r=>[r.row,r.message,r.label,r.phishing_probability,r.reasons])].map(row=>row.map(v=>'"'+String(v??'').replace(/"/g,'""')+'"').join(',')).join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));a.download='phishshift_scan_results.csv';a.click();URL.revokeObjectURL(a.href);});return;
  }
  const risk=type==='message'?data.risk:data.risk;
  const title=type==='message'?(data.label==='phishing'?'Potential phishing message':'No strong phishing pattern detected'):data.risk;
  const reasons=data.reasons||[];
  el.innerHTML=`<div class="result-top"><div><h3>${escapeHtml(title)}</h3><p>${type==='message'?`Estimated phishing score: ${data.confidence}%`:`Hostname: ${escapeHtml(data.hostname||'')}`}</p></div><span class="pill ${pillClass(risk)}">${escapeHtml(risk)}</span></div><h4>Why this result?</h4><ul>${reasons.map(r=>`<li>${escapeHtml(r)}</li>`).join('')}</ul><div class="advice"><strong>Recommended next step</strong><br>${escapeHtml(data.advice||'Verify independently before taking action.')}</div>`;
}
async function sendJSON(url,body){const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok&&!data.error)data.error='The scan failed. Please try again.';return data;}
$('scan-message').addEventListener('click',async()=>{const text=$('message-input').value.trim();if(!text){renderResult($('message-result'),{error:'Paste a message or SMS before scanning.'},'message');return;}const b=$('scan-message');b.disabled=true;b.textContent='Analyzing…';try{renderResult($('message-result'),await sendJSON('/api/scan-message',{message:text}),'message');}catch(e){renderResult($('message-result'),{error:'Could not reach the local server. Check that Flask is running.'},'message');}finally{b.disabled=false;b.innerHTML='Analyze message <span>→</span>';}});
$('analyze-url').addEventListener('click',async()=>{const url=$('url-input').value.trim();if(!url){renderResult($('url-result'),{error:'Enter a URL before analyzing.'},'url');return;}const b=$('analyze-url');b.disabled=true;b.textContent='Analyzing…';try{renderResult($('url-result'),await sendJSON('/api/analyze-url',{url}),'url');}catch(e){renderResult($('url-result'),{error:'Could not reach the local server. Check that Flask is running.'},'url');}finally{b.disabled=false;b.innerHTML='Analyze URL <span>→</span>';}});
$('scan-csv').addEventListener('click',async()=>{const file=$('csv-file').files[0];if(!file){renderResult($('csv-result'),{error:'Choose a CSV file first.'},'csv');return;}const b=$('scan-csv');b.disabled=true;b.textContent='Scanning…';try{const form=new FormData();form.append('file',file);const res=await fetch('/api/scan-csv',{method:'POST',body:form});const data=await res.json();renderResult($('csv-result'),data,'csv');}catch(e){renderResult($('csv-result'),{error:'Could not scan this file. Check that the local server is running and the CSV is valid.'},'csv');}finally{b.disabled=false;b.innerHTML='Scan CSV <span>→</span>';}});
