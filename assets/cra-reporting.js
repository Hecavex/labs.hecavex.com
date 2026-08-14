const answers = {};
const questions = [...document.querySelectorAll('[data-question]')];
const awareAt = document.querySelector('#aware-at');
function deadline(hours) { if (!awareAt.value) return null; const date = new Date(awareAt.value); date.setHours(date.getHours()+hours); return date.toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'}); }
function render() {
  const title=document.querySelector('#result-title'),body=document.querySelector('#result-body');
  const unresolved=questions.filter((q)=>!answers[q.dataset.question]).map((q)=>q.dataset.question);
  if(unresolved.length){title.textContent='Classification incomplete';body.innerHTML=`<p>Still unresolved: <strong>${unresolved.join(', ')}</strong>. Preserve the awareness time, evidence and decision log while these questions are answered.</p>`;return;}
  if(answers.role==='no'||answers.market==='no'){title.textContent='Possible scope exclusion';body.innerHTML='<p>One scope answer is “No”. Do not treat this as a final exclusion: document the product, role, market placement and legal basis, then validate with counsel.</p>';return;}
  const tracks=[];
  if(answers.exploitation==='yes') tracks.push('actively exploited vulnerability');
  if(answers.incident==='yes') tracks.push('severe incident');
  const unknown=Object.values(answers).includes('unknown');
  if(!tracks.length){title.textContent=unknown?'Evidence gap requires escalation':'No trigger identified by these answers';body.innerHTML=`<p>${unknown?'At least one trigger question remains unknown. Assign an owner and resolve it urgently.':'These answers do not identify either Article 14 track. Preserve the rationale and reassess when facts change.'}</p>`;return;}
  const due24=deadline(24),due72=deadline(72);
  title.textContent='Prepare for '+tracks.join(' and ');
  body.innerHTML=`<p>This is a preparation signal, not a legal determination.</p><ol><li>Record awareness time and the evidence supporting each classification.</li><li>Prepare the early warning within 24 hours${due24?` (indicative local time: <strong>${due24}</strong>)`:''}.</li><li>Prepare the applicable notification within 72 hours${due72?` (indicative local time: <strong>${due72}</strong>)`:''}.</li><li>Identify the coordinating CSIRT and current ENISA SRP workflow.</li><li>Open the final-report workstream now; its deadline differs by track.</li></ol>${unknown?'<p><strong>Also:</strong> resolve every “Unknown”; it may change the result.</p>':''}`;
}
document.querySelectorAll('.choice').forEach((button)=>button.addEventListener('click',()=>{const question=button.closest('[data-question]');question.querySelectorAll('.choice').forEach((b)=>b.classList.remove('active'));button.classList.add('active');answers[question.dataset.question]=button.dataset.answer;render();}));
awareAt.addEventListener('change',render);
document.querySelector('#reset').addEventListener('click',()=>{Object.keys(answers).forEach((key)=>delete answers[key]);document.querySelectorAll('.choice').forEach((b)=>b.classList.remove('active'));awareAt.value='';render();});
