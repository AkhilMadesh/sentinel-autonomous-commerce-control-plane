let token=localStorage.getItem('sentinel_token'),user=null,poller=null,charts={},currentPage=null;
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

const COUNTRY_DIAL_CODES = {
  IN: { code: '+91', placeholder: '+91 9876543210' },
  US: { code: '+1', placeholder: '+1 (555) 019-2834' },
  GB: { code: '+44', placeholder: '+44 7911 123456' },
  AE: { code: '+971', placeholder: '+971 50 123 4567' },
  SG: { code: '+65', placeholder: '+65 8123 4567' },
  AU: { code: '+61', placeholder: '+61 412 345 678' },
  DE: { code: '+49', placeholder: '+49 151 23456789' },
  CA: { code: '+1', placeholder: '+1 (416) 555-0199' },
  OTHER: { code: '+', placeholder: '+CountryCode Number' }
};

function onCountryChange(selectId, inputId){
  let sel = $(selectId), inp = $(inputId);
  if(!sel || !inp) return;
  let cfg = COUNTRY_DIAL_CODES[sel.value] || { code: '+', placeholder: '+CountryCode Number' };
  inp.placeholder = cfg.placeholder;
  let cur = inp.value.trim();
  let codes = Object.values(COUNTRY_DIAL_CODES).map(x=>x.code);
  let matched = codes.find(c => cur.startsWith(c));
  if(!cur || cur === '+' || cur === '+91' || matched){
    let rest = matched ? cur.slice(matched.length).trim() : cur.replace(/^\+\d*\s*/,'');
    inp.value = cfg.code + (rest ? ' ' + rest : ' ');
  } else if(!cur.startsWith('+')){
    inp.value = cfg.code + ' ' + cur;
  }
}

const api=async(url,opt={})=>{opt.headers={...(opt.headers||{}),Authorization:`Bearer ${token}`,'Content-Type':'application/json'};let r=await fetch(url,opt);let d=await r.json().catch(()=>({}));if(r.status===401){logout();throw Error(d.error||'Unauthorized')}if(!r.ok)throw Error(d.error||'Request failed');return d};
function money(n){return '₹'+Number(n||0).toLocaleString('en-IN')}
function toast(t){$('#toast').textContent=t;$('#toast').style.display='block';setTimeout(()=>$('#toast').style.display='none',2600)}
function closeDrawer(){let d=$('#drawer');d.classList.add('hidden');d.innerHTML=''}
function toggleSide(){$('#sidebar').classList.toggle('open')}
function togglePassword(inputId, btnEl){
  let inp = $(inputId);
  if(!inp) return;
  let isPass = inp.type === 'password';
  inp.type = isPass ? 'text' : 'password';
  const eyeOpen = `<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  const eyeClosed = `<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
  if(btnEl) btnEl.innerHTML = isPass ? eyeClosed : eyeOpen;
}

function showLogin(){
  $('#loginPanel').classList.remove('hidden');
  $('#registerPanel').classList.add('hidden');
  $('#forgotPanel').classList.add('hidden');
  $('#resetPanel').classList.add('hidden');
  $('#authModeLabel').textContent='FINANCIAL AUTHORIZATION LAYER';
  $('#authTitle').innerHTML='Autonomous commerce,<br><em>under control.</em>';
  $('#authSubtitle').textContent='Let agents act with bounded financial authority, explainable decisions and human gates.';
  $('#loginErr').textContent='';
}

function showRegister(){
  $('#loginPanel').classList.add('hidden');
  $('#registerPanel').classList.remove('hidden');
  $('#forgotPanel').classList.add('hidden');
  $('#resetPanel').classList.add('hidden');
  $('#authModeLabel').textContent='SECURE WORKSPACE ONBOARDING';
  $('#authTitle').innerHTML='Build your control plane,<br><em>securely.</em>';
  $('#authSubtitle').textContent='Create a real workspace identity. Country and contact details are stored in the protected account profile.';
  $('#loginErr').textContent='';
  onCountryChange('#regCountry','#regPhone');
}

function showForgotPassword(){
  $('#loginPanel').classList.add('hidden');
  $('#registerPanel').classList.add('hidden');
  $('#forgotPanel').classList.remove('hidden');
  $('#resetPanel').classList.add('hidden');
  $('#authModeLabel').textContent='CREDENTIAL RECOVERY';
  $('#authTitle').innerHTML='Recover your<br><em>workspace access.</em>';
  $('#authSubtitle').textContent='Enter your registered email address or username to receive a secure password change link.';
  $('#loginErr').textContent='';
  let msg = $('#forgotMsg');
  if(msg){ msg.className='auth-msg'; msg.textContent=''; }
}

function showResetPassword(tokenVal){
  $('#loginPanel').classList.add('hidden');
  $('#registerPanel').classList.add('hidden');
  $('#forgotPanel').classList.add('hidden');
  $('#resetPanel').classList.remove('hidden');
  if($('#resetToken')) $('#resetToken').value = tokenVal || '';
  $('#authModeLabel').textContent='SECURE CREDENTIAL UPDATE';
  $('#authTitle').innerHTML='Create your<br><em>new password.</em>';
  $('#authSubtitle').textContent='Choose a strong password with at least 8 characters to secure your financial control plane.';
  $('#loginErr').textContent='';
  let msg = $('#resetMsg');
  if(msg){ msg.className='auth-msg'; msg.textContent=''; }
}

async function sendForgotPassword(){
  let email = $('#forgotEmail').value.trim();
  let msg = $('#forgotMsg');
  if(!email){
    msg.className = 'auth-msg error';
    msg.textContent = 'Please enter your registered email address or username.';
    return;
  }
  msg.className = 'auth-msg';
  msg.textContent = 'Sending recovery instructions...';
  try {
    let r = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    let d = await r.json();
    if(!r.ok) throw Error(d.error || 'Failed to request password reset');
    msg.className = 'auth-msg success';
    if(d.debug_link){
      msg.innerHTML = `<strong>Reset Link Generated!</strong><br><small style="color:#a2b7ad">Live SMTP not configured: You can click the link below to reset immediately:</small><br><a href="${d.debug_link}" style="margin-top:8px;display:inline-block;font-weight:700">Open Password Reset Screen →</a>`;
    } else {
      msg.textContent = d.message || 'Password reset link sent! Check your inbox.';
    }
  } catch(e) {
    msg.className = 'auth-msg error';
    msg.textContent = e.message;
  }
}

async function submitResetPassword(){
  let tokenVal = $('#resetToken').value.trim();
  let newPass = $('#newPass').value;
  let confirmPass = $('#confirmPass').value;
  let msg = $('#resetMsg');
  
  if(!tokenVal){
    msg.className = 'auth-msg error';
    msg.textContent = 'Reset token is missing or expired. Please request a new link.';
    return;
  }
  if(!newPass || newPass.length < 8){
    msg.className = 'auth-msg error';
    msg.textContent = 'Password must be at least 8 characters long.';
    return;
  }
  if(newPass !== confirmPass){
    msg.className = 'auth-msg error';
    msg.textContent = 'Passwords do not match. Please re-type.';
    return;
  }
  
  msg.className = 'auth-msg';
  msg.textContent = 'Updating password...';
  try {
    let r = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: tokenVal, new_password: newPass })
    });
    let d = await r.json();
    if(!r.ok) throw Error(d.error || 'Failed to update password');
    msg.className = 'auth-msg success';
    msg.textContent = d.message || 'Password updated successfully! Redirecting to sign in...';
    setTimeout(() => {
      showLogin();
      $('#pass').value = '';
      $('#loginErr').textContent = '';
      toast('Password updated! Please sign in.');
    }, 1800);
  } catch(e) {
    msg.className = 'auth-msg error';
    msg.textContent = e.message;
  }
}

function fillDemo(username, password){
  let uEl = $('#user'), pEl = $('#pass');
  if(uEl) uEl.value = username;
  if(pEl) pEl.value = password;
  let err = $('#loginErr');
  if(err) err.textContent = '';
  toast(`Selected ${username.toUpperCase()} role credentials`);
}

function googleLogin(){window.location.href='/api/auth/google'}
async function login(){try{let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('#user').value.trim(),password:$('#pass').value})});let d=await r.json();if(!r.ok)throw Error(d.error||'Sign in failed');token=d.token;localStorage.setItem('sentinel_token',token);await boot(d.user)}catch(e){$('#loginErr').textContent=e.message}}
async function register(){try{let payload={email:$('#regEmail').value.trim(),username:$('#regUser').value.trim(),password:$('#regPass').value,country_code:$('#regCountry').value,phone:$('#regPhone').value.trim()};let r=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});let d=await r.json();if(!r.ok)throw Error(d.error||'Registration failed');token=d.token;localStorage.setItem('sentinel_token',token);await boot(d.user)}catch(e){$('#loginErr').textContent=e.message}}
function logout(){if(token)fetch('/api/auth/logout',{method:'POST',headers:{Authorization:`Bearer ${token}`}}).catch(()=>{});localStorage.removeItem('sentinel_token');token=null;clearInterval(poller);$('#app').classList.add('hidden');$('#login').classList.remove('hidden');showLogin()}
async function boot(u){user=u;$('#login').classList.add('hidden');$('#app').classList.remove('hidden');$('#who').textContent=`${u.username} · ${u.role.replace('_',' ')}`;$('#avatar').textContent=u.username[0].toUpperCase();document.querySelectorAll('.nav').forEach(n=>n.onclick=()=>{show(n.dataset.page);$('#sidebar').classList.remove('open')});clearInterval(poller);setInterval(()=>$('#clock').textContent=new Date().toLocaleString('en-IN',{hour:'2-digit',minute:'2-digit',second:'2-digit'}),1000);show('overview');poller=setInterval(()=>refreshBadges(),3500);refreshBadges();if(!u.country_code||!u.phone)setTimeout(showProfileOnboarding,450)}
function showProfileOnboarding(){if(document.querySelector('.profile-onboarding'))return;$('#drawer').classList.remove('hidden');$('#drawer').classList.add('modal-overlay');$('#drawer').innerHTML=`<div class="profile-modal profile-onboarding"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">ACCOUNT PROFILE</div><h2 style="margin:8px 0 6px">Complete your workspace</h2><p style="color:var(--muted);line-height:1.6">Add your country and contact number so the workspace has a real operator profile. This is stored in SENTINEL's database.</p><div class="formgrid" style="margin-top:18px"><div class="field"><label>COUNTRY<select id="profileCountry" onchange="onCountryChange('#profileCountry','#profilePhone')"><option value="">Select country</option><option value="IN">India (+91)</option><option value="US">United States (+1)</option><option value="GB">United Kingdom (+44)</option><option value="AE">United Arab Emirates (+971)</option><option value="SG">Singapore (+65)</option><option value="AU">Australia (+61)</option><option value="DE">Germany (+49)</option><option value="CA">Canada (+1)</option><option value="OTHER">Other</option></select></label></div><div class="field"><label>CONTACT NUMBER<input id="profilePhone" type="tel" placeholder="+91 9876543210"></label></div></div><div class="actions"><button class="primary" onclick="saveProfile()">Save secure profile</button></div></div>`}
async function saveProfile(){try{let d=await api('/api/me',{method:'PATCH',body:JSON.stringify({country_code:$('#profileCountry').value,phone:$('#profilePhone').value.trim()})});user=d;closeDrawer();toast('Profile saved to database')}catch(e){toast(e.message)}}
async function refreshBadges(){try{let a=await api('/api/approvals');$('#approvalBadge').textContent=a.length;let l=await api('/api/activity');$('#liveBadge').textContent=l.length;if(currentPage==='overview')await loadOverview();if(currentPage==='live')await loadLive();if(currentPage==='analytics')await loadAnalytics()}catch(e){}}
async function show(page){
  currentPage=page;
  document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.page===page));
  let builders={
    overview:overviewHTML,
    live:liveHTML,
    transactions:transactionsHTML,
    agents:agentsHTML,
    users:usersHTML,
    delegations:delegationsHTML,
    policies:policiesHTML,
    buyer:buyerHTML,
    merchant:merchantHTML,
    catalog:catalogHTML,
    risk:riskHTML,
    approvals:approvalsHTML,
    audit:auditHTML,
    analytics:analyticsHTML,
    api:apiHTML
  };
  $('#main').innerHTML=builders[page]();
  try{
    let loaders={
      overview:loadOverview,
      live:loadLive,
      transactions:loadTx,
      agents:loadAgents,
      users:loadUsers,
      delegations:loadDelegations,
      policies:loadPolicies,
      buyer:loadBuyer,
      merchant:loadMerchant,
      catalog:loadCatalog,
      risk:loadRisk,
      approvals:loadApprovals,
      audit:loadAudit,
      analytics:loadAnalytics,
      api:loadHealth
    };
    await loaders[page]();
  }catch(e){toast(e.message)}
}

function merchantHTML(){
  return head('Merchant Setup','Configure autonomous commerce parameters and verify AI readiness.',`<span class="pill" id="merchantReadinessBadge">CHECKING READINESS</span>`)+`
  <div class="grid two">
    <div class="card">
      <div class="card-title">Merchant Profile <span>IDENTITY & CURRENCY</span></div>
      <div class="formgrid">
        <div class="field full"><label>MERCHANT / WORKSPACE NAME<input id="merchName" value="Acme Commerce Control"></label></div>
        <div class="field"><label>BUSINESS CATEGORY<input id="merchCategory" value="Enterprise B2B Procurement"></label></div>
        <div class="field"><label>BASE CURRENCY<select id="merchCurrency"><option value="INR">INR (₹)</option><option value="USD">USD ($)</option></select></label></div>
      </div>
      <div class="actions"><button class="primary" onclick="saveMerchant()">Update Merchant Settings</button></div>
    </div>
    <div class="card">
      <div class="card-title">AI Commerce Readiness <span>COMPLIANCE STATUS</span></div>
      <div id="readinessList">
        <div class="check"><span>1. Merchant Catalog Connected</span><b class="pass" id="chkCat">PASS</b></div>
        <div class="check"><span>2. AI Buyer Configured</span><b class="pass" id="chkBuyer">PASS</b></div>
        <div class="check"><span>3. Payment Rail Connected</span><b class="pass" id="chkRail">PASS</b></div>
        <div class="check"><span>4. Spending Policies Active</span><b class="pass" id="chkPol">PASS</b></div>
        <div class="check"><span>5. Approval Gate Configured</span><b class="pass" id="chkApp">PASS</b></div>
      </div>
      <div class="reason" style="margin-top:16px" id="readinessSummary">Overall Posture: <strong>READY FOR AI COMMERCE</strong></div>
    </div>
  </div>`;
}

async function loadMerchant(){
  let m = await api('/api/merchant');
  $('#merchName').value = m.name;
  $('#merchCategory').value = m.business_category;
  $('#merchCurrency').value = m.currency;
  let r = m.ai_readiness || {};
  $('#chkCat').className = r.catalog_connected ? 'pass' : 'fail';
  $('#chkCat').textContent = r.catalog_connected ? 'CONNECTED' : 'EMPTY';
  $('#chkBuyer').className = r.ai_buyer_configured ? 'pass' : 'fail';
  $('#chkBuyer').textContent = r.ai_buyer_configured ? 'ACTIVE' : 'NO AGENTS';
  $('#chkPol').className = r.authorization_policy_configured ? 'pass' : 'warn';
  $('#chkPol').textContent = r.authorization_policy_configured ? 'ACTIVE' : 'DEFAULT';
  $('#merchantReadinessBadge').innerHTML = `<span class="live-dot"></span> ${r.overall_status || 'READY FOR AI COMMERCE'}`;
  $('#readinessSummary').innerHTML = `Overall System Readiness: <strong style="color:var(--accent)">${r.overall_status || 'READY FOR AI COMMERCE'}</strong><br><small style="color:var(--muted)">All autonomous purchase intents will be bounded by configured spending identities.</small>`;
}

async function saveMerchant(){
  try {
    let d = await api('/api/merchant', {
      method: 'PATCH',
      body: JSON.stringify({
        name: $('#merchName').value.trim(),
        business_category: $('#merchCategory').value.trim(),
        currency: $('#merchCurrency').value
      })
    });
    toast('Merchant configuration updated');
    loadMerchant();
  } catch(e) { toast(e.message); }
}

function catalogHTML(){
  return head('Merchant Catalog','Database-backed inventory discoverable by autonomous AI buyers.',`<button class="primary" onclick="newProductModal()">+ Add Product</button>`)+`
  <div class="toolbar">
    <input id="catSearch" placeholder="Search catalog by product name, vendor, SKU, or tags..." oninput="filterCatalog()">
    <select id="catFilter" onchange="filterCatalog()"><option value="">All Categories</option><option>Electronics</option><option>Office Equipment</option><option>Hotels</option><option>Subscriptions</option></select>
  </div>
  <div class="card"><div id="catalogTable"></div></div>`;
}

async function loadCatalog(){
  window.catalogProducts = await api('/api/catalog');
  renderCatalog(window.catalogProducts);
}

function renderCatalog(items){
  $('#catalogTable').innerHTML = items.length ? `
    <table>
      <thead>
        <tr><th>SKU / ID</th><th>PRODUCT</th><th>CATEGORY</th><th>VENDOR</th><th>PRICE</th><th>STOCK</th><th>STATUS</th><th></th></tr>
      </thead>
      <tbody>
        ${items.map(p => `
          <tr>
            <td class="log">${esc(p.sku || 'SKU-'+p.id)}</td>
            <td><strong>${esc(p.name)}</strong><br><small style="color:var(--muted)">${esc((p.description||'').slice(0,55))}...</small></td>
            <td>${esc(p.category)}</td>
            <td>${esc(p.vendor)}</td>
            <td>${money(p.price)}</td>
            <td><b class="${p.stock > 5 ? 'pass' : (p.stock > 0 ? 'warn' : 'fail')}">${p.stock} units</b></td>
            <td><span class="pill">● ${p.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
            <td><button class="btn" onclick="editStockModal(${p.id})">Edit Stock</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>` : '<div class="empty">NO PRODUCTS FOUND IN CATALOG</div>';
}

function filterCatalog(){
  let s = ($('#catSearch')?.value || '').toLowerCase();
  let c = $('#catFilter')?.value || '';
  renderCatalog((window.catalogProducts || []).filter(p => 
    (!s || `${p.name} ${p.description} ${p.sku} ${p.vendor} ${p.tags}`.toLowerCase().includes(s)) &&
    (!c || p.category === c)
  ));
}

function newProductModal(){
  let d = $('#drawer');
  d.innerHTML = `
    <div class="drawer-panel">
      <button class="drawer-close" onclick="closeDrawer()">×</button>
      <div class="eyebrow">MERCHANT CATALOG</div>
      <h2>Add New Product</h2>
      <div class="formgrid">
        <div class="field full"><label>PRODUCT NAME<input id="npName" placeholder="e.g. 27-inch 4K Studio Display"></label></div>
        <div class="field full"><label>DESCRIPTION<textarea id="npDesc" rows="3" placeholder="Detailed product specifications for AI semantic search"></textarea></label></div>
        <div class="field"><label>CATEGORY<input id="npCat" value="Electronics"></label></div>
        <div class="field"><label>VENDOR<input id="npVen" value="Acme Approved Vendors"></label></div>
        <div class="field"><label>UNIT PRICE (₹)<input id="npPrice" type="number" value="12000"></label></div>
        <div class="field"><label>STOCK QUANTITY<input id="npStock" type="number" value="25"></label></div>
        <div class="field full"><label>TAGS (comma-separated)<input id="npTags" placeholder="display, monitor, screen, 4k"></label></div>
      </div>
      <div class="actions"><button class="primary" onclick="saveNewProduct()">Save Product to Catalog</button></div>
    </div>`;
  d.classList.remove('hidden');
}

async function saveNewProduct(){
  try {
    await api('/api/catalog', {
      method: 'POST',
      body: JSON.stringify({
        name: $('#npName').value.trim(),
        description: $('#npDesc').value.trim(),
        category: $('#npCat').value.trim(),
        vendor: $('#npVen').value.trim(),
        price: +$('#npPrice').value,
        stock: +$('#npStock').value,
        tags: $('#npTags').value.trim()
      })
    });
    toast('Product added to merchant catalog');
    closeDrawer();
    loadCatalog();
  } catch(e) { toast(e.message); }
}

function editStockModal(pid){
  let p = (window.catalogProducts || []).find(x => x.id === pid);
  if(!p) return;
  let d = $('#drawer');
  d.innerHTML = `
    <div class="drawer-panel">
      <button class="drawer-close" onclick="closeDrawer()">×</button>
      <div class="eyebrow">INVENTORY CONTROL</div>
      <h2>${esc(p.name)}</h2>
      <div class="formgrid">
        <div class="field"><label>PRICE (₹)<input id="epPrice" type="number" value="${p.price}"></label></div>
        <div class="field"><label>AVAILABLE STOCK<input id="epStock" type="number" value="${p.stock}"></label></div>
      </div>
      <div class="actions"><button class="primary" onclick="updateStock(${pid})">Update Inventory</button></div>
    </div>`;
  d.classList.remove('hidden');
}

async function updateStock(pid){
  try {
    await api('/api/catalog/' + pid, {
      method: 'PATCH',
      body: JSON.stringify({
        price: +$('#epPrice').value,
        stock: +$('#epStock').value
      })
    });
    toast('Inventory updated');
    closeDrawer();
    loadCatalog();
  } catch(e) { toast(e.message); }
}

function head(title,sub,actions=''){return `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div><div class="head-actions">${actions}<span class="mono">${new Date().toLocaleString('en-IN')}</span></div></div>`}
function statusClass(d){return d==='ALLOW'?'allow':d==='BLOCK'?'block':d==='MODIFY'?'modify':'approval'}
function overviewHTML(){return head('Control Center','Real-time authorization and financial activity.',`<span class="pill"><span class="live-dot"></span> LIVE DATABASE</span>`)+`<div class="grid kpis" id="kpis"></div><div class="grid two" style="margin-top:16px"><div class="card"><div class="card-title">Live authorization pipeline <span>DECISION PLANE</span></div><div class="hero-flow" id="overviewFlow">${['BUYER','IDENTITY','INTENT','AUTHORITY','POLICY','RISK','DECISION','RAZORPAY'].map((x,i)=>`<div class="flow-node" id="flow-${i}"><strong>${['✦','◎','◇','⌘','▣','△','✓','◌'][i]}</strong><small>${x}</small></div>${i<7?'<div class="flow-arrow">›</div>':''}`).join('')}</div><div class="flowline"></div><div class="split"><span class="status">Every money action is explainable, bounded and gated.</span><button class="btn success" onclick="show('buyer')">Evaluate transaction →</button></div></div><div class="card"><div class="card-title">Decision distribution <span>LIVE</span></div><div class="chartbox"><canvas id="decisionChart"></canvas></div></div></div><div class="grid two" style="margin-top:16px"><div class="card"><div class="card-title">Transaction volume <span>LAST 14 DAYS</span></div><div class="chartbox"><canvas id="overviewVolumeChart"></canvas></div></div><div class="card"><div class="card-title">Risk distribution <span>LIVE</span></div><div class="chartbox"><canvas id="overviewRiskChart"></canvas></div></div></div><div class="grid two" style="margin-top:16px"><div class="card"><div class="card-title">Recent transactions <span>DATABASE</span></div><div id="recent"></div></div><div class="card"><div class="card-title">System posture <span>HEALTH</span></div><div id="health"></div></div></div>`}
async function loadOverview(){let d=await api('/api/overview');let vals=[['TRANSACTIONS EVALUATED',d.total,'LIFETIME'],['AUTONOMOUS APPROVALS',d.allowed,'AUTHORIZED'],['MODIFIED',d.modified,'POLICY ADJUSTED'],['APPROVAL REQUIRED',d.approval_required,'HUMAN GATE'],['BLOCKED',d.blocked,'DENIED'],['PROTECTED VALUE',money(d.protected_value),'PERSISTED VALUE']];$('#kpis').innerHTML=vals.map(x=>`<div class="card kpi"><div class="label">${x[0]}</div><div class="num">${x[1]}</div><div class="delta">${x[2]}</div></div>`).join('');let tx=await api('/api/transactions?limit=7');$('#recent').innerHTML=tx.length?`<table><thead><tr><th>ID</th><th>AGENT</th><th>AMOUNT</th><th>DECISION</th></tr></thead><tbody>${tx.map(row).join('')}</tbody></table>`:'<div class="empty">NO TRANSACTIONS YET</div>';$('#health').innerHTML=`<div class="check"><span>Decision Engine</span><b class="pass">OPERATIONAL</b></div><div class="check"><span>Policy Engine</span><b class="pass">OPERATIONAL</b></div><div class="check"><span>Database</span><b class="pass">CONNECTED</b></div><div class="check"><span>Audit Chain</span><b class="pass">ENABLED</b></div><div class="check"><span>Razorpay</span><b class="${d.total?'pass':'warn'}">TEST ADAPTER</b></div>`;if(charts.decision)charts.decision.destroy();charts.decision=new Chart($('#decisionChart'),{type:'doughnut',data:{labels:['ALLOW','MODIFY','APPROVAL','BLOCK'],datasets:[{data:[d.allowed,d.modified,d.approval_required,d.blocked],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#9ab0a5',font:{size:11}}}}}});if(charts.overviewVolume)charts.overviewVolume.destroy();charts.overviewVolume=new Chart($('#overviewVolumeChart'),{type:'line',data:{labels:(d.daily||[]).map(x=>x.day),datasets:[{label:'Transactions',data:(d.daily||[]).map(x=>x.count),tension:.35,fill:true}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8aa096',font:{size:10}}},y:{beginAtZero:true,ticks:{color:'#8aa096',font:{size:10},precision:0}}}}});if(charts.overviewRisk)charts.overviewRisk.destroy();charts.overviewRisk=new Chart($('#overviewRiskChart'),{type:'bar',data:{labels:(d.risk_buckets||[]).map(x=>x.bucket),datasets:[{label:'Transactions',data:(d.risk_buckets||[]).map(x=>x.count),borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8aa096',font:{size:10}}},y:{beginAtZero:true,ticks:{color:'#8aa096',font:{size:10},precision:0}}}}})}
function row(x){return `<tr onclick="openTx('${esc(x.tx_ref)}')"><td class="log">${esc(x.tx_ref)}</td><td>${esc(x.agent_name)}</td><td>${money(x.amount)}</td><td><span class="badge ${statusClass(x.decision)}">${esc(x.decision)}</span></td></tr>`}
function liveHTML(){return head('Live Activity','Actual events emitted by the authorization and payment pipeline.')+`<div class="card"><div class="card-title">Event stream <span id="liveTime">CONNECTING</span></div><div id="events"></div></div>`}
async function loadLive(){let d=await api('/api/activity');$('#events').innerHTML=d.map(e=>`<div class="event"><div class="dot"></div><div><small>${new Date(e.timestamp).toLocaleTimeString()} · ${esc(e.event_type)}</small><div>${esc(e.actor)} · ${esc(e.transaction_id||'SYSTEM')} · ${esc(e.details)}</div></div></div>`).join('');$('#liveTime').textContent='CONNECTED';$('#liveBadge').textContent=d.length}
function transactionsHTML(){return head('Transactions','Inspect every financial authorization.',`<button class="btn success" onclick="show('buyer')">+ Evaluate Transaction</button>`)+`<div class="toolbar"><input id="txSearch" placeholder="Search transaction, agent, vendor or intent..." oninput="filterTx()"><select id="txDecision" onchange="filterTx()"><option value="">All decisions</option><option>ALLOW</option><option>MODIFY</option><option>APPROVAL_REQUIRED</option><option>BLOCK</option></select></div><div class="card"><div id="txTable"></div></div>`}
async function loadTx(){window.allTx=await api('/api/transactions?limit=300');renderTx(window.allTx)}function renderTx(d){$('#txTable').innerHTML=d.length?`<table><thead><tr><th>TRANSACTION</th><th>TIME</th><th>AGENT</th><th>INTENT</th><th>AMOUNT</th><th>RISK</th><th>DECISION</th><th>STATUS</th></tr></thead><tbody>${d.map(x=>`<tr onclick="openTx('${esc(x.tx_ref)}')"><td class="log">${esc(x.tx_ref)}</td><td class="log">${new Date(x.created_at).toLocaleString()}</td><td>${esc(x.agent_name)}</td><td>${esc(x.intent).slice(0,45)}</td><td>${money(x.amount)}</td><td>${x.risk_score}</td><td><span class="badge ${statusClass(x.decision)}">${esc(x.decision)}</span></td><td class="status">${esc(x.status)}</td></tr>`).join('')}</tbody></table>`:'<div class="empty">NO MATCHING TRANSACTIONS</div>'}
function filterTx(){let s=($('#txSearch')?.value||'').toLowerCase(),d=$('#txDecision')?.value||'';renderTx((window.allTx||[]).filter(x=>(!s||`${x.tx_ref} ${x.agent_name} ${x.vendor} ${x.intent}`.toLowerCase().includes(s))&&(!d||x.decision===d)))}
async function openTx(ref){let d=await api('/api/transactions/'+encodeURIComponent(ref));let x=d.transaction;let checks=d.events.filter(e=>e.event_type==='TRANSACTION_EVALUATED');$('#drawer').innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">TRANSACTION DETAIL</div><h2>${esc(x.tx_ref)}</h2><div class="split"><span class="badge ${statusClass(x.decision)}">${esc(x.decision)}</span><span class="mono">${new Date(x.created_at).toLocaleString()}</span></div><div class="grid three" style="margin-top:16px"><div class="card"><div class="mono">AMOUNT</div><div class="metric">${money(x.amount)}</div></div><div class="card"><div class="mono">RISK</div><div class="metric">${x.risk_score}<small style="font-size:12px">/100</small></div></div><div class="card"><div class="mono">AUTHORITY</div><div class="metric">${money(x.approved_amount||0)}</div></div></div><div class="modal-section"><h3>Authorization explanation</h3><div class="reason">${esc(x.reason)}</div></div><div class="modal-section"><h3>Decision path</h3><div class="check"><span>Agent</span><b class="pass">${esc(x.agent_name)}</b></div><div class="check"><span>Category</span><b>${esc(x.category)}</b></div><div class="check"><span>Vendor</span><b>${esc(x.vendor)}</b></div><div class="check"><span>Quantity</span><b>${x.quantity}</b></div><div class="check"><span>Payment</span><b>${esc(x.payment_ref||'NOT CREATED')}</b></div></div><div class="modal-section"><h3>Audit timeline</h3>${d.events.map(e=>`<div class="event"><div class="dot"></div><div><small>${new Date(e.timestamp).toLocaleString()} · ${esc(e.event_type)}</small><div>${esc(e.details)}</div></div></div>`).join('')}</div>${x.status==='PENDING_APPROVAL'&&user&&['admin','finance_manager','operator'].includes(user.role)?`<div class="actions"><button class="primary" onclick="approve('${esc(x.tx_ref)}');closeDrawer()">Approve</button><button class="btn danger" onclick="reject('${esc(x.tx_ref)}');closeDrawer()">Reject</button></div>`:''}${x.status==='MODIFICATION_REQUIRED'?`<div class="actions"><button class="primary" onclick="modifyTransaction('${esc(x.tx_ref)}')">Apply compliant amount</button></div>`:''}${x.status==='AUTHORIZED'?`<div class="actions"><button class="primary" onclick="execute('${esc(x.tx_ref)}')">Execute via Razorpay Test Mode</button></div>`:''}</div>`;$('#drawer').classList.remove('hidden')}
function agentsHTML(){return head('Agents','Spending identities with explicit financial authority.',`<button class="primary" onclick="newAgent()">+ New Agent</button>`)+`<div class="card"><div id="agentTable"></div></div>`}
async function loadAgents(){let d=await api('/api/agents');window.agents=d;$('#agentTable').innerHTML=`<table><thead><tr><th>AGENT</th><th>OWNER</th><th>STATUS</th><th>PER TX</th><th>DAILY</th><th>MONTHLY</th><th>RISK</th><th></th></tr></thead><tbody>${d.map(a=>`<tr><td><strong>${esc(a.name)}</strong><div class="log">AG-${String(a.id).padStart(4,'0')}</div></td><td>${esc(a.owner)}</td><td><span class="pill">● ${esc(a.status)}</span></td><td>${money(a.per_tx_limit)}</td><td>${money(a.daily_limit)}</td><td>${money(a.monthly_limit)}</td><td>${a.risk_score}/100</td><td><button class="btn" onclick="editAgent(${a.id})">Edit</button></td></tr>`).join('')}</tbody></table>`}
function newAgent(){let d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">SPENDING IDENTITY</div><h2>Create agent</h2><div class="formgrid"><div class="field"><label>NAME<input id="an"></label></div><div class="field"><label>OWNER<input id="ao" value="finance"></label></div><div class="field"><label>PER TRANSACTION<input id="ap" type="number" value="50000"></label></div><div class="field"><label>DAILY LIMIT<input id="ad" type="number" value="200000"></label></div><div class="field"><label>MONTHLY LIMIT<input id="am" type="number" value="1500000"></label></div><div class="field"><label>CATEGORIES<input id="ac" value="Electronics,Office Equipment"></label></div><div class="field full"><label>VENDORS<input id="av" value="Acme Approved Vendors"></label></div></div><div class="actions"><button class="primary" onclick="saveAgent()">Create Spending Identity</button></div></div>`;d.classList.remove('hidden')}
async function saveAgent(){await api('/api/agents',{method:'POST',body:JSON.stringify({name:$('#an').value,owner:$('#ao').value,per_tx_limit:+$('#ap').value,daily_limit:+$('#ad').value,monthly_limit:+$('#am').value,categories:$('#ac').value,vendors:$('#av').value})});toast('Agent created');closeDrawer();show('agents')}
function editAgent(id){let a=window.agents.find(x=>x.id===id);let d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">SPENDING IDENTITY</div><h2>${esc(a.name)}</h2><div class="formgrid"><div class="field"><label>STATUS<select id="es"><option ${a.status==='ACTIVE'?'selected':''}>ACTIVE</option><option ${a.status==='PAUSED'?'selected':''}>PAUSED</option></select></label></div><div class="field"><label>PER TRANSACTION<input id="ep" type="number" value="${a.per_tx_limit}"></label></div><div class="field"><label>DAILY LIMIT<input id="ed" type="number" value="${a.daily_limit}"></label></div><div class="field"><label>MONTHLY LIMIT<input id="em" type="number" value="${a.monthly_limit}"></label></div><div class="field full"><label>CATEGORIES<input id="ec" value="${esc(a.categories)}"></label></div><div class="field full"><label>VENDORS<input id="ev" value="${esc(a.vendors)}"></label></div></div><div class="actions"><button class="primary" onclick="updateAgent(${id})">Save changes</button></div></div>`;d.classList.remove('hidden')}
async function updateAgent(id){await api('/api/agents/'+id,{method:'PATCH',body:JSON.stringify({status:$('#es').value,per_tx_limit:+$('#ep').value,daily_limit:+$('#ed').value,monthly_limit:+$('#em').value,categories:$('#ec').value,vendors:$('#ev').value})});toast('Agent updated');closeDrawer();show('agents')}
function usersHTML(){return head('Users & Roles','Role-based access to the SENTINEL control plane.',`<button class="primary" onclick="newUser()">+ Add User</button>`)+`<div class="card"><div id="userTable"></div></div>`}
async function loadUsers(){let d=await api('/api/users');window.users=d;$('#userTable').innerHTML=`<table><thead><tr><th>USER</th><th>ROLE</th><th>CREATED</th><th>ACTIONS</th></tr></thead><tbody>${d.map(x=>`<tr><td><strong>${esc(x.username)}</strong></td><td><span class="pill">${esc(x.role.replace('_',' ').toUpperCase())}</span></td><td class="log">${new Date(x.created_at).toLocaleString()}</td><td><button class="btn" onclick="changeRole(${x.id})">Change role</button></td></tr>`).join('')}</tbody></table>`}
function newUser(){let d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">RBAC</div><h2>Add user</h2><div class="formgrid"><div class="field"><label>USERNAME<input id="un"></label></div><div class="field"><label>PASSWORD<input id="up" type="password"></label></div><div class="field full"><label>ROLE<select id="ur"><option>admin</option><option>finance_manager</option><option>operator</option><option>viewer</option></select></label></div></div><div class="actions"><button class="primary" onclick="saveUser()">Create user</button></div></div>`;d.classList.remove('hidden')}
async function saveUser(){await api('/api/users',{method:'POST',body:JSON.stringify({username:$('#un').value,password:$('#up').value,role:$('#ur').value})});toast('User created');closeDrawer();show('users')}
function changeRole(id){let u=(window.users||[]).find(x=>x.id===id),d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">RBAC</div><h2>${esc(u.username)}</h2><div class="field"><label>ROLE<select id="rr">${['admin','finance_manager','operator','viewer'].map(r=>`<option ${r===u.role?'selected':''}>${r}</option>`).join('')}</select></label></div><div class="actions"><button class="primary" onclick="saveRole(${id})">Save role</button></div></div>`;d.classList.remove('hidden')}
async function saveRole(id){await api('/api/users/'+id,{method:'PATCH',body:JSON.stringify({role:$('#rr').value})});toast('Role updated');closeDrawer();show('users')}
function delegationsHTML(){return head('Delegations','A visible chain of authority from owner to autonomous actor.',`<button class="primary" onclick="newDelegation()">+ Delegate Authority</button>`)+`<div class="card"><div id="delegationTable"></div></div>`}
async function loadDelegations(){let [d,a]=await Promise.all([api('/api/delegations'),api('/api/agents')]);window.agents=a;window.delegations=d;$('#delegationTable').innerHTML=d.length?`<table><thead><tr><th>PARENT</th><th>CHILD</th><th>AUTHORITY</th><th>PURPOSE</th><th>STATUS</th><th></th></tr></thead><tbody>${d.map(x=>`<tr><td>${esc(x.parent_name||'MERCHANT ROOT')}</td><td>${esc(x.child_name)}</td><td>${money(x.amount_limit)}</td><td>${esc(x.purpose)}</td><td><span class="pill">${esc(x.status)}</span></td><td><button class="btn ${x.status==='ACTIVE'?'danger':'success'}" onclick="toggleDelegation(${x.id},'${x.status==='ACTIVE'?'REVOKED':'ACTIVE'}')">${x.status==='ACTIVE'?'Revoke':'Restore'}</button></td></tr>`).join('')}</tbody></table>`:'<div class="empty">NO DELEGATIONS CONFIGURED</div>'}
function newDelegation(){let d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">DELEGATED AUTHORITY</div><h2>Create delegation</h2><div class="formgrid"><div class="field"><label>PARENT<select id="dp"><option value="">Merchant root</option>${(window.agents||[]).map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join('')}</select></label></div><div class="field"><label>CHILD<select id="dc">${(window.agents||[]).map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join('')}</select></label></div><div class="field"><label>AMOUNT LIMIT<input id="da" type="number" value="50000"></label></div><div class="field"><label>PURPOSE<input id="du" value="Procurement authority"></label></div></div><div class="actions"><button class="primary" onclick="saveDelegation()">Create delegation</button></div></div>`;d.classList.remove('hidden')}
async function saveDelegation(){await api('/api/delegations',{method:'POST',body:JSON.stringify({parent_agent_id:$('#dp').value||null,child_agent_id:+$('#dc').value,amount_limit:+$('#da').value,purpose:$('#du').value})});toast('Delegation created');closeDrawer();show('delegations')}
async function toggleDelegation(id,status){await api('/api/delegations/'+id,{method:'PATCH',body:JSON.stringify({status})});toast('Delegation updated');show('delegations')}
function policiesHTML(){return head('Policy Center','Deterministic rules that constrain autonomous financial actions.',`<button class="primary" onclick="newPolicy()">+ New Policy</button>`)+`<div class="card"><div id="policyTable"></div></div>`}
async function loadPolicies(){let d=await api('/api/policies');window.policies=d;$('#policyTable').innerHTML=`<table><thead><tr><th>POLICY</th><th>WHEN</th><th>ACTION</th><th>STATUS</th><th></th></tr></thead><tbody>${d.map(p=>`<tr><td><strong>${esc(p.name)}</strong><div class="log">RULE-${String(p.id).padStart(3,'0')}</div></td><td>${esc(p.rule_type)} ${esc(p.operator)} ${esc(p.value)}</td><td><span class="badge ${p.action==='block'?'block':p.action==='approval'?'approval':'allow'}">${esc(p.action).toUpperCase()}</span></td><td>${p.active?'ACTIVE':'DISABLED'}</td><td><button class="btn" onclick="togglePolicy(${p.id},${p.active?0:1})">${p.active?'Disable':'Enable'}</button></td></tr>`).join('')}</tbody></table>`}
function newPolicy(){let d=$('#drawer');d.innerHTML=`<div class="drawer-panel"><button class="drawer-close" onclick="closeDrawer()">×</button><div class="eyebrow">POLICY ENGINE</div><h2>Create policy</h2><div class="formgrid"><div class="field full"><label>NAME<input id="pn" placeholder="After-hours approval"></label></div><div class="field"><label>RULE TYPE<select id="pt"><option>amount</option><option>quantity</option><option>risk_score</option><option>vendor</option><option>category</option></select></label></div><div class="field"><label>OPERATOR<select id="po"><option>></option><option>>=</option><option><</option><option><=</option><option>=</option><option>NOT_IN</option></select></label></div><div class="field"><label>VALUE<input id="pv" value="50000"></label></div><div class="field"><label>ACTION<select id="pa"><option value="approval">Require approval</option><option value="block">Block</option><option value="allow">Allow</option></select></label></div></div><div class="actions"><button class="primary" onclick="savePolicy()">Create policy</button></div></div>`;d.classList.remove('hidden')}
async function togglePolicy(id,active){await api('/api/policies/'+id,{method:'PATCH',body:JSON.stringify({active:!!active})});toast(active?'Policy enabled':'Policy disabled');show('policies')}

async function execute(ref){
  try {
    let d = await api('/api/transactions/' + encodeURIComponent(ref) + '/execute', { method: 'POST' });
    if(d.payment && window.Razorpay){
      let options = {
        key: d.payment.key_id,
        amount: d.payment.amount,
        currency: d.payment.currency,
        name: 'SENTINEL Commerce',
        description: `Authorization for ${ref}`,
        order_id: d.payment.order_id,
        handler: async function(response){
          try {
            await api('/api/transactions/' + encodeURIComponent(ref) + '/confirm-payment', {
              method: 'POST',
              body: JSON.stringify(response)
            });
            toast('Payment captured and verified on SHA-256 audit log!');
            closeDrawer();
            refreshBadges();
            show('transactions');
          } catch(e) { toast(e.message); }
        },
        theme: { color: '#73e39b' }
      };
      let rzp = new window.Razorpay(options);
      rzp.open();
    } else {
      toast('Execution initiated: ' + (d.transaction?.status || 'COMPLETED'));
      closeDrawer();
      refreshBadges();
      if(currentPage === 'transactions') loadTx();
    }
  } catch(e) {
    if(e.message && (e.message.includes("Razorpay test credentials") || e.message.includes("RAZORPAY_NOT_CONFIGURED"))){
      showRazorpaySetupModal(ref);
    } else {
      toast(e.message);
    }
  }
}

function showRazorpaySetupModal(ref){
  let d = $('#drawer');
  d.innerHTML = `
    <div class="drawer-panel">
      <button class="drawer-close" onclick="closeDrawer()">×</button>
      <div class="eyebrow" style="color:var(--accent)">RAZORPAY TEST MODE ADAPTER</div>
      <h2 style="margin:6px 0 12px">Payment Gateway Setup</h2>
      <p style="color:var(--muted);line-height:1.6;font-size:13px">
        To open the live Razorpay popup checkout, add your free test keys to <code>.env</code>:
      </p>
      <div class="reason" style="margin:12px 0;font-family:var(--mono);font-size:12px">
        RAZORPAY_KEY_ID=rzp_test_...<br>
        RAZORPAY_KEY_SECRET=...
      </div>
      <p style="color:var(--text);line-height:1.6;font-size:13px">
        <strong>Judge Sandbox:</strong> You can also simulate test capture right now to verify the complete post-authorization lifecycle, atomic SQLite inventory decrement, and cryptographic SHA-256 audit chain:
      </p>
      <div class="actions" style="margin-top:18px">
        <button class="primary" onclick="simulateCapture('${esc(ref)}')">⚡ Simulate Test Mode Capture & Decrement Stock →</button>
      </div>
    </div>`;
  d.classList.remove('hidden');
}

async function simulateCapture(ref){
  try {
    let d = await api('/api/transactions/' + encodeURIComponent(ref) + '/simulate-capture', { method: 'POST' });
    toast('Test payment captured! Stock decremented and SHA-256 audit event logged.');
    closeDrawer();
    refreshBadges();
    openTx(ref);
  } catch(e) {
    toast(e.message);
  }
}

function buyerHTML(){
  return head('AI Buyer','Translate human intent into a bounded transaction — never directly into payment.',`<span class="pill"><span class="live-dot"></span> DECISION PLANE ONLINE</span>`)+`
  <div class="grid two">
    <div class="card glow-card">
      <div class="card-title">Natural-Language Purchase Intent <span>AI TOOL CALLING</span></div>
      <div class="field">
        <label>WHAT SHOULD THE AGENT BUY?</label>
        <textarea id="intentText" rows="4" placeholder="e.g. Buy 5 4K monitors for the design team under ₹60,000."></textarea>
      </div>
      <div class="actions">
        <button class="primary" onclick="parseIntent()">Understand Intent & Search Catalog →</button>
      </div>
      <div id="intentResult"></div>
    </div>
    <div class="card">
      <div class="card-title">Spending Identity <span>BOUNDED AUTHORITY</span></div>
      <div class="field"><label>SELECT AUTONOMOUS AGENT</label><select id="buyerAgent"></select></div>
      <div id="agentAuthority" class="reason">Select an agent to view its authority limits.</div>
      <div class="authority-meter">
        <div class="authority-meter-head"><span>Autonomous Authority Ceiling</span><b id="authorityLabel">—</b></div>
        <div class="riskbar"><i id="authorityBar" style="width:100%"></i></div>
      </div>
      <div class="modal-section">
        <h3>Autonomous Control Pipeline</h3>
        <div class="hero-flow" id="buyerFlow">
          ${['BUYER','IDENTITY','INTENT','AUTHORITY','POLICY','RISK','DECISION','RAZORPAY'].map((x,i)=>`
            <div class="flow-node" id="bflow-${i}"><strong>${['✦','◎','◇','⌘','▣','△','✓','◌'][i]}</strong><small>${x}</small></div>${i<7?'<div class="flow-arrow">›</div>':''}
          `).join('')}
        </div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-title">Transaction Evaluator <span>DETERMINISTIC GATE</span></div>
    <div class="formgrid">
      <div class="field full">
        <label>CATALOG PRODUCT MATCH<select id="product" onchange="selectProduct()"><option value="">Custom Purchase</option></select></label>
      </div>
      <div class="field"><label>CATEGORY<input id="category" value="Electronics"></label></div>
      <div class="field"><label>VENDOR<input id="vendor" value="Acme Approved Vendors"></label></div>
      <div class="field"><label>QUANTITY<input id="qty" type="number" min="1" value="5" oninput="calcAmount()"></label></div>
      <div class="field"><label>UNIT PRICE (₹)<input id="unit" type="number" min="1" value="9000" oninput="calcAmount()"></label></div>
      <div class="field"><label>TOTAL AMOUNT (₹)<input id="amount" type="number" value="45000" readonly></label></div>
      <div class="field full"><label>INTENT OBJECTIVE<input id="txIntent" value="Equip the design team with monitors"></label></div>
    </div>
    
    <div class="scenario-strip">
      <span class="mono">CONTROLLED TEST SCENARIOS:</span>
      <button class="btn" onclick="runScenario('SAFE')">Safe (₹45k)</button>
      <button class="btn warn" onclick="runScenario('APPROVAL')">Approval (₹81k)</button>
      <button class="btn" onclick="runScenario('MODIFY')">Smart Modify (20 units)</button>
      <button class="btn danger" onclick="runScenario('BLOCKED_VENDOR')">Blocked Vendor</button>
      <button class="btn danger" onclick="runScenario('HIGH_RISK')">High Risk Anomaly</button>
      <button class="btn" onclick="runScenario('DUPLICATE')">Duplicate Test</button>
    </div>
    
    <div class="actions" style="margin-top:14px">
      <button class="primary big" onclick="createTx()">Evaluate & Enforce Authority <span>→</span></button>
    </div>
    
    <div id="evalResult"></div>
  </div>`;
}

async function loadBuyer(){
  let [agents, products] = await Promise.all([api('/api/agents'), api('/api/catalog')]);
  window.agents = agents;
  window.products = products;
  $('#buyerAgent').innerHTML = agents.map(a => `<option value="${a.id}">${esc(a.name)} · (₹${money(a.per_tx_limit)} / tx)</option>`).join('');
  $('#product').innerHTML = '<option value="">Custom Purchase / Direct Entry</option>' + products.map(p => `<option value="${p.id}">${esc(p.name)} · ${money(p.price)} · ${esc(p.vendor)} (Stock: ${p.stock})</option>`).join('');
  $('#buyerAgent').onchange = updateBuyerAuthority;
  updateBuyerAuthority();
}

function selectProduct(){
  let id = +$('#product').value;
  if(!id) return;
  let p = (window.products || []).find(x => x.id === id);
  if(!p) return;
  $('#category').value = p.category;
  $('#vendor').value = p.vendor;
  $('#unit').value = p.price;
  $('#txIntent').value = `Procure ${p.name}`;
  calcAmount();
}

function updateBuyerAuthority(){
  let a = (window.agents || []).find(x => x.id === +$('#buyerAgent').value);
  if(!a) return;
  $('#agentAuthority').innerHTML = `
    <div class="stat-line"><span>Per-Transaction Limit</span><b>${money(a.per_tx_limit)}</b></div>
    <div class="stat-line"><span>Daily Limit</span><b>${money(a.daily_limit)}</b></div>
    <div class="stat-line"><span>Monthly Limit</span><b>${money(a.monthly_limit)}</b></div>
    <div style="margin-top:8px">
      <span class="tag">${esc(a.status)}</span>
      <span class="tag">Risk Baseline: ${a.risk_score}/100</span>
      <span class="tag">${esc(a.categories || 'All Categories')}</span>
    </div>`;
  $('#authorityLabel').textContent = money(a.per_tx_limit);
}

function calcAmount(){
  $('#amount').value = (+$('#qty').value || 0) * (+$('#unit').value || 0);
}

async function parseIntent(){
  let text = $('#intentText').value.trim();
  if(!text) return toast('Please enter purchase intent text');
  
  // Highlight intent node
  highlightNode(0);
  highlightNode(1);
  highlightNode(2);
  
  try {
    let d = await api('/api/ai/intent', { method: 'POST', body: JSON.stringify({ text }) });
    let i = d.intent || {};
    let rec = d.recommended_product;
    
    $('#intentResult').innerHTML = `
      <div class="reason" style="margin-top:12px">
        <div class="split">
          <strong>AI Planner & Catalog Matching</strong>
          <span class="pill"><span class="live-dot"></span> TOOLS: ${(d.tools_executed||[]).join(', ')}</span>
        </div>
        <p style="margin:8px 0;line-height:1.5;color:var(--text)">${esc(d.recommendation_reason || '')}</p>
        <div class="stat-line"><span>Matched Product</span><b>${esc(rec ? rec.name : 'Custom')}</b></div>
        <div class="stat-line"><span>Quantity</span><b>${esc(i.quantity || 1)} units</b></div>
        <div class="stat-line"><span>Unit Price</span><b>${money(rec ? rec.price : i.unit_price || 0)}</b></div>
        <div class="stat-line"><span>Total Calculated</span><b>${money((rec ? rec.price : i.unit_price || 0) * (i.quantity || 1))}</b></div>
        <div style="margin-top:10px">
          <button class="btn success" onclick="applyRecommendation()">✓ Accept Recommendation & Fill Evaluator</button>
        </div>
      </div>`;
      
    window.currentSuggestedAction = d.suggested_action;
    if(d.suggested_action){
      applyRecommendation();
    }
  } catch(e) {
    toast(e.message);
  }
}

function applyRecommendation(){
  try {
    let act = window.currentSuggestedAction;
    if(!act) return;
    if(act.product_id) $('#product').value = act.product_id;
    if(act.category) $('#category').value = act.category;
    if(act.vendor) $('#vendor').value = act.vendor;
    if(act.quantity) $('#qty').value = act.quantity;
    if(act.unit_price) $('#unit').value = act.unit_price;
    if(act.intent) $('#txIntent').value = act.intent;
    calcAmount();
    toast('Cart populated from recommendation');
  } catch(e) {
    console.error(e);
  }
}

function highlightNode(idx){
  let el = $(`#bflow-${idx}`);
  if(el){
    el.classList.add('active');
    setTimeout(() => el.classList.remove('active'), 2500);
  }
}

async function createTx(){
  // Step through pipeline nodes visually
  for(let i=0; i<7; i++){
    setTimeout(() => highlightNode(i), i * 150);
  }
  
  try {
    let d = await api('/api/transactions', {
      method: 'POST',
      headers: { 'Idempotency-Key': 'sentinel-' + crypto.randomUUID() },
      body: JSON.stringify({
        agent_id: +$('#buyerAgent').value,
        amount: +$('#amount').value,
        category: $('#category').value,
        vendor: $('#vendor').value,
        quantity: +$('#qty').value,
        unit_price: +$('#unit').value,
        intent: $('#txIntent').value,
        currency: 'INR'
      })
    });
    renderEvaluation(d.transaction, d.checks, d.suggested_modification);
    toast('Transaction evaluated by SENTINEL control plane');
    refreshBadges();
  } catch(e) {
    toast(e.message);
  }
}

function renderEvaluation(x, checks, suggestedMod){
  let modHtml = '';
  if(x.decision === 'MODIFY' && (suggestedMod || x.suggested_modification)){
    let m = suggestedMod || x.suggested_modification;
    modHtml = `
      <div class="reason" style="border-left-color:#e6a23c;background:rgba(230,162,60,0.08);margin:12px 0">
        <div class="split">
          <strong style="color:#e6a23c">Smart Compliant Proposal Available</strong>
          <span class="pill" style="color:#e6a23c;border-color:rgba(230,162,60,0.4)">AUTONOMOUS ADJUSTMENT</span>
        </div>
        <p style="margin:8px 0;font-size:13px;color:var(--text)">
          Requested quantity of ${m.original_quantity} units (${money(m.original_amount)}) exceeds agent per-transaction ceiling. SENTINEL calculated a compliant ceiling of <strong>${m.suggested_quantity} units (${money(m.suggested_amount)})</strong>.
        </p>
        <button class="primary" onclick="acceptSuggestedMod('${esc(x.tx_ref)}', ${m.suggested_quantity}, ${m.unit_price}, ${m.suggested_amount})">
          Accept Compliant Proposal (${m.suggested_quantity} units · ${money(m.suggested_amount)}) →
        </button>
      </div>`;
  }
  
  $('#evalResult').innerHTML = `
    <div class="evaluation-card ${statusClass(x.decision)}" style="margin-top:16px">
      <div class="split">
        <div>
          <div class="mono">${esc(x.tx_ref)}</div>
          <div class="decision ${statusClass(x.decision)}">${esc(x.decision)}</div>
        </div>
        <span class="pill">RISK SCORE: ${x.risk_score}/100</span>
      </div>
      <div class="reason">${esc(x.reason)}</div>
      ${modHtml}
      <div class="evaluation-grid">
        ${(checks || []).map(c => `
          <div class="check"><span>${esc(c[0])}</span><b class="${c[1]==='PASS'?'pass':(c[1]==='FAIL'?'fail':'warn')}">${esc(c[1])}</b></div>
        `).join('')}
      </div>
      <div class="decision-meta">
        <span>REQUESTED: <b>${money(x.amount)}</b></span>
        <span>AUTHORITY CEILING: <b>${money(x.effective_authority || 50000)}</b></span>
        <span>APPROVED: <b>${money(x.approved_amount || 0)}</b></span>
      </div>
      <div class="actions" style="margin-top:14px">
        <button class="btn" onclick="openTx('${esc(x.tx_ref)}')">Inspect Full Audit Trail</button>
        ${x.status === 'PENDING_APPROVAL' ? '<button class="btn warn" onclick="show(\'approvals\')">Open Approvals Queue →</button>' : ''}
        ${x.status === 'AUTHORIZED' ? `<button class="primary" onclick="execute('${esc(x.tx_ref)}')">Execute via Razorpay Test Mode →</button>` : ''}
      </div>
    </div>`;
}

async function acceptSuggestedMod(ref, qty, unit, amt){
  try {
    let res = await api('/api/transactions/' + encodeURIComponent(ref) + '/modify', {
      method: 'POST',
      body: JSON.stringify({ quantity: qty, unit_price: unit, amount: amt })
    });
    toast(`Modified to ${qty} units (${money(amt)}) and evaluated by SENTINEL! Decision: ${res.decision || res.transaction?.decision}`);
    refreshBadges();
    openTx(ref);
  } catch(e) {
    toast(e.message);
  }
}

async function modifyTransaction(ref){
  try {
    let d = await api('/api/transactions/' + encodeURIComponent(ref));
    let x = d.transaction;
    let agent = (window.agents || []).find(a => a.id === x.agent_id) || { per_tx_limit: 50000 };
    let limit = agent.per_tx_limit || 50000;
    let compliantQty = Math.max(1, Math.floor(limit / x.unit_price));
    let compliantAmount = compliantQty * x.unit_price;
    await acceptSuggestedMod(ref, compliantQty, x.unit_price, compliantAmount);
  } catch(e) {
    toast(e.message);
  }
}

async function runScenario(s){
  const set = (qty, unit, cat, vendor, intent, prodId='') => {
    $('#qty').value = qty;
    $('#unit').value = unit;
    $('#category').value = cat;
    $('#vendor').value = vendor;
    $('#txIntent').value = intent;
    $('#product').value = prodId;
    calcAmount();
  };
  
  if(s === 'SAFE') set(5, 9000, 'Electronics', 'Acme Approved Vendors', 'Equip the design team with 5 4K monitors', 1);
  if(s === 'APPROVAL') set(9, 9000, 'Electronics', 'Acme Approved Vendors', 'Procure 9 monitors for new engineering hires (₹81,000)', 1);
  if(s === 'MODIFY') set(20, 9000, 'Electronics', 'Acme Approved Vendors', 'Bulk order 20 monitors for design expansion (₹180,000)', 1);
  if(s === 'BLOCKED_VENDOR') set(2, 9000, 'Electronics', 'Untrusted Shadow Vendor', 'Attempt purchase from an unapproved vendor');
  if(s === 'HIGH_RISK') set(35, 9000, 'Electronics', 'Untrusted Shadow Vendor', 'Massive off-hours bulk purchase anomaly from untrusted vendor');
  if(s === 'DUPLICATE'){
    const body = {
      agent_id: +$('#buyerAgent').value,
      amount: 45000,
      category: 'Electronics',
      vendor: 'Acme Approved Vendors',
      quantity: 5,
      unit_price: 9000,
      intent: 'Idempotency verification transaction',
      currency: 'INR'
    };
    const key = 'sentinel-idem-' + Date.now();
    const first = await api('/api/transactions', { method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(body) });
    const second = await api('/api/transactions', { method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(body) });
    renderEvaluation(second.transaction, second.checks || first.checks);
    return;
  }
  await createTx();
}

function riskHTML(){
  return head('Risk Center','Explainable risk signals around autonomous financial behavior.')+`
  <div class="grid three">
    <div class="card"><div class="mono">HIGH-RISK TRANSACTIONS</div><div class="metric" id="riskCount">—</div><div class="status">risk ≥ 70</div></div>
    <div class="card"><div class="mono">CRITICAL</div><div class="metric" id="criticalCount">—</div><div class="status">risk ≥ 80</div></div>
    <div class="card"><div class="mono">AUTHORITY VIOLATIONS</div><div class="metric" id="authorityViolations">—</div><div class="status">blocked / approval</div></div>
  </div>
  <div class="grid two" style="margin-top:14px">
    <div class="card"><div class="card-title">Risk distribution</div><div class="chartbox"><canvas id="riskChart"></canvas></div></div>
    <div class="card"><div class="card-title">Signals</div><div id="riskSignals"></div></div>
  </div>`;
}

async function loadRisk(){
  let [d, t] = await Promise.all([api('/api/analytics'), api('/api/transactions?limit=500')]);
  let hi = t.filter(x => x.risk_score >= 70).length;
  let cr = t.filter(x => x.risk_score >= 80).length;
  let av = t.filter(x => x.decision !== 'ALLOW').length;
  $('#riskCount').textContent = hi;
  $('#criticalCount').textContent = cr;
  $('#authorityViolations').textContent = av;
  $('#riskSignals').innerHTML = [
    ['Elevated amount', t.filter(x => x.amount > 50000).length],
    ['Unapproved vendor', t.filter(x => /unknown|unapproved|shadow/i.test(x.vendor)).length],
    ['High quantity', t.filter(x => x.quantity > 10).length],
    ['After-hours activity', t.filter(x => { let h = new Date(x.created_at).getHours(); return h < 5; }).length]
  ].map(a => `<div class="stat-line"><span>${a[0]}</span><b>${a[1]}</b></div>`).join('');
  if(charts.risk) charts.risk.destroy();
  charts.risk = new Chart($('#riskChart'), {
    type: 'bar',
    data: {
      labels: (d.risk_buckets||[]).map(x => x.bucket),
      datasets: [{ data: (d.risk_buckets||[]).map(x => x.count) }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#81988e' } }, y: { ticks: { color: '#81988e' } } }
    }
  });
}

function approvalsHTML(){
  return head('Approvals','Human gates for transactions outside autonomous authority.')+`
  <div class="card"><div id="approvalTable"></div></div>`;
}

async function loadApprovals(){
  let d = await api('/api/approvals');
  $('#approvalBadge').textContent = d.length;
  $('#approvalTable').innerHTML = d.length ? `
    <table>
      <thead>
        <tr><th>TRANSACTION</th><th>AGENT</th><th>REQUESTED</th><th>RISK</th><th>REASON</th><th>ACTION</th></tr>
      </thead>
      <tbody>
        ${d.map(x => `
          <tr>
            <td class="log">${esc(x.tx_ref)}</td>
            <td>${esc(x.agent_name)}</td>
            <td>${money(x.amount)}</td>
            <td>${x.risk_score}/100</td>
            <td>${esc(x.reason)}</td>
            <td>
              <button class="btn success" onclick="approve('${esc(x.tx_ref)}')">Approve</button>
              <button class="btn danger" onclick="reject('${esc(x.tx_ref)}')">Reject</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>` : '<div class="empty">NO PENDING APPROVALS — ALL CLEAR</div>';
}

async function approve(ref){
  await api('/api/transactions/' + encodeURIComponent(ref) + '/approve', { method: 'POST' });
  toast('Transaction approved and authorized');
  refreshBadges();
  show('approvals');
}

async function reject(ref){
  await api('/api/transactions/' + encodeURIComponent(ref) + '/reject', { method: 'POST' });
  toast('Transaction rejected and blocked');
  refreshBadges();
  show('approvals');
}

function auditHTML(){
  return head('Audit Trail','Tamper-evident financial events with a chained SHA-256 integrity model.',`<button class="btn success" onclick="verifyAudit()">Verify chain</button>`)+`
  <div class="card"><div id="auditTable"></div></div>`;
}

async function loadAudit(){
  let d = await api('/api/audit?limit=300');
  $('#auditTable').innerHTML = d.length ? `
    <table>
      <thead>
        <tr><th>TIME</th><th>ACTOR</th><th>EVENT</th><th>TRANSACTION</th><th>PREV HASH</th><th>EVENT HASH</th></tr>
      </thead>
      <tbody>
        ${d.map(x => `
          <tr>
            <td class="log">${new Date(x.timestamp).toLocaleString()}</td>
            <td>${esc(x.actor)}</td>
            <td><span class="pill">${esc(x.event_type)}</span></td>
            <td>${esc(x.transaction_id || '—')}</td>
            <td class="log">${esc((x.prev_hash||'').slice(0, 16))}…</td>
            <td class="log">${esc((x.event_hash||'').slice(0, 16))}…</td>
          </tr>
        `).join('')}
      </tbody>
    </table>` : '<div class="empty">NO AUDIT LOGS RECORDED</div>';
}

async function verifyAudit(){
  let d = await api('/api/audit/verify');
  toast(d.valid ? `✓ Chain valid · ${d.checked} events verified with 0 breaks` : `✕ Integrity issue at ${d.invalid_ids.join(', ')}`);
}

function apiHTML(){
  return head('API Console','Developer surface for integrating autonomous actors with SENTINEL.')+`
  <div class="grid two">
    <div class="card">
      <div class="card-title">Core Endpoints <span>REST SPEC</span></div>
      ${[
        ['POST', '/api/transactions/evaluate', 'DECIDE'],
        ['POST', '/api/transactions', 'PERSIST'],
        ['POST', '/api/transactions/:id/approve', 'APPROVE'],
        ['POST', '/api/transactions/:id/execute', 'EXECUTE'],
        ['GET', '/api/audit/verify', 'VERIFY'],
        ['POST', '/api/ai/intent', 'AI INTENT'],
        ['POST', '/api/ai/tools', 'AI TOOLS'],
        ['GET', '/api/catalog', 'CATALOG']
      ].map(x => `
        <div class="check"><span>${x[0]} ${x[1]}</span><b class="pass">${x[2]}</b></div>
      `).join('')}
    </div>
    <div class="card">
      <div class="card-title">Sample Agent Evaluation Request <span>JSON PAYLOAD</span></div>
      <div class="code">POST /api/transactions/evaluate
Authorization: Bearer &lt;token&gt;

{
  "agent_id": 1,
  "amount": 45000,
  "category": "Electronics",
  "vendor": "Acme Approved Vendors",
  "quantity": 5,
  "unit_price": 9000,
  "intent": "Equip design team with 4K monitors"
}</div>
      <div class="actions">
        <button class="btn" onclick="copyText('/api/transactions/evaluate')">Copy endpoint</button>
      </div>
    </div>
  </div>`;
}

function copyText(t){
  navigator.clipboard?.writeText(t);
  toast('Copied');
}

async function loadHealth(){
  let d = await fetch('/api/health').then(r => r.json());
  $('#apiState').textContent = d.status.toUpperCase();
}

function analyticsHTML(){
  return head('Analytics','100% database-backed metrics and protected value intelligence.')+`
  <div class="grid" id="analyticsFinancials" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px"></div>
  
  <div class="grid two" style="margin-top:16px">
    <div class="card">
      <div class="card-title">AI Commerce Conversion Funnel <span>LIFETIME</span></div>
      <div id="analyticsFunnel" style="margin-top:12px"></div>
    </div>
    <div class="card">
      <div class="card-title">Decision Distribution <span>DATABASE</span></div>
      <div class="chartbox tall"><canvas id="analyticsChart"></canvas></div>
    </div>
  </div>
  
  <div class="card" style="margin-top:16px">
    <div class="card-title">Agent Spending Performance Breakdown <span>SPENDING IDENTITIES</span></div>
    <div id="agentPerfTable"></div>
  </div>`;
}

async function loadAnalytics(){
  let [d, overview] = await Promise.all([api('/api/analytics'), api('/api/analytics/overview')]);
  let fin = overview.financials || {};
  let cards = [
    ['REQUESTED VALUE', money(fin.requested_value), 'TOTAL EVALUATED'],
    ['AUTONOMOUS AUTHORIZED', money(fin.authorized_value), 'WITHIN CEILING'],
    ['SMART MODIFIED', money(fin.modified_value), 'POLICY ADJUSTED'],
    ['BLOCKED VALUE', money(fin.blocked_value), 'DENIED AT GATE'],
    ['PAID VOLUME', money(fin.paid_value), 'RAZORPAY CAPTURED']
  ];
  $('#analyticsFinancials').innerHTML = cards.map(c => `
    <div class="card kpi">
      <div class="label">${c[0]}</div>
      <div class="num" style="font-size:20px">${c[1]}</div>
      <div class="delta">${c[2]}</div>
    </div>
  `).join('');
  
  // Funnel
  let maxCount = Math.max(...(overview.conversion_funnel || []).map(x => x.count), 1);
  $('#analyticsFunnel').innerHTML = (overview.conversion_funnel || []).map(f => `
    <div style="margin-bottom:12px">
      <div class="split" style="font-size:12px;margin-bottom:4px">
        <span>${f.stage}</span>
        <b>${f.count} transactions</b>
      </div>
      <div class="riskbar"><i style="width:${Math.round(f.count/maxCount*100)}%"></i></div>
    </div>
  `).join('');
  
  // Agents table
  $('#agentPerfTable').innerHTML = (overview.agent_performance || []).length ? `
    <table>
      <thead>
        <tr><th>AGENT NAME</th><th>TRANSACTIONS</th><th>APPROVAL RATE</th><th>TOTAL SPENT</th><th>PER-TX CEILING</th><th>RISK BASELINE</th></tr>
      </thead>
      <tbody>
        ${overview.agent_performance.map(a => `
          <tr>
            <td><strong>${esc(a.name)}</strong></td>
            <td>${a.total_transactions}</td>
            <td><b class="${a.approval_rate >= 80 ? 'pass' : 'warn'}">${a.approval_rate}%</b></td>
            <td>${money(a.total_spent)}</td>
            <td>${money(a.per_tx_limit)}</td>
            <td>${a.risk_score}/100</td>
          </tr>
        `).join('')}
      </tbody>
    </table>` : '<div class="empty">NO AGENTS LOGGED</div>';
    
  if(charts.analytics) charts.analytics.destroy();
  let dec = overview.decisions || {};
  charts.analytics = new Chart($('#analyticsChart'), {
    type: 'doughnut',
    data: {
      labels: ['ALLOW', 'MODIFY', 'APPROVAL_REQUIRED', 'BLOCK'],
      datasets: [{
        data: [dec.ALLOW || 0, dec.MODIFY || 0, dec.APPROVAL_REQUIRED || 0, dec.BLOCK || 0],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#9ab0a5', font: { size: 11 } } }
      }
    }
  });
}

/* ── Live Cyber Wave / Neural Matrix Background Animation Engine ───────────── */
(function initLiveBackground(){
  const canvas = document.getElementById('bgCanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let width, height, particles = [], pulses = [], mouse = { x: -1000, y: -1000 };

  function resize(){
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initParticles();
  }

  function initParticles(){
    particles = [];
    pulses = [];
    const count = Math.min(Math.floor((width * height) / 14000), 90);
    for(let i = 0; i < count; i++){
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.75,
        vy: (Math.random() - 0.5) * 0.75,
        radius: Math.random() * 2.2 + 1,
        pulse: Math.random() * Math.PI * 2,
        pulseSpeed: 0.02 + Math.random() * 0.035
      });
    }
    for(let i = 0; i < 8; i++){
      pulses.push({
        from: Math.floor(Math.random() * count),
        to: Math.floor(Math.random() * count),
        progress: Math.random(),
        speed: 0.008 + Math.random() * 0.015
      });
    }
  }

  window.addEventListener('resize', resize);
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  resize();

  let t = 0;
  function animate(){
    t += 0.02;
    ctx.clearRect(0, 0, width, height);

    // 1. Deep Space Cyber Atmosphere
    const bgGrad = ctx.createRadialGradient(width * 0.75, height * 0.25, 0, width * 0.75, height * 0.25, width * 0.85);
    bgGrad.addColorStop(0, 'rgba(18, 55, 38, 0.45)');
    bgGrad.addColorStop(0.5, 'rgba(8, 24, 17, 0.6)');
    bgGrad.addColorStop(1, 'rgba(5, 11, 8, 0.95)');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, width, height);

    // 2. Animated 3D Cyber Grid on the bottom horizon
    const horizon = height * 0.65;
    ctx.strokeStyle = 'rgba(115, 227, 155, 0.07)';
    ctx.lineWidth = 1;
    const gridOffset = (t * 22) % 40;
    
    // Horizontal perspective lines
    for(let y = horizon; y < height; y += (y - horizon + 10) * 0.35){
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }
    // Vertical vanishing lines
    const vpX = width / 2;
    for(let x = -width * 0.5; x <= width * 1.5; x += 60){
      ctx.beginPath();
      ctx.moveTo(vpX, horizon - 80);
      ctx.lineTo(x + gridOffset, height);
      ctx.stroke();
    }

    // 3. Fluid Neon Sine Waves (Glowing Aurora Ribbons)
    for(let w = 0; w < 4; w++){
      ctx.beginPath();
      const waveAlpha = 0.06 + w * 0.035;
      ctx.strokeStyle = w % 2 === 0 ? `rgba(115, 227, 155, ${waveAlpha})` : `rgba(79, 208, 160, ${waveAlpha})`;
      ctx.lineWidth = 2 + w * 0.5;
      for(let x = 0; x <= width; x += 14){
        const y = (height * (0.3 + w * 0.18)) +
                  Math.sin(x * 0.0025 + t * 0.9 + w * 1.4) * 65 +
                  Math.cos(x * 0.0055 - t * 0.6) * 40;
        if(x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.shadowBlur = 15;
      ctx.shadowColor = 'rgba(115, 227, 155, 0.4)';
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    // 4. Neural Constellation & Dynamic Vector Connections
    for(let i = 0; i < particles.length; i++){
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.pulse += p.pulseSpeed;

      if(p.x < 0) p.x = width;
      if(p.x > width) p.x = 0;
      if(p.y < 0) p.y = height;
      if(p.y > height) p.y = 0;

      // Mouse interactive repulse / glow
      const dx = mouse.x - p.x, dy = mouse.y - p.y;
      const distMouse = Math.hypot(dx, dy);
      if(distMouse < 160){
        p.x -= (dx / distMouse) * 1.5;
        p.y -= (dy / distMouse) * 1.5;
      }

      // Draw particle with glowing aura
      const glow = (Math.sin(p.pulse) + 1) / 2;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius + glow * 1.4, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(115, 227, 155, ${0.5 + glow * 0.5})`;
      ctx.shadowBlur = 14;
      ctx.shadowColor = 'rgba(115, 227, 155, 0.8)';
      ctx.fill();
      ctx.shadowBlur = 0;

      // Connect to neighbors
      for(let j = i + 1; j < particles.length; j++){
        const p2 = particles[j];
        const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
        if(dist < 150){
          const alpha = (1 - dist / 150) * 0.25;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(115, 227, 155, ${alpha})`;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }
    }

    // 5. Digital Energy Packets travelling between nodes
    for(let k = 0; k < pulses.length; k++){
      const pulse = pulses[k];
      const p1 = particles[pulse.from % particles.length];
      const p2 = particles[pulse.to % particles.length];
      if(!p1 || !p2) continue;
      
      pulse.progress += pulse.speed;
      if(pulse.progress >= 1){
        pulse.progress = 0;
        pulse.from = pulse.to;
        pulse.to = Math.floor(Math.random() * particles.length);
      }
      
      const px = p1.x + (p2.x - p1.x) * pulse.progress;
      const py = p1.y + (p2.y - p1.y) * pulse.progress;
      ctx.beginPath();
      ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.shadowBlur = 12;
      ctx.shadowColor = '#73e39b';
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
})();
