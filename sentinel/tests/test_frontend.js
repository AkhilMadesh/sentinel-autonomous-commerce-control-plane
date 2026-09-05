const fs = require('fs');
const path = require('path');

const appJsPath = path.join(__dirname, '..', 'static', 'app.js');
const code = fs.readFileSync(appJsPath, 'utf8');

// Mock DOM
global.document = {
  querySelector: () => ({
    classList: { add: ()=>{}, remove: ()=>{}, toggle: ()=>{} },
    innerHTML: '',
    textContent: '',
    style: {},
    appendChild: ()=>{}
  }),
  querySelectorAll: () => [],
  getElementById: () => ({
    getContext: () => ({
      clearRect: ()=>{},
      beginPath: ()=>{},
      arc: ()=>{},
      fill: ()=>{},
      stroke: ()=>{},
      moveTo: ()=>{},
      lineTo: ()=>{}
    }),
    width: 1920,
    height: 1080
  }),
  addEventListener: ()=>{}
};
global.window = { products: [], agents: [], addEventListener: ()=>{} };
global.crypto = { randomUUID: () => 'test-uuid-1234' };
global.fetch = async () => ({ ok: true, json: async () => ({}) });
global.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
global.setInterval = () => 1;
global.clearInterval = () => {};
global.setTimeout = (fn) => fn();
global.requestAnimationFrame = () => {};

try {
  eval(code);
  console.log("✓ static/app.js evaluated with zero syntax errors!");
  
  const pages = [
    'overviewHTML', 'liveHTML', 'transactionsHTML', 'agentsHTML', 'usersHTML',
    'delegationsHTML', 'policiesHTML', 'buyerHTML', 'merchantHTML', 'catalogHTML',
    'riskHTML', 'approvalsHTML', 'auditHTML', 'analyticsHTML', 'apiHTML'
  ];
  
  for (const p of pages) {
    if (typeof eval(p) !== 'function') {
      throw new Error(`Missing page builder function: ${p}`);
    }
    const html = eval(`${p}()`);
    if (typeof html !== 'string' || html.length < 20) {
      throw new Error(`Page builder ${p}() returned invalid or empty HTML: ${html}`);
    }
    console.log(`✓ ${p}() verified (${html.length} chars)`);
  }
  console.log("\nALL 15 FRONTEND PAGE BUILDERS VERIFIED NON-EMPTY AND ERROR-FREE!");
} catch (err) {
  console.error("Frontend verification failed:", err);
  process.exit(1);
}
