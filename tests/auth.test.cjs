// Dependency-free tests for the inline auth and approval controller.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('index.html', 'utf8');
const script = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(s => s.includes('const dbState'));
const nodes = new Map();
function node(id) {
  if (!nodes.has(id)) {
    const classes = new Set();
    nodes.set(id, { value: '', textContent: '', hidden: false, disabled: false,
      classList: { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x), toggle: (x, force) => { if (force === undefined) force = !classes.has(x); force ? classes.add(x) : classes.delete(x); } }, appendChild() {} });
  }
  return nodes.get(id);
}
let session = null, member = [], userError = null, user = { user_metadata: {} }, status = 'none', owner = false;
let signOutCalls = [], requests = [], deferred;
const client = {
  auth: {
    getSession: async () => ({ data: { session }, error: null }),
    getUser: async () => ({ data: { user }, error: userError }),
    signInWithPassword: async () => { session = {}; return { error: null }; },
    signUp: async args => { requests.push(['signup', args]); return { data: { session: null }, error: null }; },
    signOut: async opts => { signOutCalls.push(opts.scope); session = null; return { error: null }; }
  },
  rpc: async (name, args) => {
    requests.push([name, args]);
    if (name === 'askback_current_member') return deferred ? new Promise(resolve => { deferred.resolve = resolve; }) : { data: member, error: null };
    if (name === 'askback_request_status') return { data: status, error: null };
    if (name === 'askback_submit_join_request') { status = 'pending'; return { data: status, error: null }; }
    if (name === 'askback_is_owner') return { data: owner, error: null };
    throw new Error('Unexpected RPC ' + name);
  }
};
const context = { window: { supabase: { createClient: () => client }, location: { href: 'https://example.com/askback/' } }, document: { getElementById: node },
  localStorage: { removeItem() {}, getItem() { return null; }, setItem() {} }, console: { ...console, error() {} }, URL, setTimeout, setInterval };
vm.createContext(context);
vm.runInContext(script.replace('    app.init();', '    globalThis.app = app; globalThis.dbState = dbState;'), context);
const { app, dbState } = context;
app.closeModals = () => {};
app.showApp = () => { app.shown = true; };
let initCalls = 0;
dbState.ensureInit = async () => { initCalls++; dbState.group = { id: 1 }; dbState.members = { [member[0]?.name || 'Boss']: 1 }; };
(async () => {
  await app.restoreSession(); assert.equal(app.currentUser, null);
  session = {}; member = [{ name: 'Owner' }]; owner = true;
  await app.restoreSession();
  assert.equal(app.currentUser, 'Owner'); assert.equal(app.isOwner, true); assert.equal(app.shown, true);
  app.dashboardData = { stale: true }; app.cachedHistory = [{ stale: true }];
  member = [{ name: 'Boss' }];
  await app.restoreSession();
  assert.equal(app.currentUser, 'Boss');
  assert.equal(app.dashboardData, null, 'a renamed profile clears cached dashboard data');
  assert.equal(app.cachedHistory.length, 0, 'a renamed profile clears cached history');
  assert.equal(app.isOwner, true, 'renaming does not change admin access');
  await app.signOut(); assert.equal(app.currentUser, null); assert.equal(signOutCalls.pop(), 'global');
  session = {}; member = []; owner = false; user = { user_metadata: { display_name: 'Applicant' } }; status = 'none';
  const before = initCalls;
  await app.restoreSession();
  assert.equal(status, 'pending'); assert.equal(app.currentUser, null); assert.equal(app.waitingForApproval, true);
  assert.equal(initCalls, before, 'unapproved user must never initialize app data');
  assert.equal(node('approval-title').textContent, 'Request pending');
  assert.equal(requests.filter(([name]) => name === 'askback_submit_join_request').length, 1);
  await app.restoreSession();
  assert.equal(requests.filter(([name]) => name === 'askback_submit_join_request').length, 1, 'pending users do not resubmit');
  status = 'rejected'; await app.restoreSession();
  assert.equal(app.currentUser, null); assert.match(node('approval-message').textContent, /does not have access/);
  assert.equal(requests.filter(([name]) => name === 'askback_submit_join_request').length, 1, 'rejection does not resubmit');
  userError = new Error('offline'); await app.restoreSession(); assert.equal(app.currentUser, null);
  userError = null; deferred = {};
  const pending = app.restoreSession(); await new Promise(r => setImmediate(r)); app.lockScreen();
  deferred.resolve({ data: [{ name: 'Owner' }], error: null }); await pending;
  assert.equal(app.currentUser, null, 'stale verification cannot unlock after logout');
  deferred = null;
  app.toggleAuthMode();
  node('register-name').value = 'New applicant'; node('login-email').value = 'test@example.com'; node('login-password').value = 'private';
  await app.submitAuth({ preventDefault() {} });
  assert.equal(node('login-password').value, '');
  assert.match(node('login-note').textContent, /confirm your account/);
  assert.equal(requests.at(-1)[0], 'signup');
  console.log('auth and approval controller tests passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
