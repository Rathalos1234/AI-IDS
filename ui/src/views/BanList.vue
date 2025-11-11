<script setup>
import { ref, onMounted, onBeforeUnmount, watch, computed } from 'vue';
import { api } from '../api';
import { subscribeToEvents } from '../eventStream';
import { useRoute, useRouter } from 'vue-router';
const ip = ref(''), reason = ref(''), items = ref([]), err = ref(null), loading = ref(false);
// PD-28 additions:
const duration = ref('');  // minutes (blank = permanent)
const note = ref('');
const trusted = ref([]);   // [{ip,note,created_ts}]
const status = ref('');
const stopFns = [];
const route = useRoute();
const router = useRouter();
let statusTimer = null;
let errorTimer = null;

function clearStatusMessage(){
  if (statusTimer){
    clearTimeout(statusTimer);
    statusTimer = null;
  }
  status.value = '';
}

function clearErrorMessage(){
  if (errorTimer){
    clearTimeout(errorTimer);
    errorTimer = null;
  }
  err.value = null;
}

function setStatusMessage(message, timeout = 4000){
  clearStatusMessage();
  clearErrorMessage();
  if (message){
    status.value = message;
    statusTimer = setTimeout(() => {
      status.value = '';
      statusTimer = null;
    }, timeout);
  }
}

function setErrorMessage(message, timeout = 4000){
  clearErrorMessage();
  clearStatusMessage();
  if (message){
    err.value = message;
    errorTimer = setTimeout(() => {
      err.value = null;
      errorTimer = null;
    }, timeout);
  }
}

function friendlyError(error, fallback){
  const map = {
    bad_ip: 'IP address is not valid.',
    trusted_ip: 'That IP is already marked as trusted.',
    'ip required': 'IP address is required.',
    missing: 'Request is missing required fields.',
  };
  if (error && map[error]) return map[error];
  if (fallback && map[fallback]) return map[fallback];
  if (typeof fallback === 'string' && fallback) return fallback;
  return 'Something went wrong. Please try again.';
}

function applyRouteIp(value){
  if (typeof value === 'string' && value){
    ip.value = value;
  }
}

function clearRouteIp(){
  if (route.query.ip){
    const nextQuery = { ...route.query };
    delete nextQuery.ip;
    router.replace({ query: nextQuery });
  }
}

function deriveActiveBlocks(list){
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const active = [];
  for (const row of list){
    if (!row || !row.ip || seen.has(row.ip)) continue;
    seen.add(row.ip);
    if ((row.action || '').toLowerCase() === 'block'){
      active.push(row);
    }
  }
  return active;
}

async function refresh(){
  try{
    loading.value = true;
    clearErrorMessage();
    clearStatusMessage();
    const data = await api.blocks();
    const rawBlocks = Array.isArray(data) ? data : (data.items || []);
    if (data && Array.isArray(data.active)){
      items.value = data.active;
    } else {
      items.value = deriveActiveBlocks(rawBlocks);
    }
    const t = await (api.trustedList ? api.trustedList() : { items: [] });
    const list = Array.isArray(t) ? t : t.items || [];
    trusted.value = list;
  }catch(e){ setErrorMessage(friendlyError(e?.error, e?.message)); } finally { loading.value=false; }
}
async function block(){
  if(!ip.value) return;
  try{
    const dm = duration.value ? parseInt(duration.value,10) : null;
    const target = ip.value;
    if (api.blockIpWithDuration) {
      const res = await api.blockIpWithDuration(ip.value, { reason: reason.value || '', duration_minutes: dm });
      setStatusMessage(describeFirewall(res?.firewall, `Blocked ${target}`));
    } else {
      const res = await api.block(ip.value, reason.value || '');
      setStatusMessage(describeFirewall(res?.firewall, `Blocked ${target}`));
    }
    ip.value=''; reason.value=''; duration.value='';
    clearRouteIp();
    await refresh();
  }  catch(e){ setErrorMessage(friendlyError(e?.error, e?.message)); }
}
async function unblock(addr){
  try{
    const res = await api.unblock(addr);
    setStatusMessage(describeFirewall(res?.firewall, `Unblocked ${addr}`));
    await refresh();
  }
  catch(e){ setErrorMessage(friendlyError(e?.error, e?.message)); }
}
async function trust(addr){
  const target = (typeof addr === 'string' && addr) ? addr : ip.value;
  if (!target) return;
  try{
    await api.trustIp(target, note.value || '');
    setStatusMessage(`Marked ${target} as trusted.`);
    if (!(typeof addr === 'string' && addr)) {
      note.value='';
      ip.value='';
      clearRouteIp();
    }
    await refresh();
  }
  catch(e){ setErrorMessage(friendlyError(e?.error, e?.message)); }
}
async function untrust(addr){
  const target = (typeof addr === 'string' && addr) ? addr : ip.value;
  if (!target) return;
  try{
    await api.untrustIp(target);
    setStatusMessage(`Removed ${target} from trusted list.`);
    if (!(typeof addr === 'string' && addr)) {
      ip.value='';
      clearRouteIp();
    }
    await refresh();
  }
  catch(e){ setErrorMessage(friendlyError(e?.error, e?.message)); }
}
function applyBlockEvent(event) {
  if (!event || !event.id) return;
  if (event.action && event.action !== 'block') {
    const idx = items.value.findIndex((row) => row.ip === event.ip);
    if (idx !== -1) items.value.splice(idx, 1);
    return;
  }
  const idx = items.value.findIndex((row) => row.ip === event.ip);
  if (idx !== -1) {
    items.value.splice(idx, 1, event);
  } else {
    items.value.unshift(event);
    if (items.value.length > 200) items.value.splice(200);
  }
}

onMounted(async () => {
  applyRouteIp(route.query.ip);
  await refresh();
  stopFns.push(subscribeToEvents('block', applyBlockEvent));
});

watch(() => route.query.ip, (value) => {
  if (typeof value === 'string' && value) {
    applyRouteIp(value);
  }
});

onBeforeUnmount(() => {
  while (stopFns.length) {
    const off = stopFns.pop();
    try { if (typeof off === 'function') off(); } catch (e) { console.error(e); }
  }
  clearStatusMessage();
  clearErrorMessage();
});

function describeFirewall(fw, prefix){
  if (!fw) return prefix;
  if (fw.applied) {
    return `${prefix} — firewall rule applied.`;
  }
  if (fw.error) {
    return `${prefix} — firewall: ${fw.error}`;
  }
  if (fw.capabilities && fw.capabilities.supported === false) {
    return `${prefix} — recorded (firewall unsupported).`;
  }
  return `${prefix}.`;
}

const tableEntries = computed(() => {
  const rows = [];
  for (const block of items.value){
    rows.push({
      kind: 'blocked',
      ip: block.ip,
      ts: block.ts || '',
      detail: block.reason || '',
    });
  }
  for (const t of trusted.value){
    rows.push({
      kind: 'trusted',
      ip: t.ip,
      ts: t.created_ts || '',
      detail: t.note || '',
    });
  }
  const order = { trusted: 0, blocked: 1 };
  return rows.sort((a, b) => {
    if (order[a.kind] !== order[b.kind]){
      return order[a.kind] - order[b.kind];
    }
    const aTs = a.ts || '';
    const bTs = b.ts || '';
    if (aTs && bTs) return bTs.localeCompare(aTs);
    if (aTs) return -1;
    if (bTs) return 1;
    return a.ip.localeCompare(b.ip);
  });
});

function entryDate(ts){
  if (!ts) return '—';
  if (typeof ts === 'string' && ts.includes('T')){
    return ts.split('T')[0];
  }
  return ts;
}

function entryDetail(text){
  return text && String(text).trim() ? text : '—';
}

</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Ban List</h1>
        <p>Contain hostile hosts and manage trusted allow-list entries.</p>
      </div>
      <div class="actions-row">
        <button class="btn" @click="refresh" :disabled="loading">{{ loading ? 'Refreshing…' : 'Refresh' }}</button>
      </div>
    </div>

    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>
    <div v-if="status" class="alert-banner success" style="margin-bottom:16px;">{{ status }}</div>

    <section class="surface surface--soft" style="margin-bottom:20px;">
      <div class="actions-row" style="flex-wrap:wrap; gap:12px;">
        <input class="input" v-model="ip" placeholder="IP address" style="min-width:180px;" />
        <input class="input" v-model="reason" placeholder="Reason (optional)" style="min-width:200px;" />
        <input class="input" v-model="duration" placeholder="Minutes (blank = permanent)" style="min-width:200px;" />
        <button class="btn btn--danger" @click="block" :disabled="!ip">Block</button>
      </div>
      <div class="actions-row" style="flex-wrap:wrap; gap:12px; margin-top:14px;">
        <input class="input" v-model="ip" placeholder="IP address (trust)" style="min-width:180px;" />
        <input class="input" v-model="note" placeholder="Trust note (optional)" style="min-width:200px;" />
        <div class="actions-row" style="gap:10px;">
          <button class="btn btn--primary" @click="trust()" :disabled="!ip">Trust</button>
          <!-- <button class="btn" @click="untrust()" :disabled="!ip">Untrust</button> -->
        </div>
      </div>
    </section>
    <section class="surface table-card">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>IP Address</th>
            <th>Details</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in tableEntries" :key="`${entry.kind}-${entry.ip}`">
            <td>{{ entryDate(entry.ts) }}</td>
            <td>{{ entry.ip }}</td>
            <td>{{ entryDetail(entry.detail) }}</td>
            <td>
              <span class="badge" :class="entry.kind === 'trusted' ? 'badge--trusted' : 'badge--blocked'">
                {{ entry.kind === 'trusted' ? 'TRUSTED' : 'BLOCKED' }}
              </span>
            </td>
            <td>
              <button
                v-if="entry.kind === 'blocked'"
                class="btn btn--ghost"
                @click="unblock(entry.ip)"
              >Unblock</button>
              <button
                v-else
                class="btn btn--ghost"
                @click="untrust(entry.ip)"
              >Untrust</button>
            </td>
          </tr>
          <tr v-if="!tableEntries.length">
            <td colspan="5" class="small" style="text-align:center;color:var(--muted);padding:18px;">No entries yet.</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
