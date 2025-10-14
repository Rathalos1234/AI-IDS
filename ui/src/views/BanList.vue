<script setup>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';
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

async function refresh(){
  try{
    loading.value = true; err.value=null; status.value='';
    const data = await api.blocks();
    items.value = Array.isArray(data) ? data : (data.items || []);
    const t = await (api.trustedList ? api.trustedList() : { items: [] });
    const list = Array.isArray(t) ? t : t.items || [];
    trusted.value = list;
  }catch(e){ err.value = e?.error || e?.message; } finally { loading.value=false; }
}
async function block(){
  if(!ip.value) return;
  try{
    const dm = duration.value ? parseInt(duration.value,10) : null;
    const target = ip.value;
    if (api.blockIpWithDuration) {
      const res = await api.blockIpWithDuration(ip.value, { reason: reason.value || '', duration_minutes: dm });
      status.value = describeFirewall(res?.firewall, `Blocked ${target}`);
    } else {
      const res = await api.block(ip.value, reason.value || '');
      status.value = describeFirewall(res?.firewall, `Blocked ${target}`);
    }
    ip.value=''; reason.value=''; duration.value='';
    clearRouteIp();
    await refresh();
  }  catch(e){ err.value = e?.error || e?.message; }
}
async function unblock(addr){
  try{ const res = await api.unblock(addr); status.value = describeFirewall(res?.firewall, `Unblocked ${addr}`); await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
const isTrusted = (xip) => !!trusted.value.find(t => t.ip === xip);
async function trust(addr){
  const target = (typeof addr === 'string' && addr) ? addr : ip.value;
  if (!target) return;
  try{
    await api.trustIp(target, note.value || '');
    status.value = `Marked ${target} as trusted.`;
    if (!(typeof addr === 'string' && addr)) {
      note.value='';
      ip.value='';
      clearRouteIp();
    }
    await refresh();
  }
  catch(e){ err.value = e?.error || e?.message; }
}
async function untrust(addr){
  const target = (typeof addr === 'string' && addr) ? addr : ip.value;
  if (!target) return;
  try{
    await api.untrustIp(target);
    status.value = `Removed ${target} from trusted list.`;
    if (!(typeof addr === 'string' && addr)) {
      ip.value='';
      clearRouteIp();
    }
    await refresh();
  }
  catch(e){ err.value = e?.error || e?.message; }
}
function applyBlockEvent(event) {
  if (!event || !event.id) return;
  const existingIdx = items.value.findIndex((row) => row.id === event.id);
  if (existingIdx !== -1) {
    items.value.splice(existingIdx, 1);
  }
  items.value.unshift(event);
  if (items.value.length > 200) items.value.splice(200);
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
          <button class="btn" @click="untrust()" :disabled="!ip">Untrust</button>
        </div>
      </div>
      <div v-if="trusted.length" class="trusted-chips small">
        <div class="chip chip--action" v-for="t in trusted" :key="t.ip">
          <span>{{ t.ip }} • {{ t.note || 'trusted' }}</span>
          <button class="chip__close" type="button" @click.stop="untrust(t.ip)" :aria-label="`Remove trust for ${t.ip}`">×</button>
        </div>
      </div>
    </section>
    <section class="surface table-card">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>IP Address</th>
            <th>Reason</th>
            <th>Action</th>
            <th>Ops</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in items" :key="b.id">
            <td>{{ (b.ts||'').split('T')[0] }}</td>
            <td>{{ b.ip }}</td>
            <td>{{ b.reason || '—' }}</td>
            <td>
              <button v-if="b.action==='block'" class="btn btn--ghost" @click="unblock(b.ip)">Unblock</button>
              <span v-else class="small" style="color:var(--muted); text-transform:capitalize;">{{ b.action }}</span>
            </td>
            <td>
              <span v-if="isTrusted(b.ip)" class="badge">Trusted</span>
              <button v-else class="btn btn--ghost" @click="trust(b.ip)">Trust</button>
            </td>
          </tr>
          <tr v-if="!items.length">
            <td colspan="5" class="small" style="text-align:center;color:var(--muted);padding:18px;">No blocks yet.</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
