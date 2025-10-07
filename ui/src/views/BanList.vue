<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const ip = ref(''), reason = ref(''), items = ref([]), err = ref(null), loading = ref(false);
// PD-28 additions:
const duration = ref('');  // minutes (blank = permanent)
const note = ref('');
const trusted = ref([]);   // [{ip,note,created_ts}]

async function refresh(){
  try{
    loading.value = true; err.value=null;
    const data = await api.blocks();
    items.value = Array.isArray(data) ? data : (data.items || []);
    const t = await (api.trustedList ? api.trustedList() : { items: [] });
    trusted.value = t.items || [];
  }catch(e){ err.value = e?.error || e?.message; } finally { loading.value=false; }
}
async function block(){
  if(!ip.value) return;
  try{
    const dm = duration.value ? parseInt(duration.value,10) : null;
    if (api.blockIpWithDuration) {
      await api.blockIpWithDuration(ip.value, { reason: reason.value || '', duration_minutes: dm });
    } else {
      await api.block(ip.value, reason.value || '');
    }
    ip.value=''; reason.value=''; duration.value='';
    await refresh();
  }  catch(e){ err.value = e?.error || e?.message; }
}
async function unblock(addr){
  try{ await api.unblock(addr); await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
const isTrusted = (xip) => !!trusted.value.find(t => t.ip === xip);
async function trust(addr){
  try{ await api.trustIp(addr, note.value || ''); note.value=''; await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
async function untrust(addr){
  try{ await api.untrustIp(addr); await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
onMounted(refresh);
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Ban List</h1>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px;margin-bottom:12px;">
     <div style="display:grid;grid-template-columns:1fr 2fr 1fr auto;gap:8px;">
        <input class="input" v-model="ip" placeholder="IP address"/>
        <input class="input" v-model="reason" placeholder="Reason (optional)"/>
        <input class="input" v-model="duration" placeholder="Minutes (blank = permanent)"/>
        <button class="btn" @click="block">Block</button>
      </div>
      <div style="display:grid;grid-template-columns:1fr 2fr auto;gap:8px; margin-top:8px;">
        <input class="input" v-model="ip" placeholder="IP address (trust/untrust)"/>
        <input class="input" v-model="note" placeholder="Trust note (optional)"/>
        <div style="display:flex;gap:8px;">
          <button class="btn" @click="trust(ip)" :disabled="!ip">Trust</button>
          <button class="btn" @click="untrust(ip)" :disabled="!ip">Untrust</button>
        </div>
      </div>
    </div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr style="background:#0f141b;"><th style="text-align:left;padding:12px;">Date</th><th style="text-align:left;padding:12px;">IP Address</th><th style="text-align:left;padding:12px;">Reason</th><th style="text-align:left;padding:12px;">Action</th><th style="text-align:left;padding:12px;">Ops</th></tr></thead>
        <tbody>
          <tr v-for="b in items" :key="b.id" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ (b.ts||'').split('T')[0] }}</td>
            <td style="padding:12px;">{{ b.ip }}</td>
            <td style="padding:12px;">{{ b.reason || '—' }}</td>
            <td style="padding:12px;">
              <button v-if="b.action==='block'" class="btn" @click="unblock(b.ip)">Unblock</button>
            </td>
            <td style="padding:12px;">
              <span v-if="isTrusted(b.ip)" class="badge">Trusted</span>
              <button v-else class="btn" @click="trust(b.ip)">Trust</button>
              <button v-if="isTrusted(b.ip)" class="btn" style="margin-left:6px" @click="untrust(b.ip)">Untrust</button>
            </td>
          </tr>
          <tr v-if="!items.length"><td colspan="4" style="padding:12px;color:var(--muted);">No blocks yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
