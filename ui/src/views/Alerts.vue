<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const items = ref([]), nextCursor = ref(null), limit = 50, err = ref(null), loading = ref(false);
const base = (localStorage.getItem('API_BASE') || window.API_BASE || '');
async function load(cursor=null){
  try{
    loading.value=true; err.value=null;
    const data = await api.alerts(limit, cursor);
    if (Array.isArray(data)) { items.value = cursor? items.value.concat(data) : data; nextCursor.value = data.length?data[data.length-1].ts:null; }
    else { const page = data.items||[]; items.value = items.value.concat(page); nextCursor.value = data.next_cursor || (items.value[items.value.length-1]?.ts || null); }
  }catch(e){ err.value = e?.error || e?.message; } finally{ loading.value=false; }
}
onMounted(()=>load());
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Alerts</h1>
    <div style="margin:8px 0; display:flex; gap:8px;">
      <a class="btn" :href="`${base}/api/logs/export?type=alert&format=csv`" download>Export CSV</a>
      <a class="btn" :href="`${base}/api/logs/export?type=alert&format=json`" download>Export JSON</a>
    </div>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr style="background:#0f141b;"><th style="text-align:left;padding:12px;">Date</th><th style="text-align:left;padding:12px;">Time</th><th style="text-align:left;padding:12px;">IP Address</th><th style="text-align:left;padding:12px;">Description</th></tr></thead>
        <tbody>
          <tr v-for="a in items" :key="a.id" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ (a.ts||'').split('T')[0] }}</td>
            <td style="padding:12px;">{{ (a.ts||'').split('T')[1]?.slice(0,5) }}</td>
            <td style="padding:12px;">{{ a.src_ip }}</td>
            <td style="padding:12px;">{{ a.label }}</td>
          </tr>
          <tr v-if="!items.length"><td colspan="4" style="padding:12px;color:var(--muted);">No alerts yet.</td></tr>
        </tbody>
      </table>
    </div>
    <div style="margin-top:12px;">
      <button class="btn" :disabled="!nextCursor||loading" @click="load(nextCursor)">Load more</button>
    </div>
  </div>
</template>
