<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const ip = ref(''), reason = ref(''), items = ref([]), err = ref(null), loading = ref(false);

async function refresh(){
  try{
    loading.value = true; err.value=null;
    const data = await api.blocks();
    items.value = Array.isArray(data) ? data : (data.items || []);
  }catch(e){ err.value = e?.error || e?.message; } finally { loading.value=false; }
}
async function block(){
  if(!ip.value) return;
  try{ await api.block(ip.value, reason.value); ip.value=''; reason.value=''; await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
async function unblock(addr){
  try{ await api.unblock(addr); await refresh(); }
  catch(e){ err.value = e?.error || e?.message; }
}
onMounted(refresh);
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Ban List</h1>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px;margin-bottom:12px;">
      <div style="display:grid;grid-template-columns:1fr 2fr auto;gap:8px;">
        <input class="input" v-model="ip" placeholder="IP address"/>
        <input class="input" v-model="reason" placeholder="Reason (optional)"/>
        <button class="btn" @click="block">Block</button>
      </div>
    </div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr style="background:#0f141b;"><th style="text-align:left;padding:12px;">Date</th><th style="text-align:left;padding:12px;">IP Address</th><th style="text-align:left;padding:12px;">Reason</th><th style="text-align:left;padding:12px;">Action</th></tr></thead>
        <tbody>
          <tr v-for="b in items" :key="b.id" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ (b.ts||'').split('T')[0] }}</td>
            <td style="padding:12px;">{{ b.ip }}</td>
            <td style="padding:12px;">{{ b.reason || '—' }}</td>
            <td style="padding:12px;">
              <button v-if="b.action==='block'" class="btn" @click="unblock(b.ip)">Unblock</button>
            </td>
          </tr>
          <tr v-if="!items.length"><td colspan="4" style="padding:12px;color:var(--muted);">No blocks yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
