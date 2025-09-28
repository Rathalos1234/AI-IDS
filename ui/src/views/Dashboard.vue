<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';

const counts = ref(null);
const ts = ref(null);
const devices = ref([]);
const recent = ref([]);
const err = ref(null);
const loading = ref(false);

async function load() {
  try {
    loading.value = true; err.value = null;
    const s = await api.stats(); counts.value = s.counts; ts.value = s.ts;
    const d = await api.devices(); devices.value = Array.isArray(d) ? d : (d.items || []);
    const a = await api.alerts(5); const items = Array.isArray(a) ? a : (a.items || []);
    recent.value = items.slice(0,5);
  } catch(e) { err.value = e?.error || e?.message; }
  finally { loading.value = false; }
}
onMounted(load);
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Dashboard</h1>

    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <button class="btn-toggle" @click="load"><span class="swap"><span class="front">Scan Network</span><span class="back">Refresh</span></span></button>

    <div style="display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-top:16px;">
      <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead><tr style="background:#0f141b;"><th style="text-align:left;padding:12px;">IP Address</th><th style="text-align:left;padding:12px;">Device Name</th><th style="text-align:left;padding:12px;">Open Ports</th><th style="text-align:left;padding:12px;">Action</th></tr></thead>
          <tbody>
            <tr v-for="d in devices" :key="d.ip" style="border-top:1px solid var(--border);">
              <td style="padding:12px;">{{ d.ip }}</td>
              <td style="padding:12px;">{{ d.name || 'Unknown' }}</td>
              <td style="padding:12px;"><span class="badge low">Low</span></td>
              <td style="padding:12px;"><router-link to="/banlist"><button class="btn">Block</button></router-link></td>
            </tr>
            <tr v-if="!devices.length"><td colspan="4" style="padding:12px;color:var(--muted);">No devices yet.</td></tr>
          </tbody>
        </table>
      </div>

      <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;">
        <h3 style="margin:0 0 8px;">Quick Overview</h3>
        <div class="small">Total Devices: <b>{{ devices.length }}</b></div>
        <div class="small">Last Scan: <b>{{ new Date(ts||'').toLocaleTimeString() || '—' }}</b></div>
        <div class="small">Unknown Devices: <b>{{ devices.filter(d=>!d.name).length }}</b></div>

        <div style="margin-top:16px;">
          <h4 style="margin:0 0 8px;">Recent Alerts</h4>
          <div v-for="a in recent" :key="a.id" class="small" style="display:flex;justify-content:space-between;border-top:1px solid var(--border);padding:8px 0;">
            <span>IP: {{ a.src_ip }} • {{ a.label }}</span>
            <span class="mono">{{ (a.ts||'').split('T')[1]?.slice(0,5) }}</span>
          </div>
          <div v-if="!recent.length" class="small" style="color:var(--muted)">No alerts yet.</div>
        </div>
      </div>
    </div>
  </div>
</template>
