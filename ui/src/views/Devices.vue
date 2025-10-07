<script setup>
import { ref, onMounted } from 'vue'
import { fetchDevices } from '../api'  // or idsApi.getDevices() if you use the aggregator
const items = ref([]), err = ref(null), loading = ref(false)
async function load(){
  try{
    loading.value = true; err.value=null
    const data = await fetchDevices?.() || (await idsApi.getDevices())
    items.value = Array.isArray(data) ? data : (data.items || [])
  }catch(e){ err.value = e?.error || e?.message }
  finally{ loading.value = false }
}
onMounted(load)
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Devices</h1>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr style="background:#0f141b;">
          <th style="text-align:left;padding:12px;">IP</th>
          <th style="text-align:left;padding:12px;">First Seen</th>
          <th style="text-align:left;padding:12px;">Last Seen</th>
          <th style="text-align:left;padding:12px;">Name</th>
        </tr></thead>
        <tbody>
          <tr v-for="d in items" :key="d.ip" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ d.ip }}</td>
            <td style="padding:12px;">{{ d.first_seen }}</td>
            <td style="padding:12px;">{{ d.last_seen }}</td>
            <td style="padding:12px;">{{ d.name || '—' }}</td>
          </tr>
          <tr v-if="!items.length"><td colspan="4" style="padding:12px;color:var(--muted);">No devices yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
