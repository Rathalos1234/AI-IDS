<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { fetchLogs } from '../api'

const items = ref([])
const err = ref(null)
let es

function normalize(e) {
  // unify table shape
  if (e.type === 'alert' || e.kind === 'ANOMALY' || e.kind === 'SIGNATURE') {
    return { id: e.id, ts: e.ts, ip: e.src_ip || e.ip, type: 'alert', detail: e.label || e.kind }
  }
  if (e.type === 'block' || e.action === 'block' || e.action === 'unblock') {
    return { id: e.id, ts: e.ts, ip: e.ip, type: e.action === 'block' ? 'block' : 'unblock', detail: e.action }
  }
  return { id: e.id, ts: e.ts, ip: e.ip || e.src_ip, type: e.type || e.kind || 'event', detail: e.label || '' }
}

async function initialLoad() {
  try {
    err.value = null
    const res = await fetchLogs(200)
    const page = Array.isArray(res) ? res : (res.items || [])
    items.value = page.map(normalize)
  } catch (e) {
    err.value = e?.error || e?.message || 'Failed to load logs'
  }
}

function startSSE() {
  const base = localStorage.getItem('API_BASE') || ''
  es = new EventSource(base + '/api/events', { withCredentials: true })
  es.addEventListener('alert', (ev) => {
    const d = JSON.parse(ev.data); items.value.unshift(normalize({ ...d, type: 'alert' }))
  })
  es.addEventListener('block', (ev) => {
    const d = JSON.parse(ev.data); items.value.unshift(normalize({ ...d, type: 'block' }))
  })
  es.onerror = () => { /* network hiccup: keep connection open; browser will retry */ }
}

onMounted(async () => { await initialLoad(); startSSE() })
onBeforeUnmount(() => { if (es) es.close() })
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Log History</h1>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead>
          <tr style="background:#0f141b;">
            <th style="text-align:left;padding:12px;">Date</th>
            <th style="text-align:left;padding:12px;">Time</th>
            <th style="text-align:left;padding:12px;">IP Address</th>
            <th style="text-align:left;padding:12px;">Type</th>
            <th style="text-align:left;padding:12px;">Details</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in items" :key="e.id + e.type" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ (e.ts||'').split('T')[0] }}</td>
            <td style="padding:12px;">{{ (e.ts||'').split('T')[1]?.slice(0,5) }}</td>
            <td style="padding:12px;">{{ e.ip }}</td>
            <td style="padding:12px; text-transform:capitalize;">{{ e.type }}</td>
            <td style="padding:12px;">{{ e.detail }}</td>
          </tr>
          <tr v-if="!items.length"><td colspan="5" style="padding:12px;color:var(--muted);">No events yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
