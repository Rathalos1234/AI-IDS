<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { api } from '../api'

const counts = ref(null)
const ts = ref(null)
const devices = ref([])
const recent = ref([])
const err = ref(null)
const loading = ref(false)

const scanning = ref(false)
const scanInfo = ref(null)

// single passive poller, started ONLY while a scan is running
let statusTimer = null
let lastScanStatus = null
const loadingGuard = ref(false)

async function load () {
  if (loadingGuard.value) return
  try {
    loadingGuard.value = true
    loading.value = true
    err.value = null
    const s = await api.stats(); counts.value = s.counts; ts.value = s.ts
    const d = await api.devices(); devices.value = Array.isArray(d) ? d : (d.items || [])
    const a = await api.alerts(5); const items = Array.isArray(a) ? a : (a.items || [])
    recent.value = items.slice(0, 5)
  } catch (e) {
    err.value = e?.error || e?.message || 'Load failed'
  } finally {
    loading.value = false
    loadingGuard.value = false
  }
}

function startStatusPolling () {
  if (statusTimer) return
  statusTimer = setInterval(async () => {
    try {
      const r = await fetch('/api/scan/status', { credentials: 'include' })
      if (!r.ok) return
      const { scan } = await r.json()
      scanInfo.value = scan
      const status = (scan && scan.status) ? scan.status : 'idle'
      scanning.value = status === 'running'

      // React only to status transitions
      if (status !== lastScanStatus) {
        lastScanStatus = status
        if (status === 'done' || status === 'error' || status === 'canceled') {
          // stop polling and refresh once
          clearInterval(statusTimer); statusTimer = null
          scanning.value = false
          await load()
          return
        }
      }

      // If we become idle for any reason, stop polling
      if (status === 'idle' && statusTimer) {
        clearInterval(statusTimer); statusTimer = null
      }
    } catch (_) {}
  }, 2000)
}

onMounted(async () => {
  await load()
  // One-time status check on mount; only start polling if already running
  try {
    const r = await fetch('/api/scan/status', { credentials: 'include' })
    if (r.ok) {
      const { scan } = await r.json()
      scanInfo.value = scan
      const status = (scan && scan.status) ? scan.status : 'idle'
      lastScanStatus = status
      scanning.value = status === 'running'
      if (scanning.value) startStatusPolling()
    }
  } catch (_) {}
})

onBeforeUnmount(() => {
  if (statusTimer) clearInterval(statusTimer)
})

// ---- Start a scan from the UI ----
async function runScan () {
  try {
    scanning.value = true
    lastScanStatus = 'running'
    if (api.startScan) {
      await api.startScan()
    } else {
      const r = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({})
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
    }
    startStatusPolling() // begin polling only after a scan is started
  } catch (e) {
    scanning.value = false
    console.error(e)
  }
}

// helpers already used in your template
const lastScanStr = computed(() => {
  const t = (scanInfo.value && scanInfo.value.finished) ? scanInfo.value.finished : ts.value
  if (!t) return '—'
  try { return new Date(t).toLocaleTimeString() } catch { return '—' }
})
function hhmm (s) {
  if (!s) return '—'
  const parts = String(s).split('T')
  return parts.length > 1 ? parts[1].slice(0, 5) : '—'
}
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Dashboard</h1>

    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <button class="btn-toggle" @click="runScan" :disabled="scanning">
      <span class="swap">
        <span class="front">{{ scanning ? 'Scanning…' : 'Scan Network' }}</span>
        <span class="back">{{ scanning ? 'Scanning…' : 'Scan Network' }}</span>
      </span>
    </button>
    <span
      v-if="scanInfo"
      class="small"
      style="margin-left:8px;color:var(--muted);"
      data-test="scan-status"
    >
      {{ scanInfo.progress }} / {{ scanInfo.total }} · {{ scanInfo.status }}
    </span>
    <button class="btn" style="margin-left:8px" @click="load" :disabled="loading">Refresh</button>

    <div style="display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-top:16px;">
      <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead>
            <tr style="background:#0f141b;">
              <th style="text-align:left;padding:12px;">IP Address</th>
              <th style="text-align:left;padding:12px;">Device Name</th>
              <th style="text-align:left;padding:12px;">Open Ports / Risk</th>
              <th style="text-align:left;padding:12px;">Action</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="d in devices"
              :key="d.ip"
              style="border-top:1px solid var(--border);"
              data-test="device-row"
            >
              <td style="padding:12px;">{{ d.ip }}</td>
              <td style="padding:12px;">{{ d.name || 'Unknown' }}</td>
              <td style="padding:12px;">
                <div class="small">Ports: {{ d.open_ports || '—' }}</div>
                <div><span class="badge" :class="(d.risk || '').toLowerCase()">{{ d.risk || '—' }}</span></div>
              </td>
              <td style="padding:12px;"><router-link to="/banlist"><button class="btn">Block</button></router-link></td>
            </tr>
            <tr v-if="!devices.length">
              <td colspan="4" style="padding:12px;color:var(--muted);">No devices yet.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;">
        <h3 style="margin:0 0 8px;">Quick Overview</h3>
        <div class="small">Total Devices: <b>{{ devices.length }}</b></div>
        <div class="small">
          Last Scan:
          <b class="mono" data-test="last-update">{{ lastScanStr }}</b>
        </div>
        <div class="small">Unknown Devices: <b>{{ devices.filter(d => !d.name).length }}</b></div>

        <div style="margin-top:16px;" data-test="recent-alerts">
          <h4 style="margin:0 0 8px;">Recent Alerts</h4>
          <div
            v-for="a in recent"
            :key="a.id"
            class="small"
            data-test="alert-row"
            style="display:flex;justify-content:space-between;border-top:1px solid var(--border);padding:8px 0;"
          >
            <span>IP: {{ a.src_ip }} • {{ a.label }}</span>
            <span class="mono">{{ hhmm(a.ts) }}</span>
          </div>
          <div v-if="!recent.length" class="small" style="color:var(--muted)">No alerts yet.</div>
        </div>
      </div>
    </div>
  </div>
</template>
