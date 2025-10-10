<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { api } from '../api'
import { subscribeToEvents } from '../eventStream'

const counts = ref(null)
const ts = ref(null)
const devices = ref([])
const recent = ref([])
const err = ref(null)
const loading = ref(false)
const apiBase = window.API_BASE || localStorage.getItem('API_BASE') || ''
const scanning = ref(false)
const scanInfo = ref(null)
const realtimeStops = []

// single passive poller, started ONLY while a scan is running
let statusTimer = null
let lastScanStatus = null
const loadingGuard = ref(false)

const unknownDevices = computed(() => devices.value.filter(d => !d?.name).length)
const alertCount = computed(() => counts.value?.alerts_200 ?? 0)
const blockCount = computed(() => counts.value?.blocks_200 ?? 0)

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
      const data = await fetchScanStatus()
      if (!data) return
      const { scan } = data
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

async function fetchScanStatus () {
  try {
    if (api.scanStatus) {
      return await api.scanStatus()
    }
    const r = await fetch(`${apiBase}/api/scan/status`, { credentials: 'include' })
    if (!r.ok) return null
    return await r.json()
  } catch (e) {
    console.error('scan status failed', e)
    return null
  }
}

async function triggerScan () {
  if (api.startScan) {
    return api.startScan()
  }
  const r = await fetch(`${apiBase}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({}),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

onMounted(async () => {
  await load()
  // One-time status check on mount; only start polling if already running
  try {
    const data = await fetchScanStatus()
    if (!data) return
    const { scan } = data
    scanInfo.value = scan
    const status = (scan && scan.status) ? scan.status : 'idle'
    lastScanStatus = status
    scanning.value = status === 'running'
    if (scanning.value) startStatusPolling()
  } catch (_) {}

  startRealtime()
})

onBeforeUnmount(() => {
  if (statusTimer) clearInterval(statusTimer)
  while (realtimeStops.length) {
    const off = realtimeStops.pop()
    try { if (typeof off === 'function') off() } catch (e) { console.error(e) }
  }
})

// ---- Start a scan from the UI ----
async function runScan () {
  try {
    scanning.value = true
    lastScanStatus = 'running'
    await triggerScan()
    startStatusPolling() // begin polling only after a scan is started
  } catch (e) {
    scanning.value = false
    console.error(e)
  }
}

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

const alertIp = (entry) => entry?.src_ip || entry?.ip || '—'
const alertLabel = (entry) => entry?.label || entry?.detail || entry?.kind || 'Alert'

function startRealtime () {
  realtimeStops.push(
    subscribeToEvents('alert', (payload) => {
      if (!payload || !payload.id) return
      counts.value = {
        ...(counts.value || {}),
        alerts_200: (counts.value?.alerts_200 || 0) + 1,
      }
      const idx = recent.value.findIndex(r => r.id === payload.id)
      if (idx !== -1) recent.value.splice(idx, 1)
      recent.value.unshift(payload)
      if (recent.value.length > 5) recent.value.splice(5)
    }),
  )
  realtimeStops.push(
    subscribeToEvents('block', () => {
      counts.value = {
        ...(counts.value || {}),
        blocks_200: (counts.value?.blocks_200 || 0) + 1,
      }
    }),
  )
}
</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Dashboard</h1>
        <p>Live network posture, devices, and the latest detections.</p>
      </div>
      <div class="actions-row">
        <button class="btn btn--primary" @click="runScan" :disabled="scanning">{{ scanning ? 'Scanning…' : 'Scan Network' }}</button>
        <button class="btn" @click="load" :disabled="loading">{{ loading ? 'Refreshing…' : 'Refresh' }}</button>
      </div>
    </div>

    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>
    <p v-if="scanInfo" class="small" style="margin-top:-6px;color:var(--muted);">
      {{ scanning ? 'Scan in progress' : 'Last scan' }} · {{ scanInfo.progress }} / {{ scanInfo.total }} · {{ scanInfo.status }}
    </p>

    <div class="card-grid" style="grid-template-columns:minmax(0,2fr) minmax(0,1fr);align-items:start;gap:24px;">
      <section class="surface table-card">
        <header class="view-header" style="margin-bottom:8px;">
          <div>
            <h2 style="margin:0;font-size:20px;">Discovered Devices</h2>
            <p class="small" style="margin:4px 0 0;">Known hosts with risk context.</p>
          </div>
          <router-link to="/devices" class="btn btn--ghost">View all</router-link>
        </header>
        <table>
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Name</th>
              <th>Ports · Risk</th>
              <th style="text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in devices" :key="d.ip">
              <td>{{ d.ip }}</td>
              <td>{{ d.name || 'Unknown' }}</td>
              <td>
                <div class="small">Ports: {{ d.open_ports || '—' }}</div>
                <span class="badge" :class="(d.risk || '').toLowerCase()">{{ d.risk || '—' }}</span>
              </td>
              <td style="text-align:right;">
                <router-link to="/banlist" class="btn btn--ghost">Contain</router-link>
              </td>
            </tr>
            <tr v-if="!devices.length">
              <td colspan="4" class="small" style="text-align:center;color:var(--muted);padding:18px;">No devices yet.</td>
            </tr>
          </tbody>
        </table>
      </section>

      <div class="card-grid" style="gap:20px;">
        <section class="surface surface--soft">
          <h2 style="margin:0 0 12px;font-size:20px;">Quick Overview</h2>
          <div class="small" style="margin-bottom:8px;">Total Devices · <span class="mono">{{ devices.length }}</span></div>
          <div class="small" style="margin-bottom:8px;">Unknown Names · <span class="mono">{{ unknownDevices }}</span></div>
          <div class="small" style="margin-bottom:8px;">Alerts Logged · <span class="mono">{{ alertCount }}</span></div>
          <div class="small" style="margin-bottom:8px;">Blocks Recorded · <span class="mono">{{ blockCount }}</span></div>
          <div class="small" style="margin-bottom:8px;">Recent Alerts (24h) · <span class="mono">{{ recent.length }}</span></div>
          <div class="small">Last Scan · <span class="mono">{{ lastScanStr }}</span></div>
        </section>

        <section class="surface surface--soft">
          <h2 style="margin:0 0 12px;font-size:20px;">Recent Alerts</h2>
         <transition-group name="list-fade" tag="ul" class="recent-alerts">
            <li v-for="a in recent" :key="a.id" class="recent-alert">
              <div class="recent-alert__top">
                <span class="recent-alert__ip mono">{{ alertIp(a) }}</span>
                <span class="recent-alert__time mono small">{{ hhmm(a.ts) }}</span>
              </div>
              <div class="recent-alert__label">{{ alertLabel(a) }}</div>
            </li>
          </transition-group>
          <div v-if="!recent.length" class="small" style="color:var(--muted);">No alerts yet.</div>
        </section>
      </div>
    </div>
  </div>
</template>
