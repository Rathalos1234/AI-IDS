<template>
  <div class="page">
    <header class="topbar">
      <div class="brand">AI-IDS</div>
      <div class="actions">
        <button @click="refresh" :disabled="loading">{{ loading ? 'Refreshing…' : 'Refresh' }}</button>
      </div>
    </header>

    <main class="container">
      <section class="stats">
        <div class="card">
          <div class="stat-title">Alerts</div>
          <div class="stat-value">{{ alerts.length }}</div>
        </div>
        <div class="card">
          <div class="stat-title">Blocked IPs</div>
          <div class="stat-value">{{ blocks.filter(b => b.action==='block').length }}</div>
        </div>
        <div class="card">
          <div class="stat-title">Last Update</div>
          <div class="stat-value small">{{ lastUpdated || '—' }}</div>
        </div>
      </section>

      <section class="blockbox card">
        <h3>Quick Block / Unblock</h3>
        <form @submit.prevent="onBlock">
          <input v-model.trim="ip" placeholder="IP address e.g. 192.168.1.10" />
          <button type="submit">Block</button>
          <button type="button" class="secondary" @click="onUnblock">Unblock</button>
        </form>
      </section>

      <div class="grid">
        <section class="card">
          <div class="card-header">
            <h3>Recent Alerts</h3>
            <input v-model.trim="q" placeholder="Filter by IP/label…" />
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Time</th><th>Src IP</th><th>Label</th><th>Severity</th><th>Kind</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in filteredAlerts" :key="a.id">
                  <td>{{ a.ts }}</td>
                  <td><a href="#" @click.prevent="ip = a.src_ip">{{ a.src_ip }}</a></td>
                  <td>{{ a.label }}</td>
                  <td><span :class="['badge', 'sev-' + (a.severity||'').toString().toLowerCase()]">{{ a.severity }}</span></td>
                  <td>{{ a.kind }}</td>
                </tr>
                <tr v-if="!filteredAlerts.length">
                  <td colspan="5" class="muted">No alerts.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <div class="card-header">
            <h3>Blocklist Activity</h3>
          </div>
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr><th>Time</th><th>IP</th><th>Action</th></tr>
              </thead>
              <tbody>
                <tr v-for="b in blocks" :key="b.id">
                  <td>{{ b.ts }}</td>
                  <td><a href="#" @click.prevent="ip = b.ip">{{ b.ip }}</a></td>
                  <td>
                    <button
                      type="button"
                      class="btn-toggle"
                      :data-state="b.action"
                      @click="toggleBlock(b)"
                      :aria-label="b.action === 'block' ? `Unblock ${b.ip}` : `Block ${b.ip}`"
                    >
                      <span class="swap">
                        <span class="front">{{ b.action === 'block' ? 'blocked' : 'unblocked' }}</span>
                        <span class="back">{{ b.action === 'block' ? 'unblock' : 'block' }}</span>
                      </span>
                    </button>
                  </td>
                </tr>
                <tr v-if="!blocks.length">
                  <td colspan="3" class="muted">No blocklist activity.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>

    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { fetchAlerts, fetchBlocks, blockIp, unblockIp } from './api.js'

const alerts = ref([])
const blocks = ref([])
const ip = ref('')
const q = ref('')
const loading = ref(false)
const lastUpdated = ref('')
const toast = ref('')

const filteredAlerts = computed(() => {
  const t = q.value.toLowerCase()
  if (!t) return alerts.value
  return alerts.value.filter(a =>
    (a.src_ip || '').toLowerCase().includes(t) ||
    (a.label || '').toLowerCase().includes(t) ||
    (a.kind || '').toLowerCase().includes(t)
  )
})

function showToast(msg) {
  toast.value = msg
  setTimeout(() => { toast.value = '' }, 2000)
}

async function load() {
  loading.value = true
  try {
    const [a, b] = await Promise.all([fetchAlerts(100), fetchBlocks(100)])
    alerts.value = Array.isArray(a) ? a : []
    blocks.value = Array.isArray(b) ? b : []
    lastUpdated.value = new Date().toLocaleString()
  } catch (e) {
    showToast('Failed to load data')
    console.error(e)
  } finally {
    loading.value = false
  }
}

async function toggleBlock(b) {
  try {
    if (b.action === 'block') {
      await unblockIp(b.ip);
      showToast(`Unblocked ${b.ip}`);
    } else {
      await blockIp(b.ip);
      showToast(`Blocked ${b.ip}`);
    }
    await load();
  } catch (e) {
    showToast('Action failed');
    console.error(e);
  }
}

async function onBlock() {
  if (!ip.value) return
  try {
    await blockIp(ip.value)
    showToast(`Blocked ${ip.value}`)
    ip.value = ''
    await load()
  } catch (e) {
    showToast('Block failed')
    console.error(e)
  }
}
async function onUnblock() {
  if (!ip.value) return
  try {
    await unblockIp(ip.value)
    showToast(`Unblocked ${ip.value}`)
    ip.value = ''
    await load()
  } catch (e) {
    showToast('Unblock failed')
    console.error(e)
  }
}

function refresh(){ load() }

onMounted(() => { load(); setInterval(load, 5000) })
</script>

<style scoped>
.page { min-height: 100vh; background: var(--bg); color: var(--fg); }
.topbar { position: sticky; top:0; z-index:5; backdrop-filter: blur(6px); background: color-mix(in lab, var(--bg), transparent 20%); border-bottom: 1px solid var(--border); padding: 0.75rem 1rem; display:flex; align-items:center; justify-content:space-between; }
.brand { font-weight: 700; letter-spacing: .3px; }
.container { max-width: 1200px; margin: 1.25rem auto; padding: 0 1rem; }
.stats { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 1rem; margin-bottom: 1rem; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 1rem; box-shadow: 0 1px 0 rgba(0,0,0,.05); }
.card-header { display:flex; align-items:center; justify-content:space-between; gap:.75rem; margin-bottom:.5rem; }
.card-header input { max-width: 220px; }
.grid { display:grid; grid-template-columns: 1fr 1fr; gap:1rem; }
.blockbox form { display:flex; gap:.5rem; }
.blockbox + .grid { margin-top: 1rem; }
.blockbox .hint { margin:.5rem 0 0; color: var(--muted); font-size:.85rem; }

input { border:1px solid var(--border); border-radius:10px; background: var(--input); color: var(--fg); padding:.6rem .8rem; outline:none; width: 100%; }
button { border:1px solid var(--border); border-radius: 10px; background: var(--btn); padding:.6rem .9rem; cursor:pointer; }
button:hover { filter: brightness(1.05); }
button.secondary { background: var(--panel); }

.table-wrap { overflow:auto; max-height: 420px; }
.table { width:100%; border-collapse: collapse; }
.table th, .table td { text-align:left; padding:.6rem .7rem; border-bottom:1px solid var(--border); }
.table thead th { position: sticky; top: 0; background: var(--panel); z-index:1; }
.table tbody tr:hover { background: color-mix(in lab, var(--panel), var(--fg) 3%); }
.muted { color: var(--muted); text-align: center; }

.badge { display:inline-block; padding:.2rem .5rem; border-radius:999px; border:1px solid var(--border); font-size:.8rem; text-transform: capitalize; }
.sev-low { background:#2e7d32; color:white; border-color:#2e7d32; }
.sev-medium { background:#ed6c02; color:white; border-color:#ed6c02; }
.sev-high, .sev-critical { background:#d32f2f; color:white; border-color:#d32f2f; }

.stat-title { color: var(--muted); font-size:.9rem; margin-bottom:.25rem; }
.stat-value { font-size:1.6rem; font-weight:700; }
.stat-value.small { font-size:1rem; font-weight:600; }

.toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: var(--panel); border:1px solid var(--border); padding:.6rem .9rem; border-radius:12px; box-shadow: 0 6px 28px rgba(0,0,0,.20); }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr; } }
</style>
