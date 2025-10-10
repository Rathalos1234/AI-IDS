<script setup>
import { ref, onMounted } from 'vue'
// import { fetchDevices } from '../api'  // or idsApi.getDevices() if you use the aggregator
// const items = ref([]), err = ref(null), loading = ref(false)
import { api } from '../api'

const items = ref([])
const err = ref(null)
const loading = ref(false)

const formatTs = (value) => {
  if (!value) return '—'
  try {
    const dt = new Date(value)
    if (Number.isNaN(dt.getTime())) return value
    return dt.toLocaleString()
  } catch (e) {
    return value
  }
}


async function load(){
  try{
    loading.value = true
    err.value=null
    const data = await (api.devices ? api.devices() : [])
    const list = Array.isArray(data) ? data : (data.items || [])
    items.value = list
  }catch(e){
    err.value = e?.error || e?.message || 'Failed to load devices'
  }
  finally{
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Devices</h1>
        <p>Observed network endpoints with discovery timestamps.</p>
      </div>
      <div class="actions-row">
        <button class="btn" @click="load" :disabled="loading">{{ loading ? 'Refreshing…' : 'Refresh' }}</button>
      </div>
    </div>

    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>

    <section class="surface table-card">
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in items" :key="d.ip">
            <td>{{ d.ip }}</td>
            <td>{{ formatTs(d.first_seen) }}</td>
            <td>{{ formatTs(d.last_seen) }}</td>
            <td>{{ d.name || '—' }}</td>
          </tr>
          <tr v-if="!items.length">
            <td colspan="4" class="small" style="text-align:center;color:var(--muted);padding:18px;">No devices yet.</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
