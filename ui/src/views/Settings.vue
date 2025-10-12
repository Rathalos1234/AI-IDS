<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const settings = ref({}); const err = ref(null); const msg = ref(null);
// PD-29 ops state
const opsBusy = ref(false);
const opsMsg = ref('');


async function load(){
  try{ err.value=null; msg.value=null;
    const res = await api.getSettings();
    settings.value = res.settings || {};
  }catch(e){ err.value = e?.error || e?.message; }
}
async function save(){
  try{ err.value=null; msg.value=null;
    const res = await api.putSettings(settings.value);
    msg.value = res.ok !== false ? 'Saved' : (res.message || 'Save failed');
  }catch(e){ err.value = e?.error || e?.message; }
}
onMounted(load);

// ---- PD-29: Operations actions ----
async function onRunRetention () {
  try {
    opsBusy.value = true; opsMsg.value = '';
    const r = await (api.runRetention ? api.runRetention() : fetch('/api/retention/run', {method:'POST', credentials:'include'}).then(r=>r.json()));
    const a = r?.deleted?.alerts ?? 0, b = r?.deleted?.blocks ?? 0;
    opsMsg.value = r?.ok ? `Retention done — alerts: ${a}, blocks: ${b}` : (r?.error || 'Retention failed');
  } catch (e) {
    opsMsg.value = `Retention failed: ${e?.message||'error'}`;
  } finally { opsBusy.value = false; }
}

async function onBackup () {
  try {
    opsBusy.value = true; opsMsg.value = '';
    const res = await (api.downloadDbBackup ? api.downloadDbBackup() : fetch('/api/backup/db', {credentials:'include'}).then(r=>r.blob()));
    const url = URL.createObjectURL(res);
    const a = document.createElement('a'); a.href = url; a.download = 'ids_web_backup.sqlite'; a.click(); URL.revokeObjectURL(url);
    opsMsg.value = 'Backup downloaded.';
  } catch (e) {
    opsMsg.value = `Backup failed: ${e?.message||'error'}`;
  } finally { opsBusy.value = false; }
}

async function onHealth () {
  try {
    opsBusy.value = true; opsMsg.value = '';
    const h = await (api.health ? api.health() : fetch('/healthz').then(r=>r.json()));
    const up = h?.uptime_sec ?? 0;
    opsMsg.value = h?.ok ? `Healthy • uptime ${up}s` : 'Unhealthy';
  } catch { opsMsg.value = 'Health check failed'; }
  finally { opsBusy.value = false; }
}
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Settings</h1>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>
    <div v-if="msg" style="color:#27c383;margin-bottom:12px;">{{ msg }}</div>

    <div class="stack" style="display:flex;flex-direction:column;gap:10px;">
      <label>Signatures.Enable <input class="input" v-model="settings['Signatures.Enable']"/></label>
      <label>Logging.LogLevel <input class="input" v-model="settings['Logging.LogLevel']"/></label>
      <label>Logging.EnableFileLogging <input class="input" v-model="settings['Logging.EnableFileLogging']"/></label>
      <label>Monitoring.AlertThresholds <input class="input" v-model="settings['Monitoring.AlertThresholds']"/></label>
      <!-- PD-29: optional retention keys if you set them via /api/settings -->
      <label>Retention.AlertsDays <input class="input" v-model="settings['Retention.AlertsDays']" placeholder="e.g. 7"/></label>
      <label>Retention.BlocksDays <input class="input" v-model="settings['Retention.BlocksDays']" placeholder="e.g. 14"/></label>
    </div>

    <div style="margin-top:12px;">
      <button class="btn" @click="save">Save</button>
      <button class="btn" style="margin-left:8px;" @click="load">Reset</button>
    </div>


    <!-- PD-29: Operations -->
    <section class="card" style="margin-top:16px;">
      <div class="card-header"><h3>Operations</h3></div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn" @click="onRunRetention" :disabled="opsBusy">{{ opsBusy ? 'Running…' : 'Run retention now' }}</button>
        <button class="btn" @click="onBackup" :disabled="opsBusy">Download DB backup</button>
        <button class="btn" @click="onHealth" :disabled="opsBusy">Health check</button>
      </div>
      <div class="small" style="margin-top:8px; color: var(--muted);" v-if="opsMsg">{{ opsMsg }}</div>
    </section>
  </div>
</template>
