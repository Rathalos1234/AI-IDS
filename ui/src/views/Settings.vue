<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const settings = ref({}); const err = ref(null); const msg = ref(null);
// PD-29 ops state
const opsBusy = ref(false);
const opsMsg = ref('');
const themeKey = 'ids.theme';
const theme = ref(localStorage.getItem(themeKey) || document.documentElement.dataset.theme || 'dark');

function applyTheme(mode) {
  const next = mode === 'light' ? 'light' : 'dark';
  theme.value = next;
  document.documentElement.dataset.theme = next;
  localStorage.setItem(themeKey, next);
}

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
onMounted(() => {
  load();
  applyTheme(theme.value);
});

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

async function onResetAll () {
  if (!window.confirm('This will remove alerts, blocks, trusted IPs, and devices. Continue?')) return;
  try {
    opsBusy.value = true; opsMsg.value = '';
    const res = await (api.resetAllData
      ? api.resetAllData()
      : fetch('/api/ops/reset', { method: 'POST', credentials: 'include' }).then(r => r.json()));
    if (res?.ok) {
      const cleared = res.cleared || {};
      const parts = Object.entries(cleared).map(([k, v]) => `${k}: ${v}`);
      opsMsg.value = parts.length ? `Reset complete (${parts.join(', ')})` : 'Reset complete.';
    } else {
      opsMsg.value = res?.error ? `Reset failed: ${res.error}` : 'Reset failed';
    }
  } catch (e) {
    opsMsg.value = `Reset failed: ${e?.message || 'error'}`;
  } finally { opsBusy.value = false; }
}

</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Settings</h1>
        <p>Adjust monitoring thresholds, logging, and maintenance operations.</p>
      </div>
      <div class="actions-row">
        <button class="btn btn--primary" @click="save">Save</button>
        <button class="btn btn--ghost" @click="load">Reset</button>
      </div>
    </div>

    <section class="surface surface--soft" style="margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <div>
        <h3 style="margin:0 0 4px;">Appearance</h3>
        <p class="small" style="margin:0;">Toggle between dark and light mode.</p>
      </div>
      <div class="actions-row">
        <button class="btn" :class="{ active: theme==='dark' }" @click="applyTheme('dark')">Dark</button>
        <button class="btn" :class="{ active: theme==='light' }" @click="applyTheme('light')">Light</button>
      </div>
    </section>

    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>
    <div v-if="msg" class="alert-banner success" style="margin-bottom:16px;">{{ msg }}</div>

    <section class="surface surface--soft" style="margin-bottom:20px;">
      <div class="stack">
        <label>Signatures.Enable <input class="input" v-model="settings['Signatures.Enable']"/></label>
        <label>Logging.LogLevel <input class="input" v-model="settings['Logging.LogLevel']"/></label>
        <label>Logging.EnableFileLogging <input class="input" v-model="settings['Logging.EnableFileLogging']"/></label>
        <label>Monitoring.AlertThresholds <input class="input" v-model="settings['Monitoring.AlertThresholds']"/></label>
        <label>Retention.AlertsDays <input class="input" v-model="settings['Retention.AlertsDays']" placeholder="e.g. 7"/></label>
        <label>Retention.BlocksDays <input class="input" v-model="settings['Retention.BlocksDays']" placeholder="e.g. 14"/></label>
      </div>
    </section>

    <section class="surface surface--soft">
      <h3 style="margin:0 0 12px;">Operations</h3>
      <div class="actions-row" style="flex-wrap:wrap; gap:12px;">
        <button class="btn btn--primary" @click="onRunRetention" :disabled="opsBusy">{{ opsBusy ? 'Running…' : 'Run retention now' }}</button>
        <button class="btn" @click="onBackup" :disabled="opsBusy">Download DB backup</button>
        <button class="btn btn--danger" @click="onResetAll" :disabled="opsBusy">Reset data</button>
        <button class="btn" @click="onHealth" :disabled="opsBusy">Health check</button>
      </div>
      <div class="small" style="margin-top:12px; color: var(--muted);" v-if="opsMsg">{{ opsMsg }}</div>
    </section>
  </div>
</template>
