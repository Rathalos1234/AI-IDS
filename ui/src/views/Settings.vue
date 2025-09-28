<script setup>
import { ref, onMounted } from 'vue';
import { api } from '../api';
const settings = ref({}); const err = ref(null); const msg = ref(null);

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
    </div>

    <div style="margin-top:12px;">
      <button class="btn" @click="save">Save</button>
      <button class="btn" style="margin-left:8px;" @click="load">Reset</button>
    </div>
  </div>
</template>
