<script setup>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';
import { api } from '../api';
const settings = ref({});
const lastLoadedSettings = ref({});
const defaultSettings = ref({});
const err = ref(null);
const msg = ref(null);
const saving = ref(false);
const formReady = ref(false);
const fieldErrors = ref({});
const fieldTouched = ref({});
const showAllErrors = ref(false);
const settingFields = [
  {
    key: 'Signatures.Enable',
    label: 'Signatures.Enable',
    tooltip: 'True: turn rule-based detector on\nFalse: turn rule-based detector off'
  },
  {
    key: 'Logging.LogLevel',
    label: 'Logging.LogLevel',
    tooltip: 'DEBUG: everything - detailed developer messages, useful while diagnosing issues.\nINFO: normal operational messages\nWARNING: unusual conditions that aren’t failures\nERROR: actual failures that prevented something from working\nChooses how chatty the backend logging is. Use INFO for normal use, DEBUG when troubleshooting'
  },
  {
    key: 'Logging.EnableFileLogging',
    label: 'Logging.EnableFileLogging',
    tooltip: 'True: backend also writes logs to a file'
  },
  {
    key: 'Monitoring.AlertThresholds',
    label: 'Monitoring.AlertThresholds',
    tooltip: 'E.g., -0.10, -0.05\nAlerts whose scores are more negative than -0.10 are labeled “High”, between -0.10 and -0.05 are labeled “Medium” and above -0.05 are “Low”'
  },
  {
    key: 'Retention.AlertsDays',
    label: 'Retention.AlertsDays',
    placeholder: 'e.g. 7',
    tooltip: 'How long to keep alerts in the web database.'
  },
  {
    key: 'Retention.BlocksDays',
    label: 'Retention.BlocksDays',
    placeholder: 'e.g. 14',
    tooltip: 'How long to keep blocked or trusted IP records in the web database.'
  }
];
const fieldMap = Object.fromEntries(settingFields.map((field) => [field.key, field]));
// PD-29 ops state
const opsBusy = ref(false);
const opsMsg = ref('');
const themeKey = 'ids.theme';
const theme = ref(localStorage.getItem(themeKey) || document.documentElement.dataset.theme || 'dark');

let errTimer = null;
let msgTimer = null;

function clearErrorMessage() {
  if (errTimer) {
    clearTimeout(errTimer);
    errTimer = null;
  }
  err.value = null;
}

function clearStatusMessage() {
  if (msgTimer) {
    clearTimeout(msgTimer);
    msgTimer = null;
  }
  msg.value = null;
}

function setErrorMessage(message, timeout = 4000) {
  clearErrorMessage();
  clearStatusMessage();
  if (message) {
    err.value = message;
    errTimer = setTimeout(() => {
      err.value = null;
      errTimer = null;
    }, timeout);
  }
}

function setStatusMessage(message, timeout = 4000) {
  clearStatusMessage();
  clearErrorMessage();
  if (message) {
    msg.value = message;
    msgTimer = setTimeout(() => {
      msg.value = null;
      msgTimer = null;
    }, timeout);
  }
}

const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];
const TRUE_LITERALS = new Set(['true', '1', 'yes', 'on']);
const FALSE_LITERALS = new Set(['false', '0', 'no', 'off']);

function asString(value) {
  if (value == null) return '';
  return typeof value === 'string' ? value : String(value);
}

function labelFor(key) {
  return fieldMap[key]?.label || key;
}

function cloneSettings(values = {}) {
  return Object.fromEntries(
    Object.entries(values || {}).map(([key, value]) => [key, asString(value)])
  );
}

function initializeFieldState(values = {}) {
  const errors = {};
  const touched = {};
  for (const { key } of settingFields) {
    errors[key] = null;
    touched[key] = false;
  }
  fieldErrors.value = errors;
  fieldTouched.value = touched;
  showAllErrors.value = false;
  if (values && Object.keys(values).length) {
    fieldErrors.value = collectFieldErrors(values);
  }
}

function normalizeBoolean(key, raw) {
  const label = labelFor(key);
  const text = asString(raw).trim().toLowerCase();
  if (!text) throw new Error(`${label} must be true or false.`);
  if (TRUE_LITERALS.has(text)) return 'true';
  if (FALSE_LITERALS.has(text)) return 'false';
  throw new Error(`${label} must be true or false (for example, "true").`);
}

function normalizeLogLevel(key, raw) {
  const text = asString(raw).trim().toUpperCase();
  if (!text) throw new Error('Log level is required.');
  if (!LOG_LEVELS.includes(text)) {
    throw new Error(`Log level must be one of ${LOG_LEVELS.join(', ')}.`);
  }
  return text;
}

function normalizeAlertThresholds(key, raw) {
  const label = labelFor(key);
  const text = asString(raw).trim();
  if (!text) {
    throw new Error(`${label} must include two numbers like "-0.10, -0.05".`);
  }
  const parts = text.split(',').map((part) => part.trim()).filter(Boolean);
  if (parts.length !== 2) {
    throw new Error(`${label} must include exactly two comma-separated numbers (high, medium).`);
  }
  const hi = Number(parts[0]);
  const med = Number(parts[1]);
  if (!Number.isFinite(hi) || !Number.isFinite(med)) {
    throw new Error(`${label} must be two numbers like "-0.10, -0.05".`);
  }
  if (hi > med) {
    throw new Error(`${label} must have the first value less than or equal to the second.`);
  }
  return `${parts[0]}, ${parts[1]}`;
}

function normalizeRetentionDays(key, raw) {
  const label = labelFor(key);
  const text = asString(raw).trim();
  if (!text) {
    throw new Error(`${label} must be a whole number (0 or greater).`);
  }
  if (!/^\d+$/.test(text)) {
    throw new Error(`${label} must be a whole number (0 or greater).`);
  }
  const value = Number.parseInt(text, 10);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a whole number (0 or greater).`);
  }
  return String(value);
}

const validators = {
  'Signatures.Enable': normalizeBoolean,
  'Logging.EnableFileLogging': normalizeBoolean,
  'Logging.LogLevel': normalizeLogLevel,
  'Monitoring.AlertThresholds': normalizeAlertThresholds,
  'Retention.AlertsDays': normalizeRetentionDays,
  'Retention.BlocksDays': normalizeRetentionDays,
};

function collectFieldErrors(values = {}) {
  const errors = {};
  for (const { key } of settingFields) {
    const validator = validators[key];
    if (!validator) {
      errors[key] = null;
      continue;
    }
    try {
      validator(key, asString(values[key]));
      errors[key] = null;
    } catch (error) {
      errors[key] = error?.message || 'Invalid value.';
    }
  }
  return errors;
}

function validateSettingsPayload(current, { collectErrors = false } = {}) {
  const sanitized = {};
  const errors = {};
  for (const [key, value] of Object.entries(current || {})) {
    sanitized[key] = asString(value);
  }
  for (const [key, validator] of Object.entries(validators)) {
    if (Object.prototype.hasOwnProperty.call(sanitized, key)) {
      try {
        sanitized[key] = validator(key, sanitized[key]);
      } catch (error) {
        if (!collectErrors) {
          throw error;
        }
        errors[key] = error?.message || 'Invalid value.';
      }
    }
  }
  if (collectErrors && Object.keys(errors).length) {
    const fallback = Object.values(errors)[0] || 'Please check the highlighted values.';
    const aggregateError = new Error(fallback);
    aggregateError.fieldErrors = errors;
    throw aggregateError;
  }
  return sanitized;
}

function friendlyErrorMessage(error, fallback) {
  const raw = [error, fallback].find((item) => typeof item === 'string' && item.trim());
  if (!raw) return 'Something went wrong. Please try again.';
  const text = raw.startsWith('Invalid config update:')
    ? raw.slice('Invalid config update:'.length).trim()
    : raw.trim();
  const lowered = text.toLowerCase();
  if (lowered.includes('loglevel') && lowered.includes('one of')) {
    return `Log level must be one of ${LOG_LEVELS.join(', ')}.`;
  }
  if (lowered.includes('alertthresholds') && lowered.includes('two float')) {
    return 'Alert thresholds must be two numbers like "-0.10, -0.05".';
  }
  if (lowered.includes('alertthresholds') && lowered.includes('high<=medium')) {
    return 'Alert thresholds must have the first value less than or equal to the second.';
  }
  if (lowered.includes('not writable')) {
    return 'That setting cannot be changed from this page.';
  }
  return text;
}

function applyTheme(mode) {
  const next = mode === 'light' ? 'light' : 'dark';
  theme.value = next;
  document.documentElement.dataset.theme = next;
  localStorage.setItem(themeKey, next);
}

async function load(){
  try{
    formReady.value = false;
    showAllErrors.value = false;
    clearErrorMessage();
    clearStatusMessage();
    const res = await api.getSettings();
    const incoming = res.settings || {};
    const defaultsRaw = res.defaults || null;
    const normalizedDefaults = defaultsRaw ? cloneSettings(defaultsRaw) : {};
    const normalized = cloneSettings(incoming);
    for (const { key } of settingFields) {
      if (!Object.prototype.hasOwnProperty.call(normalized, key)) {
        normalized[key] = '';
      }
      if (!Object.prototype.hasOwnProperty.call(normalizedDefaults, key)) {
        normalizedDefaults[key] = normalized[key];
      }
    }
    settings.value = cloneSettings(normalized);
    lastLoadedSettings.value = cloneSettings(normalized);
    defaultSettings.value = cloneSettings(normalizedDefaults);
    initializeFieldState(settings.value);
    formReady.value = true;
  }catch(e){ setErrorMessage(friendlyErrorMessage(e?.error, e?.message)); formReady.value = true; }
}
async function save(){
  clearErrorMessage();
  clearStatusMessage();
  let payload;
  try {
    payload = validateSettingsPayload(settings.value, { collectErrors: true });
  } catch (validationError) {
    showAllErrors.value = true;
    const nextErrors = collectFieldErrors(settings.value);
    if (validationError?.fieldErrors) {
      for (const [key, message] of Object.entries(validationError.fieldErrors)) {
        nextErrors[key] = message;
      }
    }
    fieldErrors.value = nextErrors;
    setErrorMessage(validationError?.message || 'Please check the highlighted values.');
    return;
  }
  try{
    saving.value = true;
    const res = await api.putSettings(payload);
    if (res?.ok === false) {
      setErrorMessage(friendlyErrorMessage(res?.error, res?.message));
      return;
    }
    settings.value = cloneSettings(payload);
    lastLoadedSettings.value = cloneSettings(payload);
    initializeFieldState(settings.value);
    setStatusMessage(res?.message || 'Settings saved.');
    showAllErrors.value = false;
  }catch(e){
    setErrorMessage(friendlyErrorMessage(e?.error, e?.message));
  } finally {
    saving.value = false;
  }
}
function resetForm() {
  if (!formReady.value) return;
  clearErrorMessage();
  clearStatusMessage();
  showAllErrors.value = false;
  const source = Object.keys(defaultSettings.value || {}).length
    ? defaultSettings.value
    : lastLoadedSettings.value;
  settings.value = cloneSettings(source);
  initializeFieldState(settings.value);
  setStatusMessage('Settings reset to defaults. Make sure to Save');
}
watch(settings, (newSettings) => {
  if (!formReady.value) return;
  fieldErrors.value = collectFieldErrors(newSettings);
}, { deep: true });

function markFieldTouched(key) {
  if (fieldTouched.value[key]) return;
  fieldTouched.value = {
    ...fieldTouched.value,
    [key]: true,
  };
}
onMounted(() => {
  load();
  applyTheme(theme.value);
});

onBeforeUnmount(() => {
  clearStatusMessage();
  clearErrorMessage();
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
        <button class="btn btn--primary" @click="save" :disabled="saving">{{ saving ? 'Saving…' : 'Save' }}</button>
        <button class="btn btn--ghost" @click="resetForm" :disabled="!formReady">Reset</button>
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
        <label
          v-for="field in settingFields"
          :key="field.key"
          class="setting-field"
        >
          <span class="setting-label">
            {{ field.label }}
            <span
              class="info-tooltip"
              tabindex="0"
              role="img"
              aria-label="More information"
              :data-tooltip="field.tooltip"
            >?
            </span>
          </span>
          <input
            class="input"
            :placeholder="field.placeholder"
            v-model="settings[field.key]"
            :class="{ 'input--error': (showAllErrors || fieldTouched[field.key]) && fieldErrors[field.key] }"
            :aria-invalid="(showAllErrors || fieldTouched[field.key]) && !!fieldErrors[field.key]"
            @input="markFieldTouched(field.key)"
          />
          <div
            v-if="(showAllErrors || fieldTouched[field.key]) && fieldErrors[field.key]"
            class="input-error"
            role="alert"
          >
            {{ fieldErrors[field.key] }}
          </div>
        </label>
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
