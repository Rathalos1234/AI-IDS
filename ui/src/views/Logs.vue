<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue';
import { api } from '../api';
import { subscribeToEvents } from '../eventStream';

const items = ref([]);
const nextCursor = ref(null);
const limit = 50;
const err = ref(null);
const loading = ref(false);
const stopFns = [];
// Track IDs we've already rendered to avoid accidental duplicates.
const seenIds = new Set();

function parseLabel(alert) {
  const label = alert?.label || '';
  const match = String(label).match(/^(.*)\s+score=([-+]?\d*\.?\d+(?:e[-+]?\d+)?)/i);
  if (match) {
    return {
      ...alert,
      label: match[1].trim(),
      score: Number(match[2]),
    };
  }
  return {
    ...alert,
    score: typeof alert?.score === 'number' ? alert.score : null,
  };
}

const formatScore = (score) => (typeof score === 'number' && score === score ? score.toFixed(3) : '—');



async function load(cursor = null) {
  try {
    loading.value = true;
    err.value = null;
    const data = await api.alerts(limit, cursor);

    // Helper: map + de-dup by id
    const consume = (arr) => {
      const mapped = arr.map(parseLabel);
      const fresh = mapped.filter(r => r && r.id && !seenIds.has(r.id));
      fresh.forEach(r => seenIds.add(r.id));
      return fresh;
    };

    if (!cursor) seenIds.clear(); // fresh load resets de-dup set

    if (Array.isArray(data)) {
      const fresh = consume(data);
      items.value = cursor ? items.value.concat(fresh) : fresh;
      nextCursor.value = fresh.length ? fresh[fresh.length - 1].ts : null;
    } else {
      const page = Array.isArray(data.items) ? data.items : [];
      const fresh = consume(page);
      items.value = cursor ? items.value.concat(fresh) : fresh;
      nextCursor.value = data.next_cursor || (fresh.length ? fresh[fresh.length - 1].ts : null);
    }
  } catch (e) {
    err.value = e?.error || e?.message || 'Failed to load log history';
  } finally {
    loading.value = false;
  }
}

function upsertAlert(alert) {
  if (!alert || !alert.id) return;
  const normalized = parseLabel(alert);
  const existingIdx = items.value.findIndex((row) => row.id === alert.id);
  if (existingIdx !== -1) {
    items.value.splice(existingIdx, 1);
  }
    items.value.unshift(normalized);
    if (items.value.length > 200) items.value.splice(200);
}

function startRealtime() {
  stopFns.push(
    subscribeToEvents('alert', (payload) => {
      upsertAlert(payload);
    }),
  );
}

onMounted(async () => {
  await load();
  startRealtime();
});
onBeforeUnmount(() => {
  while (stopFns.length) {
    const off = stopFns.pop();
    try { if (typeof off === 'function') off(); } catch (e) { console.error(e); }
  }
});

async function exportHistory(format) {
  try {
    await api.exportLogs?.({ type: 'alert' }, format);
  } catch (e) {
    err.value = e?.error || e?.message || 'Export failed';
  }
}

</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Log History</h1>
        <p>Chronological list of recent alert events.</p>
      </div>
      <div class="actions-row">
        <button class="btn" @click="exportHistory('csv')">Export CSV</button>
        <button class="btn" @click="exportHistory('json')">Export JSON</button>
      </div>
    </div>
    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>

    <section class="surface table-card">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>Time</th>
            <th>IP</th>
            <th>Description</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in items" :key="a.id">
            <td>{{ (a.ts||'').split('T')[0] }}</td>
            <td>{{ (a.ts||'').split('T')[1]?.slice(0,5) }}</td>
            <td>{{ a.src_ip }}</td>
            <td>{{ a.label }}</td>
            <td>{{ formatScore(a.score) }}</td>
          </tr>
          <tr v-if="!items.length">
           <td colspan="5" class="small" style="text-align:center;color:var(--muted);padding:18px;">No events yet.</td>
          </tr>
        </tbody>
      </table>
    </section>
    <div class="actions-row" style="justify-content:flex-end;margin-top:16px;">
      <button class="btn" :disabled="!nextCursor || loading" @click="load(nextCursor)">
        {{ loading ? 'Loading…' : 'Load more' }}
      </button>
    </div>
  </div>
</template>
