<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { api } from '../api';
const router = useRouter();
const route = useRoute();
const navItems = [
  { to: '/dashboard', label: 'Dashboard', hint: 'Overview' },
  { to: '/alerts', label: 'Alerts', hint: 'Filtered feed' },
  { to: '/devices', label: 'Devices', hint: 'Inventory' },
  { to: '/logs', label: 'Log History', hint: 'Signal feed' },
  { to: '/banlist', label: 'Ban List', hint: 'Containment' },
  { to: '/settings', label: 'Settings', hint: 'Preferences' },
];

// PD-29: health badge
const apiHealthy = ref(true);
const loggingOut = ref(false);
let healthTimer = null;
async function checkHealth () {
  try {
    const h = await (api.health ? api.health() : fetch('/healthz').then(r=>r.json()));
    apiHealthy.value = !!h?.ok;
  } catch { apiHealthy.value = false; }
}
const isActive = (path) => route.path === path;

function go (path) {
  if (route.path !== path) router.push(path);
}

async function logout () {
  if (loggingOut.value) return;
  loggingOut.value = true;
  try {
    if (typeof api.logout === 'function') {
      await api.logout();
    }
  } catch (err) {
    console.error('logout failed', err);
  } finally {
    loggingOut.value = false;
    router.push('/auth');
  }
}
onMounted(async () => {
  await checkHealth();
  healthTimer = setInterval(checkHealth, 30000); // 30s
});
onBeforeUnmount(() => { if (healthTimer) clearInterval(healthTimer); });
const statusTitle = computed(() => apiHealthy.value ? 'API healthy' : 'API unreachable');
</script>

<template>
  <div class="layout-shell fade-in">
    <div class="layout-grid">
      <aside class="surface surface--soft sidebar">
        <div class="brand">
          <span>AI-Powered IDS</span>
          <span :title="statusTitle" :class="['status-dot', apiHealthy ? '' : 'off']"></span>
        </div>
        <nav class="nav">
          <button
            v-for="item in navItems"
            :key="item.to"
            class="nav-link"
            :class="{ active: isActive(item.to) }"
            @click="go(item.to)"
          >
            <span>{{ item.label }}</span>
            <span class="small">{{ item.hint }}</span>
          </button>
          <button class="nav-link" @click="logout" :disabled="loggingOut">
            <span>Log Out</span>
            <span class="small">Goodbye</span>
          </button>
        </nav>
      </aside>

      <main class="main-panel">
        <router-view />
      </main>
    </div>
  </div>
</template>
