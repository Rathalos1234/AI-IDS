<script setup>
import { useRouter } from 'vue-router';
const router = useRouter();
</script>

<template>
  <div style="max-width:1200px;margin:34px auto;padding:0 16px;">
    <div style="display:grid;grid-template-columns:240px 1fr;gap:16px;">
      <aside style="background:var(--panel);padding:18px;border:1px solid var(--border);border-radius:12px;">
        <div style="font-weight:800;font-size:18px;margin-bottom:12px;">AI-Powered IDS</div>
        <nav class="stack" style="display:flex;flex-direction:column;gap:10px;">
          <button class="btn-toggle" @click="router.push('/dashboard')"><span class="swap"><span class="front">Dashboard</span><span class="back">Open</span></span></button>
          <button class="btn-toggle" @click="router.push('/alerts')"><span class="swap"><span class="front">Alerts</span><span class="back">Open</span></span></button>
          <button class="btn-toggle" @click="router.push('/logs')"><span class="swap"><span class="front">Log History</span><span class="back">Open</span></span></button>
          <button class="btn-toggle" @click="router.push('/banlist')"><span class="swap"><span class="front">Ban List</span><span class="back">Open</span></span></button>
          <button class="btn-toggle" @click="router.push('/settings')"><span class="swap"><span class="front">Settings</span><span class="back">Open</span></span></button>
          <button class="btn-toggle" @click="router.push('/auth')"><span class="swap"><span class="front">Log Out</span><span class="back">Bye</span></span></button>
        </nav>
      </aside>

      <main style="background:var(--panel);padding:18px;border:1px solid var(--border);border-radius:12px;">
        <router-view />
      </main>
    </div>
  </div>
</template>
