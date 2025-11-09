<script setup>
import { useRouter, RouterLink } from 'vue-router';
const router = useRouter();
</script>

<template>
  <div class="hero">
    <div class="hero-card">
      <div class="hero-grid">
        <div>
          <h1 style="margin:0 0 12px;">AI-Powered Intrusion<br/>Detection System</h1>
          <p class="small" style="margin:0;">Secure your network with anomaly detection, signatures, and one-click containment.</p>
        </div>
        <div style="display:flex;flex-direction:column;gap:12px;align-items:flex-start;">
          <button class="btn btn--primary" @click="router.push('/auth')">Login</button>
          <RouterLink class="btn btn--ghost" to="/signup">Create Account</RouterLink>
        </div>
      </div>
    </div>
  </div>
</template>
