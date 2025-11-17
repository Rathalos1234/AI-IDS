<script setup>
import { useRouter, RouterLink } from 'vue-router';
const router = useRouter();
</script>

<template>
  <div class="hero">
    <div class="hero-card">
      <div class="hero-grid">
        <div class="hero-copy">
          <h1>AI-Powered Intrusion<br/>Detection System</h1>
          <p class="small hero-subtitle">
            Secure your network with anomaly detection, signatures, and one-click containment.
          </p>
        </div>
        <div class="hero-actions">
          <button class="btn btn--primary" @click="router.push('/auth')">Login</button>
          <RouterLink class="btn btn--ghost" to="/signup">Create Account</RouterLink>
        </div>
      </div>
    </div>
  </div>
</template>
