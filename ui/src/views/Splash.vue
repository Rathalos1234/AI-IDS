<script setup>
import { useRouter } from 'vue-router';
const router = useRouter();
</script>

<template>
  <div style="display:grid;place-items:center;min-height:100vh;">
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:740px;width:92%;">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:center;">
        <div>
          <h1 style="margin:0 0 8px;">AI-Powered Intrusion<br/>Detection System</h1>
          <p style="color:var(--muted);margin:0;">Secure your network with anomaly detection & signatures.</p>
        </div>
        <div style="display:flex;flex-direction:column;gap:12px;align-items:flex-start;">
          <button class="btn-toggle" @click="router.push('/auth')"><span class="swap"><span class="front">Login</span><span class="back">Sign In</span></span></button>
          <button class="btn-toggle" @click="router.push('/auth')"><span class="swap"><span class="front">Create Account</span><span class="back">Register</span></span></button>
        </div>
      </div>
    </div>
  </div>
</template>
