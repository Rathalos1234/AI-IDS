<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api';

const router = useRouter();
const username = ref('admin');
const password = ref('admin');
const msg = ref(null);
const err = ref(null);

async function login() {
  msg.value = err.value = null;
  try {
    const res = await api.login(username.value, password.value);
    msg.value = `Welcome ${res.user || username.value}`;
    setTimeout(()=>router.push('/dashboard'), 400);
  } catch(e) {
    err.value = e?.error || e?.message || 'Login failed';
  }
}
</script>

<template>
  <div class="hero">
    <div class="form-card">
      <h2>Login</h2>
      <p class="small">Sign in to continue to the dashboard.</p>
      <div class="stack">
        <input class="input" v-model="username" placeholder="Username" />
        <input class="input" v-model="password" type="password" placeholder="Password" />
        <button class="btn btn--primary" @click="login">{{ msg ? 'Redirecting…' : 'Login' }}</button>
      </div>
      <p class="small" style="color:var(--muted);margin-top:10px;">Forgot Password? <a>Click to reset</a></p>
      <div v-if="msg" class="alert-banner success" style="margin-top:12px;">{{ msg }}</div>
      <div v-if="err" class="alert-banner" style="margin-top:12px;">{{ err }}</div>
    </div>
  </div>
</template>
