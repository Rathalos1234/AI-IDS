<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api';

const router = useRouter();
const username = ref('admin');
const password = ref('admin123');
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
  <div style="display:grid;place-items:center;min-height:100vh;">
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(460px,92vw);">
      <h2 style="margin:0 0 6px;text-align:center;">Login</h2>
      <p style="color:var(--muted);text-align:center;margin:0 0 14px;">Sign In To Your Account</p>
      <div class="stack" style="display:flex;flex-direction:column;gap:10px;">
        <input class="input" v-model="username" placeholder="Username" />
        <input class="input" v-model="password" type="password" placeholder="Password" />
        <button class="btn-toggle" @click="login"><span class="swap"><span class="front">Login</span><span class="back">Go</span></span></button>
      </div>
      <p class="small" style="color:var(--muted);margin-top:10px;">Forgot Password? <a>Click to reset</a></p>
      <p v-if="msg" class="small" style="color:#27c383;">{{ msg }}</p>
      <p v-if="err" class="small" style="color:#ff7070;">{{ err }}</p>
    </div>
  </div>
</template>
