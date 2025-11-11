<script setup>
import { ref, reactive, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../api';

const props = defineProps({
  mode: { type: String, default: 'login' },
});

const router = useRouter();
const route = useRoute();
const mode = ref('login');
const msg = ref(null);
const err = ref(null);
const loading = ref(false);

const loginForm = reactive({ username: 'admin', password: 'admin' });
const registerForm = reactive({ username: '', password: '', confirm: '' });
const resetForm = reactive({ username: '', password: '', confirm: '' });

const canRegister = computed(() => typeof api.register === 'function');
const canReset = computed(() => typeof api.resetPassword === 'function');

function resolveMode() {
  const qMode = typeof route.query.mode === 'string' ? route.query.mode : '';
  if (qMode) return qMode;
  if (route.path === '/signup') return 'register';
  if (route.path === '/reset') return 'reset';
  if (props.mode) return props.mode;
  return 'login';
}

mode.value = resolveMode();

watch(
  () => [route.path, route.query.mode, props.mode],
  () => {
    const next = resolveMode();
    if (next !== mode.value) {
      mode.value = next;
    }
  },
);

watch(mode, () => {
  msg.value = null;
  err.value = null;
  const username = loginForm.username.trim();
  const password = loginForm.password;
  if (!username || !password) {
    err.value = 'Username and password are required.';
    return;
  }
  loginForm.username = username;
  loading.value = false;
});

const title = computed(() => {
  if (mode.value === 'register') return 'Create Account';
  if (mode.value === 'reset') return 'Reset Password';
  return 'Login';
});

const subtitle = computed(() => {
  if (mode.value === 'register') return 'Set up a new administrator account.';
  if (mode.value === 'reset') return 'Choose a new password for your account.';
  return 'Sign in to continue to the dashboard.';
});

const primaryLabel = computed(() => {
  if (mode.value === 'register') return loading.value ? 'Creating…' : 'Create Account';
  if (mode.value === 'reset') return loading.value ? 'Updating…' : 'Reset Password';
  return loading.value ? 'Signing in…' : 'Login';
});

function friendlyAuthError(error, fallback, defaultMessage = 'Something went wrong.') {
  const map = {
    invalid: 'The username or password is incorrect.',
    locked: 'This account is locked. Please try again later.',
    missing: 'Username and password are required.',
    'missing credentials': 'Username and password are required.',
    user_exists: 'That username is already taken.',
    username_short: 'Username must be at least 3 characters long.',
    password_short: 'Password must be at least 6 characters long.',
    unknown_user: 'We could not find that account.',
  };
  if (error && map[error]) return map[error];
  if (fallback && map[fallback]) return map[fallback];
  if (typeof fallback === 'string' && fallback) {
    const normalized = fallback.toLowerCase();
    if (normalized.includes('is not defined') || normalized.includes('referenceerror')) {
      return defaultMessage;
    }
    return fallback;
  }
  return defaultMessage;
}

function switchMode(next) {
  if (next === 'register') {
    if (!canRegister.value) return;
    if (route.path !== '/signup') {
      router.push('/signup');
    } else {
      mode.value = 'register';
    }
    return;
  }
  if (next === 'reset') {
    if (!canReset.value) return;
    if (route.path !== '/reset') {
      router.push('/reset');
    } else {
      mode.value = 'reset';
    }
    return;
  }
  if (route.path !== '/auth' || route.query.mode) {
    router.push('/auth');
  } else {
    mode.value = 'login';
  }
}

const goHome = () => router.push('/');

async function submitLogin() {
  if (typeof api.login !== 'function') {
    err.value = 'Login is not available.';
    return;
  }
  msg.value = null;
  err.value = null;
  loading.value = true;
  try {
    const res = await api.login(loginForm.username, loginForm.password);
    msg.value = `Welcome ${res.user || loginForm.username}! Redirecting…`;
    loginForm.password = '';
    setTimeout(() => router.push('/dashboard'), 400);
  } catch (e) {
    err.value = friendlyAuthError(e?.error, e?.message, 'Login failed.');
  } finally {
    loading.value = false;
  }
}

async function submitRegister() {
  if (!canRegister.value) {
    err.value = 'Registration is not available.';
    return;
  }
  msg.value = null;
  err.value = null;
  const username = registerForm.username.trim();
  const password = registerForm.password;
  if (!username || !password) {
    err.value = 'Username and password are required.';
    return;
  }
  if (password !== registerForm.confirm) {
    err.value = 'Passwords do not match.';
    return;
  }
  if (password.length < 6) {
    err.value = 'Password must be at least 6 characters long.';
    return;
  }
  loading.value = true;
  try {
    const res = await api.register(username, password);
    registerForm.password = '';
    registerForm.confirm = '';
    msg.value = `Welcome ${res.user || username}! Redirecting…`;
    loginForm.username = username;
    loginForm.password = '';
    if (res?.token) {
      setTimeout(() => router.push('/dashboard'), 400);
    } else {
      setTimeout(() => switchMode('login'), 800);
    }
  } catch (e) {
    err.value = friendlyAuthError(e?.error, e?.message, 'Unable to create account.');
  } finally {
    loading.value = false;
  }
}

async function submitReset() {
  if (!canReset.value) {
    err.value = 'Password reset is not available.';
    return;
  }
  msg.value = null;
  err.value = null;
  const username = resetForm.username.trim();
  const password = resetForm.password;
  if (!username || !password) {
    err.value = 'Username and a new password are required.';
    return;
  }
  if (password !== resetForm.confirm) {
    err.value = 'Passwords do not match.';
    return;
  }
  if (password.length < 6) {
    err.value = 'Password must be at least 6 characters long.';
    return;
  }
  loading.value = true;
  try {
    await api.resetPassword(username, password);
    resetForm.password = '';
    resetForm.confirm = '';
    msg.value = 'Password updated! You can log in with your new password.';
    loginForm.username = username;
    loginForm.password = '';
    setTimeout(() => switchMode('login'), 800);
  } catch (e) {
    err.value = friendlyAuthError(e?.error, e?.message, 'Unable to reset password.');
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="hero">
    <div class="form-card">
      <button class="btn btn--link form-card__back" type="button" @click="goHome">← Back to welcome</button>
      <h2>{{ title }}</h2>
      <p class="small" style="margin-top:0;">{{ subtitle }}</p>

      <form v-if="mode === 'login'" class="stack" @submit.prevent="submitLogin">
        <input class="input" v-model="loginForm.username" placeholder="Username" autocomplete="username" />
        <input class="input" v-model="loginForm.password" type="password" placeholder="Password" autocomplete="current-password" />
        <button class="btn btn--primary" type="submit" :disabled="loading">{{ primaryLabel }}</button>
      </form>

      <form v-else-if="mode === 'register'" class="stack" @submit.prevent="submitRegister">
        <input class="input" v-model="registerForm.username" placeholder="Username" autocomplete="username" />
        <input class="input" v-model="registerForm.password" type="password" placeholder="Password" autocomplete="new-password" />
        <input class="input" v-model="registerForm.confirm" type="password" placeholder="Confirm password" autocomplete="new-password" />
        <button class="btn btn--primary" type="submit" :disabled="loading">{{ primaryLabel }}</button>
      </form>
      <form v-else class="stack" @submit.prevent="submitReset">
        <input class="input" v-model="resetForm.username" placeholder="Username" autocomplete="username" />
        <input class="input" v-model="resetForm.password" type="password" placeholder="New password" autocomplete="new-password" />
        <input class="input" v-model="resetForm.confirm" type="password" placeholder="Confirm new password" autocomplete="new-password" />
        <button class="btn btn--primary" type="submit" :disabled="loading">{{ primaryLabel }}</button>
      </form>

      <div class="stack" style="margin-top:14px;gap:6px;">
        <template v-if="mode === 'login'">
          <p class="small" style="color:var(--muted);margin:0;">
            Need an account?
            <button class="btn btn--link" type="button" @click="switchMode('register')" :disabled="!canRegister">Create one</button>
          </p>
          <p class="small" style="color:var(--muted);margin:0;">
            Forgot password?
            <button class="btn btn--link" type="button" @click="switchMode('reset')" :disabled="!canReset">Reset it</button>
          </p>
        </template>
        <p v-else-if="mode === 'register'" class="small" style="color:var(--muted);margin:0;">
          Already have an account?
          <button class="btn btn--link" type="button" @click="switchMode('login')">Log in</button>
        </p>
        <p v-else class="small" style="color:var(--muted);margin:0;">
          Remembered your password?
          <button class="btn btn--link" type="button" @click="switchMode('login')">Return to login</button>
        </p>
      </div>
      
      <div v-if="msg" class="alert-banner success" style="margin-top:12px;">{{ msg }}</div>
      <div v-if="err" class="alert-banner" style="margin-top:12px;">{{ err }}</div>
    </div>
  </div>
</template>
