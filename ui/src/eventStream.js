import { authToken } from './api';

const listeners = new Map(); // event -> Set<handler>
let source = null;

function totalListeners() {
  let total = 0;
  listeners.forEach((set) => { total += set.size; });
  return total;
}

function dispatch(type, payload) {
  const set = listeners.get(type);
  if (!set) return;
  [...set].forEach((handler) => {
    try {
      handler(payload);
    } catch (err) {
      console.error('event handler error', err);
    }
  });
}

function ensureSource() {
  if (source) return;
  const base = localStorage.getItem('API_BASE') || window.API_BASE || '';
  const origin = base ? base : window.location.origin;
  const target = new URL('/api/events', origin);
  const token = typeof authToken?.get === 'function' ? authToken.get() : null;
  if (token) target.searchParams.set('token', token);
  const options = token ? undefined : { withCredentials: true };
  source = new EventSource(target.toString(), options);
  source.addEventListener('alert', (event) => {
    try {
      const data = JSON.parse(event.data);
      dispatch('alert', data);
    } catch (err) {
      console.error('failed to parse alert event', err);
    }
  });
  source.addEventListener('block', (event) => {
    try {
      const data = JSON.parse(event.data);
      dispatch('block', data);
    } catch (err) {
      console.error('failed to parse block event', err);
    }
  });
  source.addEventListener('scan', (event) => {
    try {
      const data = JSON.parse(event.data);
      dispatch('scan', data);
    } catch (err) {
      console.error('failed to parse scan event', err);
    }
  });
  source.onerror = () => {
    // allow browser to attempt automatic reconnects; if it closes we will rebuild
    console.warn('event stream error, waiting for reconnect');
  };
  source.onopen = () => {
    console.info('event stream connected');
  };
}

export function subscribeToEvents(type, handler) {
  if (!listeners.has(type)) listeners.set(type, new Set());
  const set = listeners.get(type);
  set.add(handler);
  ensureSource();
  return () => {
    set.delete(handler);
    if (set.size === 0) listeners.delete(type);
    if (totalListeners() === 0 && source) {
      source.close();
      source = null;
    }
  };
}

export function closeEventStream() {
  if (source) {
    source.close();
    source = null;
  }
  listeners.clear();
}