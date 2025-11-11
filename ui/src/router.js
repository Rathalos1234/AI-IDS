import { createRouter, createWebHashHistory } from 'vue-router';
import Splash from './views/Splash.vue';
import Auth from './views/Auth.vue';
import Layout from './views/Layout.vue';
import Dashboard from './views/Dashboard.vue';
import Alerts from './views/Alerts.vue';
import Logs from './views/Logs.vue';
import BanList from './views/BanList.vue';
import Settings from './views/Settings.vue';
import Devices from './views/Devices.vue';

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', component: Splash },
    { path: '/auth', component: Auth },
    { path: '/signup', component: Auth, props: { mode: 'register' } },
    { path: '/reset', component: Auth, props: { mode: 'reset' } },
    {
       path: '/',
      component: Layout,
      children: [
        { path: 'dashboard', component: Dashboard },
        { path: 'alerts', component: Alerts },
        { path: 'logs', component: Logs },
        { path: 'devices', component: Devices },
        { path: 'banlist', component: BanList },
        { path: 'settings', component: Settings },
      ],
    },
  ],
});
