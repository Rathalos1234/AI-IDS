import { createApp } from 'vue';
import App from './App.vue';
import router from './router';

import './styles.css';

const THEME_KEY = 'ids.theme';
const initialTheme = localStorage.getItem(THEME_KEY) || 'dark';
document.documentElement.dataset.theme = initialTheme;

createApp(App).use(router).mount('#app');
