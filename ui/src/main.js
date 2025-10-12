import { createApp } from 'vue';
import App from './App.vue';
import router from './router';

// import your existing global CSS (root-level file): ../styles.css
import './styles.css';   // adjusts to the dark theme you already have

createApp(App).use(router).mount('#app');
