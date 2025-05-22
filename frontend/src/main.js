import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import axios from 'axios';

// 创建 Vue 应用
const app = createApp(App);

// 全局注册 Element Plus
app.use(ElementPlus);

// 全局注册路由
app.use(router);

// 配置 Axios
app.config.globalProperties.$axios = axios.create({
  baseURL: 'http://localhost:5000', // 设置后端 API 基础地址
  timeout: 30000, // 请求超时
});

// 挂载应用
app.mount('#app');
