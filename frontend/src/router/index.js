// src/router/index.js
import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '@/components/Dashboard.vue';
import VulnerabilityList from '@/components/VulnerabilityList.vue';
import AssetManagement from '@/components/AssetManagement.vue';
import ReportManagement from '@/components/ReportManagement.vue';
import NotificationList from '@/components/NotificationList.vue';
import EmailConfig from '@/components/EmailConfig.vue';
import ScanResults from '@/components/ScanResults.vue';

// 定义路由规则
const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/vulnerabilities',
    name: 'VulnerabilityList',
    component: VulnerabilityList
  },
  {
    path: '/assets',
    name: 'AssetManagement',
    component: AssetManagement
  },
  {
    path: '/reports',
    name: 'ReportManagement',
    component: ReportManagement
  },
  {
    path: '/notifications',
    name: 'NotificationList',
    component: NotificationList
  },
  {
    path: '/email-config',
    name: 'EmailConfig',
    component: EmailConfig
  },
  {
    path: '/scan-results',
    name: 'ScanResults',
    component: ScanResults
  }
];

// 创建 router 实例
const router = createRouter({
  history: createWebHistory(),
  routes
});

// 导出 router 实例
export default router;
