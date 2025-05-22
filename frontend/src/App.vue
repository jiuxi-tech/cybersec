<template>
  <div id="app">
    <el-menu :default-active="activeRoute" mode="horizontal" @select="handleSelect">
      <el-menu-item index="/">仪表盘</el-menu-item>
      <el-menu-item index="/vulnerabilities">漏洞列表</el-menu-item>
      <el-menu-item index="/assets">资产管理</el-menu-item>
      <el-menu-item index="/scan-results">扫描结果</el-menu-item>
      <el-menu-item index="/notifications">通知记录</el-menu-item>
      <el-menu-item index="/reports">处置报告</el-menu-item>
      <el-menu-item index="/email-config">邮件配置</el-menu-item>
    </el-menu>
    <router-view></router-view>
  </div>
</template>

<script>
export default {
  data() {
    return {
      activeRoute: this.$route.path
    };
  },
  watch: {
    '$route'(to) {
      this.activeRoute = to.path;
    }
  },
  methods: {
    handleSelect(key) {
      this.$router.push(key);
    }
  }
};
</script>

<style scoped>
#app {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}
.el-menu {
  margin-bottom: 20px;
}
</style>
