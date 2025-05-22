<template>
  <div>
    <h2>扫描结果</h2>
    
    <el-card>
      <template #header>
        <div class="card-header">
          <span>扫描结果列表</span>
        </div>
      </template>
      
      <el-table :data="scanResults" style="width: 100%">
        <el-table-column prop="asset_name" label="资产名称" width="150"></el-table-column>
        <el-table-column prop="ip" label="IP地址" width="150"></el-table-column>
        <el-table-column prop="port" label="端口" width="100"></el-table-column>
        <el-table-column prop="service" label="服务" width="150"></el-table-column>
        <el-table-column prop="version" label="版本" width="150"></el-table-column>
        <el-table-column prop="vulnerabilities" label="漏洞信息" min-width="200"></el-table-column>
        <el-table-column prop="scan_time" label="扫描时间" width="180"></el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      scanResults: []
    };
  },
  mounted() {
    this.fetchScanResults();
  },
  methods: {
    fetchScanResults() {
      axios.get('http://localhost:5000/api/scan_results')
        .then(response => {
          this.scanResults = response.data;
        })
        .catch(error => {
          console.error('获取扫描结果失败:', error);
          this.$message.error('获取扫描结果失败');
        });
    }
  }
};
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
