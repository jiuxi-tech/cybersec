<template>
  <div>
    <h2>漏洞比对</h2>
    
    <el-card>
      <template #header>
        <div class="card-header">
          <span>比对操作</span>
        </div>
      </template>
      <el-button type="primary" @click="compareVulnerabilities">开始比对</el-button>
      <el-button type="success" @click="compareAndNotify">比对并通知</el-button>
      <el-button type="info" @click="simulateScan">先扫描再比对</el-button>
    </el-card>
    
    <el-card class="match-card">
      <template #header>
        <div class="card-header">
          <span>比对结果</span>
          <el-tag type="info">共 {{ matches.length }} 条匹配</el-tag>
        </div>
      </template>
      
      <el-table :data="matches" style="width: 100%">
        <el-table-column prop="asset_name" label="资产名称"></el-table-column>
        <el-table-column prop="vuln_name" label="漏洞名称"></el-table-column>
        <el-table-column prop="severity" label="危害等级">
          <template #default="scope">
            <el-tag :type="getSeverityType(scope.row.severity)">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="manager" label="管理员"></el-table-column>
        <el-table-column label="操作">
          <template #default="scope">
            <el-button 
              size="small" 
              type="primary" 
              @click="sendNotification(scope.row)"
              :disabled="!scope.row.manager_email"
            >
              发送通知
            </el-button>
            <el-button 
              size="small" 
              type="success" 
              @click="createReport(scope.row)"
            >
              创建报告
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      matches: []
    };
  },
  mounted() {
    this.compareVulnerabilities();
  },
  methods: {
    compareVulnerabilities() {
      this.$message.info('正在比对漏洞...');
      axios.get('http://localhost:5000/api/compare')
        .then(response => {
          this.matches = response.data;
          this.$message.success(`比对完成，发现 ${this.matches.length} 个匹配项`);
        })
        .catch(error => {
          console.error('漏洞比对失败:', error);
          this.$message.error('漏洞比对失败');
        });
    },
    compareAndNotify() {
      this.$message.info('正在比对漏洞并发送通知...');
      axios.get('http://localhost:5000/api/compare_and_notify')
        .then(response => {
          if (response.data.status === 'success') {
            this.matches = response.data.matches;
            this.$message.success(`比对完成，发现 ${this.matches.length} 个匹配项，已发送 ${response.data.notification_sent} 条通知`);
          } else {
            this.$message.error('比对通知失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('比对通知失败');
          console.error(error);
        });
    },
    sendNotification(match) {
      axios.post('http://localhost:5000/api/send_notification', {
        asset_id: match.asset_id,
        vuln_id: match.vuln_id,
        recipient: match.manager_email
      })
        .then(response => {
          if (response.data.status === 'success') {
            this.$message.success('通知发送成功');
          } else {
            this.$message.error('通知发送失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('通知发送失败');
          console.error(error);
        });
    },
    createReport(match) {
      this.$router.push({
        path: '/reports',
        query: {
          asset_id: match.asset_id,
          vuln_id: match.vuln_id
        }
      });
    },
    simulateScan() {
      this.$message.info('正在模拟扫描资产...');
      axios.post('http://localhost:5000/api/simulate_scan')
        .then(response => {
          if (response.data.status === 'success') {
            this.$message.success('扫描完成，开始比对');
            this.compareVulnerabilities();
          } else {
            this.$message.error('扫描失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('扫描失败');
          console.error(error);
        });
    },
    getSeverityType(severity) {
      switch (severity) {
        case '高危':
          return 'danger';
        case '中危':
          return 'warning';
        case '低危':
          return 'info';
        default:
          return '';
      }
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
.match-card {
  margin-top: 20px;
}
</style>

