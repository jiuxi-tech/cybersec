<template>
  <div>
    <el-row :gutter="20">
      <el-col :span="24">
        <el-card class="welcome-card">
          <h2>欢迎使用网络安全信息管理平台</h2>
          <p>本平台提供漏洞预警信息收集、资产漏洞比对和漏洞处置报告管理功能</p>
        </el-card>
      </el-col>
    </el-row>
    
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>资产统计</span>
            </div>
          </template>
          <div class="stat-number">{{ assetCount }}</div>
          <div class="stat-label">已管理资产数量</div>
          <el-button type="primary" @click="$router.push('/assets')">管理资产</el-button>
        </el-card>
      </el-col>
      
      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>漏洞统计</span>
            </div>
          </template>
          <div class="stat-number">{{ vulnCount }}</div>
          <div class="stat-label">已收集漏洞数量</div>
          <el-button type="primary" @click="collectVulnerabilities">收集漏洞</el-button>
        </el-card>
      </el-col>
      
      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>处置报告</span>
            </div>
          </template>
          <div class="stat-number">{{ reportCount }}</div>
          <div class="stat-label">已提交处置报告</div>
          <el-button type="primary" @click="$router.push('/reports')">查看报告</el-button>
        </el-card>
      </el-col>
    </el-row>
    
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>漏洞危害等级分布</span>
            </div>
          </template>
          <div id="severity-chart" style="height: 300px;"></div>
        </el-card>
      </el-col>
      
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>快速操作</span>
            </div>
          </template>
          <el-button type="primary" @click="$router.push('/compare')">漏洞比对</el-button>
          <el-button type="success" @click="compareAndNotify">比对并通知</el-button>
          <el-button type="warning" @click="simulateScan">模拟扫描</el-button>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script>
import axios from 'axios';
import * as echarts from 'echarts';

export default {
  data() {
    return {
      assetCount: 0,
      vulnCount: 0,
      reportCount: 0,
      severityChart: null
    };
  },
  mounted() {
    this.fetchStatistics();
    this.initSeverityChart();
  },
  methods: {
    fetchStatistics() {
      // 获取资产数量
      axios.get('http://localhost:5000/api/assets')
        .then(response => {
          this.assetCount = response.data.length;
        })
        .catch(error => {
          console.error('获取资产失败:', error);
        });
      
      // 获取漏洞数量
      axios.get('http://localhost:5000/api/vulnerabilities')
        .then(response => {
          this.vulnCount = response.data.length;
          this.updateSeverityChart(response.data);
        })
        .catch(error => {
          console.error('获取漏洞失败:', error);
        });
      
      // 获取报告数量
      axios.get('http://localhost:5000/api/reports')
        .then(response => {
          this.reportCount = response.data.length;
        })
        .catch(error => {
          console.error('获取报告失败:', error);
        });
    },
    initSeverityChart() {
      this.severityChart = echarts.init(document.getElementById('severity-chart'));
      const option = {
        tooltip: {
          trigger: 'item',
          formatter: '{a} <br/>{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          left: 10,
          data: ['高危', '中危', '低危']
        },
        series: [
          {
            name: '漏洞危害等级',
            type: 'pie',
            radius: ['50%', '70%'],
            avoidLabelOverlap: false,
            label: {
              show: false,
              position: 'center'
            },
            emphasis: {
              label: {
                show: true,
                fontSize: '18',
                fontWeight: 'bold'
              }
            },
            labelLine: {
              show: false
            },
            data: [
              { value: 0, name: '高危' },
              { value: 0, name: '中危' },
              { value: 0, name: '低危' }
            ]
          }
        ]
      };
      this.severityChart.setOption(option);
    },
    updateSeverityChart(vulnerabilities) {
      const severityCounts = {
        '高危': 0,
        '中危': 0,
        '低危': 0
      };
      
      vulnerabilities.forEach(vuln => {
        if (vuln.severity in severityCounts) {
          severityCounts[vuln.severity]++;
        }
      });
      
      const data = [
        { value: severityCounts['高危'], name: '高危' },
        { value: severityCounts['中危'], name: '中危' },
        { value: severityCounts['低危'], name: '低危' }
      ];
      
      this.severityChart.setOption({
        series: [{
          data: data
        }]
      });
    },
    collectVulnerabilities() {
      this.$message.info('正在收集漏洞信息...');
      axios.get('http://localhost:5000/api/collect_vulnerabilities')
        .then(response => {
          if (response.data.status === 'success') {
            this.$message.success(`成功收集 ${response.data.count} 条漏洞信息`);
            this.fetchStatistics();
          } else {
            this.$message.error('漏洞收集失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('漏洞收集失败');
          console.error(error);
        });
    },
    compareAndNotify() {
      this.$message.info('正在比对漏洞并发送通知...');
      axios.get('http://localhost:5000/api/compare_and_notify')
        .then(response => {
          if (response.data.status === 'success') {
            this.$message.success(`发现 ${response.data.matches.length} 个匹配项，已发送 ${response.data.notification_sent} 条通知`);
          } else {
            this.$message.error('比对通知失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('比对通知失败');
          console.error(error);
        });
    },
    simulateScan() {
      this.$message.info('正在模拟扫描资产...');
      axios.post('http://localhost:5000/api/simulate_scan')
        .then(response => {
          if (response.data.status === 'success') {
            this.$message.success('扫描完成');
            this.fetchStatistics();
          } else {
            this.$message.error('扫描失败: ' + response.data.message);
          }
        })
        .catch(error => {
          this.$message.error('扫描失败');
          console.error(error);
        });
    }
  }
}
</script>

<style scoped>
.welcome-card {
  margin-bottom: 20px;
  text-align: center;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.stat-number {
  font-size: 36px;
  font-weight: bold;
  text-align: center;
  margin: 10px 0;
}
.stat-label {
  text-align: center;
  margin-bottom: 15px;
  color: #666;
}
</style>

