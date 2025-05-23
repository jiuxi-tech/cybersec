<template>
  <div>
    <h2>漏洞处置报告管理</h2>

    <el-card class="form-card">
      <template #header>
        <div class="card-header">
          <span>提交处置报告</span>
        </div>
      </template>
      <el-form :model="reportForm" label-width="120px">
        <el-form-item label="资产">
          <el-select v-model="reportForm.asset_id" placeholder="请选择资产" @change="updateAssetInfo">
            <el-option
              v-for="asset in assets"
              :key="asset.id"
              :label="asset.name"
              :value="asset.id"
            ></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="漏洞">
          <el-select v-model="reportForm.vuln_id" placeholder="请选择漏洞" @change="updateVulnInfo">
            <el-option
              v-for="vuln in vulnerabilities"
              :key="vuln.id"
              :label="vuln.name"
              :value="vuln.id"
            ></el-option>
          </el-select>
        </el-form-item>

        <div v-if="selectedAsset && selectedVuln" class="info-box">
          <div class="info-section">
            <h4>资产信息</h4>
            <p><strong>名称:</strong> {{ selectedAsset.name }}</p>
            <p><strong>类型:</strong> {{ selectedAsset.type }}</p>
            <p><strong>IP地址:</strong> {{ selectedAsset.ip }}</p>
            <p><strong>软件:</strong> {{ selectedAsset.software }} {{ selectedAsset.version }}</p>
          </div>
          <div class="info-section">
            <h4>漏洞信息</h4>
            <p><strong>名称:</strong> {{ selectedVuln.name }}</p>
            <p><strong>危害等级:</strong> {{ selectedVuln.severity }}</p>
            <p><strong>解决方案:</strong> {{ selectedVuln.solution }}</p>
          </div>
        </div>

        <el-form-item label="处置状态">
          <el-select v-model="reportForm.status" placeholder="请选择处置状态">
            <el-option label="已修复" value="fixed"></el-option>
            <el-option label="部分修复" value="partially_fixed"></el-option>
            <el-option label="无需修复" value="no_action_needed"></el-option>
            <el-option label="无法修复" value="cannot_fix"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="处置方法">
          <el-input v-model="reportForm.treatment_method" type="textarea" :rows="4"></el-input>
        </el-form-item>
        <el-form-item label="处置日期">
          <el-date-picker v-model="reportForm.treatment_date" type="date" placeholder="选择日期"></el-date-picker>
        </el-form-item>
        <el-form-item label="报告人">
          <el-input v-model="reportForm.reporter"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submitReport">提交报告</el-button>
          <el-button @click="resetForm">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="list-card">
      <template #header>
        <div class="card-header">
          <span>处置报告列表</span>
        </div>
      </template>

      <el-table :data="reports" style="width: 100%">
        <el-table-column prop="id" label="ID" width="60"></el-table-column>
        <el-table-column prop="asset_name" label="资产名称"></el-table-column>
        <el-table-column prop="vuln_name" label="漏洞名称"></el-table-column>
        <el-table-column prop="status" label="处置状态">
          <template #default="scope">
            <el-tag :type="getStatusType(scope.row.status)">
              {{ getStatusText(scope.row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="treatment_date" label="处置日期"></el-table-column>
        <el-table-column prop="reporter" label="报告人"></el-table-column>
        <el-table-column prop="report_date" label="报告日期"></el-table-column>
        <el-table-column label="操作">
          <template #default="scope">
            <el-button size="small" @click="showReportDetail(scope.row)">查看</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 报告详情对话框 -->
    <el-dialog v-model="dialogVisible" title="报告详情" width="60%">
      <template v-if="selectedReport">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="资产">{{ selectedReport.asset_name }}</el-descriptions-item>
          <el-descriptions-item label="漏洞">{{ selectedReport.vuln_name }}</el-descriptions-item>
          <el-descriptions-item label="处置状态">
            <el-tag :type="getStatusType(selectedReport.status)">
              {{ getStatusText(selectedReport.status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="处置方法">{{ selectedReport.treatment_method }}</el-descriptions-item>
          <el-descriptions-item label="处置日期">{{ selectedReport.treatment_date }}</el-descriptions-item>
          <el-descriptions-item label="报告人">{{ selectedReport.reporter }}</el-descriptions-item>
          <el-descriptions-item label="报告日期">{{ selectedReport.report_date }}</el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      reportForm: {
        asset_id: '',
        vuln_id: '',
        status: '',
        treatment_method: '',
        treatment_date: '',
        reporter: ''
      },
      assets: [],
      vulnerabilities: [],
      reports: [],
      selectedAsset: null,
      selectedVuln: null,
      dialogVisible: false,
      selectedReport: null
    };
  },
  mounted() {
    this.fetchAssets();
    this.fetchVulnerabilities();
    this.fetchReports();

    // 如果URL中有参数，自动填充表单
    const { asset_id, vuln_id } = this.$route.query;
    if (asset_id) {
      this.reportForm.asset_id = parseInt(asset_id);
      this.$nextTick(() => {
        this.updateAssetInfo();
      });
    }
    if (vuln_id) {
      this.reportForm.vuln_id = parseInt(vuln_id);
      this.$nextTick(() => {
        this.updateVulnInfo();
      });
    }
  },
  methods: {
    fetchAssets() {
      axios.get('http://localhost:5000/api/assets')
        .then(response => {
          this.assets = response.data || [];
        })
        .catch(error => {
          console.error('获取资产失败:', error);
          this.$message.error('获取资产失败');
        });
    },
    fetchVulnerabilities() {
      axios.get('http://localhost:5000/api/vulnerabilities')
        .then(response => {
          this.vulnerabilities = response.data || [];
        })
        .catch(error => {
          console.error('获取漏洞失败:', error);
          this.$message.error('获取漏洞失败');
        });
    },
    fetchReports() {
      axios.get('http://localhost:5000/api/reports')
        .then(response => {
          this.reports = response.data || [];
        })
        .catch(error => {
          console.error('获取报告失败:', error);
          this.$message.error('获取报告失败');
        });
    },
    updateAssetInfo() {
      if (this.reportForm.asset_id) {
        this.selectedAsset = this.assets.find(asset => asset.id === this.reportForm.asset_id);
      } else {
        this.selectedAsset = null;
      }
    },
    updateVulnInfo() {
      if (this.reportForm.vuln_id) {
        this.selectedVuln = this.vulnerabilities.find(vuln => vuln.id === this.reportForm.vuln_id);
      } else {
        this.selectedVuln = null;
      }
    },
    submitReport() {
      // 简单验证
      if (!this.reportForm.asset_id || !this.reportForm.vuln_id || !this.reportForm.status) {
        this.$message.warning('请填写必要的报告信息');
        return;
      }

      // 格式化日期
      const formattedData = { ...this.reportForm };
      if (this.reportForm.treatment_date) {
        formattedData.treatment_date = this.formatDate(this.reportForm.treatment_date);
      }
      formattedData.report_date = this.formatDate(new Date());

      axios.post('http://localhost:5000/api/reports', formattedData)
        .then(() => {
          this.$message.success('报告提交成功');
          this.fetchReports();
          this.resetForm();
        })
        .catch(error => {
          this.$message.error('报告提交失败');
          console.error(error);
        });
    },
    resetForm() {
      this.reportForm = {
        asset_id: '',
        vuln_id: '',
        status: '',
        treatment_method: '',
        treatment_date: '',
        reporter: ''
      };
      this.selectedAsset = null;
      this.selectedVuln = null;
    },
    showReportDetail(report) {
      this.selectedReport = report;
      this.dialogVisible = true;
    },
    getStatusType(status) {
      switch (status) {
        case 'fixed':
          return 'success';
        case 'partially_fixed':
          return 'warning';
        case 'no_action_needed':
          return 'info';
        case 'cannot_fix':
          return 'danger';
        default:
          return '';
      }
    },
    getStatusText(status) {
      switch (status) {
        case 'fixed':
          return '已修复';
        case 'partially_fixed':
          return '部分修复';
        case 'no_action_needed':
          return '无需修复';
        case 'cannot_fix':
          return '无法修复';
        default:
          return status;
      }
    },
    formatDate(date) {
      if (!date) return '';
      const d = new Date(date);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    }
  }
};
</script>

<style scoped>
.form-card {
  margin-bottom: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.list-card {
  margin-top: 20px;
}
.info-box {
  display: flex;
  margin: 15px 0;
  border: 1px solid #ebeef5;
  border-radius: 4px;
  background-color: #f5f7fa;
  padding: 15px;
}
.info-section {
  flex: 1;
  padding: 0 10px;
}
.info-section h4 {
  margin-top: 0;
  color: #409eff;
}
</style>
