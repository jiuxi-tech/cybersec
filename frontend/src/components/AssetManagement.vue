<template>
  <div>
    <h2>资产管理</h2>
    
    <el-card>
      <template #header>
        <div class="card-header">
          <span>资产列表</span>
          <el-button type="primary" @click="showAddDialog">添加资产</el-button>
        </div>
      </template>
      
      <el-table :data="assets" style="width: 100%" :row-class-name="tableRowClassName">
        <el-table-column prop="name" label="资产名称"></el-table-column>
        <el-table-column prop="type" label="类型"></el-table-column>
        <el-table-column prop="os" label="操作系统"></el-table-column>
        <el-table-column prop="ip" label="IP地址"></el-table-column>
        <el-table-column prop="software" label="软件"></el-table-column>
        <el-table-column prop="version" label="版本"></el-table-column>
        <el-table-column prop="manager" label="负责人"></el-table-column>
        <el-table-column prop="manager_email" label="邮箱"></el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="scope">
            <el-button size="small" @click="editAsset(scope.row)">编辑</el-button>
            <el-button size="small" type="danger" @click="deleteAsset(scope.row.id)">删除</el-button>
            <el-button size="small" type="primary" @click="startScanTask(scope.row.id)">扫描</el-button>
          </template>
        </el-table-column>
      </el-table>
      
      <!-- 版本不一致警告 -->
      <el-card v-if="versionMismatches.length" style="margin-top: 20px">
        <template #header>
          <div class="card-header">
            <span>版本不一致警告</span>
          </div>
        </template>
        <el-table :data="versionMismatches" style="width: 100%">
          <el-table-column type="index" label="序号" width="80"></el-table-column>
          <el-table-column prop="asset_name" label="资产名称"></el-table-column>
          <el-table-column prop="service" label="服务"></el-table-column>
          <el-table-column prop="reported_version" label="填报版本"></el-table-column>
          <el-table-column prop="scanned_version" label="实际扫描版本"></el-table-column>
          <el-table-column prop="scan_time" label="扫描时间"></el-table-column>
        </el-table>
      </el-card>
      
      <!-- 当前资产扫描结果 -->
      <el-card v-if="currentScanResults.length" style="margin-top: 20px">
        <template #header>
          <div class="card-header">
            <span>当前资产扫描结果</span>
          </div>
        </template>
        <el-table :data="currentScanResults" style="width: 100%">
          <el-table-column prop="asset_name" label="资产名称"></el-table-column>
          <el-table-column prop="ip" label="IP地址"></el-table-column>
          <el-table-column prop="port" label="端口"></el-table-column>
          <el-table-column prop="service" label="服务"></el-table-column>
          <el-table-column prop="version" label="实际版本"></el-table-column>
          <el-table-column prop="vulnerabilities" label="漏洞信息"></el-table-column>
          <el-table-column prop="scan_time" label="扫描时间"></el-table-column>
        </el-table>
      </el-card>
    </el-card>
    
    <!-- 添加资产对话框 -->
    <el-dialog title="添加资产" v-model="dialogVisible" width="30%">
      <el-form :model="form" label-width="120px">
        <el-form-item label="资产名称">
          <el-input v-model="form.name"></el-input>
        </el-form-item>
        <el-form-item label="类型">
          <el-input v-model="form.type"></el-input>
        </el-form-item>
        <el-form-item label="操作系统">
          <el-input v-model="form.os"></el-input>
        </el-form-item>
        <el-form-item label="IP地址">
          <el-input v-model="form.ip"></el-input>
        </el-form-item>
        <el-form-item label="软件">
          <el-input v-model="form.software"></el-input>
        </el-form-item>
        <el-form-item label="版本">
          <el-input v-model="form.version"></el-input>
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="form.manager"></el-input>
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="form.manager_email"></el-input>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="addAsset">确定</el-button>
      </template>
    </el-dialog>
    
    <!-- 编辑资产对话框 -->
    <el-dialog title="编辑资产" v-model="editDialogVisible" width="30%">
      <el-form :model="editForm" label-width="120px">
        <el-form-item label="资产名称">
          <el-input v-model="editForm.name"></el-input>
        </el-form-item>
        <el-form-item label="类型">
          <el-input v-model="editForm.type"></el-input>
        </el-form-item>
        <el-form-item label="操作系统">
          <el-input v-model="editForm.os"></el-input>
        </el-form-item>
        <el-form-item label="IP地址">
          <el-input v-model="editForm.ip"></el-input>
        </el-form-item>
        <el-form-item label="软件">
          <el-input v-model="editForm.software"></el-input>
        </el-form-item>
        <el-form-item label="版本">
          <el-input v-model="editForm.version"></el-input>
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="editForm.manager"></el-input>
        </el-form-item>
        <el-form-item label="邮箱">
          <el-input v-model="editForm.manager_email"></el-input>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      assets: [],
      dialogVisible: false,
      editDialogVisible: false,
      currentScanResults: [],
      versionMismatches: [],
      form: {
        name: '',
        type: '',
        os: '',
        ip: '',
        software: '',
        version: '',
        manager: '',
        manager_email: ''
      },
      editForm: {
        id: null,
        name: '',
        type: '',
        os: '',
        ip: '',
        software: '',
        version: '',
        manager: '',
        manager_email: ''
      }
    };
  },
  mounted() {
    this.fetchAssets();
    this.fetchVersionMismatches();
  },
  methods: {
    fetchAssets() {
      axios.get('http://localhost:5000/api/assets')
        .then(response => {
          this.assets = response.data;
        })
        .catch(error => {
          console.error('获取资产失败:', error);
          this.$message.error('获取资产失败');
        });
    },
    fetchVersionMismatches() {
      axios.get('http://localhost:5000/api/compare_versions')
        .then(response => {
          this.versionMismatches = response.data;
        })
        .catch(error => {
          console.error('获取版本不一致信息失败:', error);
          this.$message.error('获取版本不一致信息失败');
        });
    },
    tableRowClassName({ row }) {
      return this.versionMismatches.some(mismatch => mismatch.asset_id === row.id) ? 'warning-row' : '';
    },
    showAddDialog() {
      this.form = {
        name: '',
        type: '',
        os: '',
        ip: '',
        software: '',
        version: '',
        manager: '',
        manager_email: ''
      };
      this.dialogVisible = true;
    },
    addAsset() {
      axios.post('http://localhost:5000/api/assets', this.form)
        .then(() => {
          this.$message.success('资产添加成功');
          this.dialogVisible = false;
          this.fetchAssets();
        })
        .catch(error => {
          console.error('添加资产失败:', error);
          this.$message.error('添加资产失败');
        });
    },
    editAsset(asset) {
      this.editForm = { ...asset };
      this.editDialogVisible = true;
    },
    saveEdit() {
      axios.put(`http://localhost:5000/api/assets/${this.editForm.id}`, this.editForm)
        .then(() => {
          this.$message.success('资产更新成功');
          this.editDialogVisible = false;
          this.fetchAssets();
          this.fetchVersionMismatches();
        })
        .catch(error => {
          console.error('更新资产失败:', error);
          this.$message.error('更新资产失败');
        });
    },
    deleteAsset(id) {
      axios.delete(`http://localhost:5000/api/assets/${id}`)
        .then(() => {
          this.$message.success('资产删除成功');
          this.fetchAssets();
          this.fetchVersionMismatches();
        })
        .catch(error => {
          console.error('删除资产失败:', error);
          this.$message.error('删除资产失败');
        });
    },
    startScanTask(assetId) {
      this.currentScanResults = [];
      axios.post('http://localhost:5000/api/simulate_scan', { ports: '80,443,8080,8443,22,3389,6379', asset_id: assetId })
        .then(response => {
          this.$message.success('扫描完成');
          this.currentScanResults = response.data.results;
          this.versionMismatches = response.data.version_mismatches;
          if (response.data.version_mismatches.length) {
            this.$message.warning('检测到版本不一致，已发送邮件通知');
          }
        })
        .catch(error => {
          console.error('扫描失败:', error);
          this.$message.error('扫描失败');
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
.warning-row {
  background-color: #fff1f0 !important;
}
</style>
