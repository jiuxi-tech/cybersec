<template>
  <div>
    <h2>邮件通知配置</h2>

    <el-card>
      <template #header>
        <div class="card-header">
          <span>邮件服务器设置</span>
        </div>
      </template>

      <el-form :model="emailConfig" :rules="rules" ref="emailForm" label-width="120px">
        <el-form-item label="SMTP服务器" prop="host">
          <el-input v-model="emailConfig.host" placeholder="smtp.163.com"></el-input>
        </el-form-item>
        <el-form-item label="端口" prop="port">
          <el-input v-model.number="emailConfig.port" placeholder="25" type="number"></el-input>
        </el-form-item>
        <el-form-item label="发件人邮箱" prop="user">
          <el-input v-model="emailConfig.user" placeholder="your_email@163.com"></el-input>
        </el-form-item>
        <el-form-item label="授权码" prop="password">
          <el-input v-model="emailConfig.password" type="password" placeholder="授权码(非登录密码)"></el-input>
          <div class="tip">
            <el-alert
              title="注意：授权码不是邮箱登录密码，需要在邮箱设置中开启SMTP服务并获取授权码"
              type="warning"
              :closable="false"
              show-icon
            ></el-alert>
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveConfig">保存配置</el-button>
          <el-button @click="testEmail">测试邮件</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px;">
      <template #header>
        <div class="card-header">
          <span>邮件服务使用说明</span>
        </div>
      </template>

      <div class="instruction">
        <h3>如何获取163邮箱的SMTP授权码</h3>
        <ol>
          <li>登录163邮箱网页版</li>
          <li>点击页面右上角的"设置"</li>
          <li>在左侧菜单中选择"POP3/SMTP/IMAP"</li>
          <li>开启"SMTP服务"</li>
          <li>按照提示完成验证，获取授权码</li>
        </ol>

        <h3>常见问题</h3>
        <p><strong>Q: 为什么要使用授权码而不是密码？</strong></p>
        <p>A: 出于安全考虑，第三方客户端登录需要使用授权码而非邮箱密码。</p>

        <p><strong>Q: 邮件发送失败怎么办？</strong></p>
        <p>A: 请检查以下几点：</p>
        <ul>
          <li>确认SMTP服务已开启</li>
          <li>确认授权码正确</li>
          <li>检查端口是否被防火墙阻止（可尝试使用25或465端口）</li>
          <li>检查发送频率是否过高（163邮箱有发送频率限制）</li>
        </ul>
      </div>
    </el-card>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      emailConfig: {
        host: 'smtp.163.com',
        port: 25, // 端口使用数字类型
        user: '',
        password: '',
        // 'from' 字段在后端会默认使用 'user'，前端无需单独维护
      },
      rules: {
        host: [{ required: true, message: '请输入SMTP服务器', trigger: 'blur' }],
        port: [
          { required: true, message: '请输入端口', trigger: 'blur' },
          { type: 'number', message: '端口必须为数字值' }
        ],
        user: [
          { required: true, message: '请输入发件人邮箱', trigger: 'blur' },
          { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
        ],
        password: [{ required: true, message: '请输入授权码', trigger: 'blur' }],
        // 移除 'from' 字段的验证规则
      }
    };
  },
  mounted() {
    this.fetchConfig();
  },
  methods: {
    fetchConfig() {
      axios.get('http://localhost:5000/api/email_config')
        .then(response => {
          // 后端直接返回配置对象，无需 response.data.data
          // 确保 port 转换为数字
          this.emailConfig = {
            host: response.data.host,
            port: Number(response.data.port),
            user: response.data.user,
            // 密码不从后端获取，因为是敏感信息，保持为空或原有输入
            password: this.emailConfig.password,
          };
          console.log('Fetched email config:', this.emailConfig);
        })
        .catch(error => {
          console.error('获取邮件配置失败:', error);
          this.$message.error('获取邮件配置失败');
        });
    },
    saveConfig() {
      this.$refs.emailForm.validate((valid) => {
        if (valid) {
          // 添加 from 字段，值与 user 保持一致，以便后端处理
          const configToSend = { ...this.emailConfig, from: this.emailConfig.user };
          console.log('Saving email config:', configToSend);
          axios.post('http://localhost:5000/api/email_config', configToSend)
            .then(() => {
              this.$message.success('邮件配置保存成功');
            })
            .catch(error => {
              this.$message.error('邮件配置保存失败');
              console.error(error);
            });
        } else {
          this.$message.error('请填写所有必填字段');
        }
      });
    },
    testEmail() {
      this.$refs.emailForm.validate((valid) => {
        if (valid) {
          this.$message.info('正在发送测试邮件...');
          // 添加 from 字段，值与 user 保持一致，以便后端处理
          const configToSend = { ...this.emailConfig, from: this.emailConfig.user };
          console.log('Testing email config:', configToSend);
          axios.post('http://localhost:5000/api/test_email', configToSend)
            .then(response => {
              if (response.data.status === 'success') {
                this.$message.success('测试邮件发送成功');
              } else {
                this.$message.error('测试邮件发送失败: ' + response.data.message);
              }
            })
            .catch(error => {
              this.$message.error('测试邮件发送失败');
              console.error(error);
            });
        } else {
          this.$message.error('请填写所有必填字段');
        }
      });
    }
  },
  // 移除 watch 监听，因为 from 字段不再由前端单独维护
};
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.tip {
  margin-top: 10px;
}
.instruction {
  line-height: 1.6;
}
.instruction h3 {
  margin-top: 20px;
  margin-bottom: 10px;
  color: #409eff;
}
.instruction ol, .instruction ul {
  padding-left: 20px;
}
</style>
