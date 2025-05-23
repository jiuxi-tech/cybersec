<template>
  <div>
    <h2>通知记录</h2>

    <el-card>
      <template #header>
        <div class="card-header">
          <span>通知记录列表</span>
        </div>
      </template>

      <el-table :data="notifications" style="width: 100%; margin-right: 0 !important;">
        <el-table-column prop="asset_name" label="资产名称" width="150"></el-table-column>
        <el-table-column prop="sender" label="发件人" width="150"></el-table-column>
        <el-table-column prop="recipient" label="收件人" width="200"></el-table-column>
        <el-table-column prop="send_time" label="发送时间" width="180"></el-table-column>
        <el-table-column prop="status" label="状态" width="150"></el-table-column>
        <el-table-column prop="message" label="失败原因" v-if="hasFailedNotifications"></el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      notifications: []
    };
  },
  computed: {
    hasFailedNotifications() {
      return this.notifications.some(notification => notification.status === 'failed');
    }
  },
  mounted() {
    this.fetchNotifications();
  },
  methods: {
    fetchNotifications() {
      axios.get('http://localhost:5000/api/notifications')
        .then(response => {
          this.notifications = response.data.map(notification => {
            // 格式化 send_time 为更友好的时间显示
            if (notification.send_time) {
              const date = new Date(notification.send_time);
              notification.send_time = date.toLocaleString('zh-CN', {
                hour12: false,
                timeZone: 'Asia/Tokyo'
              });
            }
            // 如果后端数据中没有 sender 字段，尝试从其他字段（如 from 或 sender_from）获取，或使用默认值
            if (!notification.sender) {
              notification.sender = '网络安全信息管理平台'; // 默认发件人，可以根据实际需求调整
            }
            return notification;
          });
        })
        .catch(error => {
          console.error('获取通知记录失败:', error);
          this.$message.error('获取通知记录失败');
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

/* 确保 el-table 没有右边 margin */
.el-table {
  margin-right: 0 !important;
}
</style>
