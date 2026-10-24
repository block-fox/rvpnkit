# 官方客户端功能核对

核对基线：本机 Windows `RvRvpnGui.exe` **2.1.4951.1**，2026-10-25。
通过安装目录的 Qt 中文翻译表核对 427 个消息条目。审计脚本为
`scripts/audit-official.py`，原始翻译、程序和本机快照仅保存于忽略的
`.local-audit/`，不纳入发布或 Git 提交。官方帮助站在本次环境访问超时。

本表区分「已实现」「系统集成」「官方桥接」「待验证」。有按钮不等于实现；
未确定的协议字段和结果不能推测为成功。VPN 驱动仍由官方服务提供。

## 功能清单

| 官方区域 | 功能 | 验证依据 |
| --- | --- | --- |
| 系统 | 上线/下线、更名、退出、后台运行、日志、设置 | MainWindow / QCommand |
| 网络 | 创建、确认密码、加入私有/游戏网络、游戏搜索 | DlgCreateNetwork / DlgJoinNetwork |
| 网络管理 | 启用/禁用、离开、删除、复制名称、社区链接 | QCommand |
| 网络属性 | 信息、成员、类型、角色、禁止新成员、免密码申请、改密码 | DlgNetworkProperties |
| 成员 | 名称、IPv4/IPv6、在线状态、角色、通道、延迟 | DlgNodeProperties / CNodeWidget |
| 成员管理 | 批准申请、踢出、授予/撤销管理员 | QCommand |
| 连接工具 | Ping、共享文件夹、复制地址和名称 | QCommand |
| Radmin Viewer | 全控、查看、文件传输、Telnet、关机、聊天、语音、消息 | CRadminIntegration |
| 系统维护 | 网络适配器、驱动修复、官方更新、防火墙例外与应用放行 | MainWindow / CReinstallDriver |
| 设置 | 语言、自动/浅/深主题、代理地址/端口/认证、自动更新 | DlgProgramSettings |
| 通知 | 桌面通知、声音、尊重专注模式、入网审批与 IP 冲突 | DlgProgramSettings / Toast |
| 聊天 | 群聊/私聊、历史、回复、编辑、删除、重发、表情、输入状态 | Chat* / SendPane / MessagesMenu |
| 聊天管理 | 未读、置静音、屏蔽、禁言、成员列表、举报 | ChatListMenu / UserMenu / Report* |
| 帮助 | 帮助、社区、问题反馈、功能建议、安装 Radmin Server、关于 | MainWindow / DlgAbout |

## 验收原则

- 操作结果需要关联请求编号和服务返回；写入管道本身不代表操作成功。
- 地址、角色、状态和通道来自已核对的控制协议字段；未知值显示未知。
- 管理操作按实际网络权限校验，禁止对自己执行不合适的批量操作。
- 官方组件桥接明确标记，不能声称为第三方原生重写。
- 测试使用脱敏合成数据；不将真实网络名称、节点、日志或密码提交到 GitHub。
