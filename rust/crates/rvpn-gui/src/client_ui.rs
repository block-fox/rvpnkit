//! Client workflows and desktop integrations, isolated from rendering shell.
use super::*;
use rvpn_core::desktop::{self, DesktopAction, VIEWER_ACTIONS};

pub(super) fn fuzzy_match(value: &str, query: &str) -> bool {
    let hay = value.to_lowercase();
    let needle = query.trim().to_lowercase();
    if needle.is_empty() || hay.contains(&needle) {
        return true;
    }
    let mut cursor = 0;
    for ch in needle.chars() {
        let Some(offset) = hay[cursor..].find(ch) else {
            return false;
        };
        cursor += offset + ch.len_utf8();
    }
    true
}

#[derive(Default)]
pub(super) struct ClientUi {
    pub output: Option<String>,
    pub network: Option<NetworkInfo>,
    pub tool_confirm: Option<(DesktopAction, Option<String>, String)>,
    pub member_status: u8,
    pub member_role: u8,
    pub member_sort: u8,
    pub create: Option<bool>,
    pub confirm_password: String,
    pub reveal_password: bool,
}
impl App {
    pub(super) fn measured_latency(&self, member: &MemberInfo) -> Option<u32> {
        member
            .virtual_ip
            .as_ref()
            .and_then(|ip| self.measured_latency.get(ip).copied().flatten())
    }

    pub(super) fn latency_label(&self, member: &MemberInfo) -> String {
        match self.measured_latency(member) {
            Some(ms) => {
                let bars = match ms {
                    0..=30 => "▮▮▮▮",
                    31..=80 => "▮▮▮▫",
                    81..=160 => "▮▮▫▫",
                    _ => "▮▫▫▫",
                };
                format!("{bars} {ms} ms")
            }
            None if member.online() == Some(true) => "测量中…".into(),
            None => "—".into(),
        }
    }

    pub(super) fn member_rows(&self, net: &NetworkInfo) -> Vec<MemberInfo> {
        let q = self.filter.trim().to_lowercase();
        let mut rows: Vec<_> = net
            .members
            .iter()
            .filter(|m| {
                let search = format!(
                    "{} {} {} {} {}",
                    m.node_id,
                    m.label(),
                    m.public_ip.as_deref().unwrap_or(""),
                    m.virtual_ip.as_deref().unwrap_or(""),
                    m.virtual_ipv6.as_deref().unwrap_or("")
                );
                fuzzy_match(&search, &q)
                    && (self.client.member_status == 0
                        || match self.client.member_status {
                            1 => m.online() == Some(true),
                            2 => m.online() == Some(false),
                            _ => m.online().is_none(),
                        })
                    && (self.client.member_role == 0
                        || m.role == Some(self.client.member_role as u32))
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| match self.client.member_sort {
            1 => a.node_id.cmp(&b.node_id),
            2 => a.virtual_ip.cmp(&b.virtual_ip),
            3 => a
                .virtual_ip
                .as_ref()
                .and_then(|ip| self.measured_latency.get(ip).copied().flatten())
                .unwrap_or(u32::MAX)
                .cmp(
                    &b.virtual_ip
                        .as_ref()
                        .and_then(|ip| self.measured_latency.get(ip).copied().flatten())
                        .unwrap_or(u32::MAX),
                ),
            _ => a.label().to_lowercase().cmp(&b.label().to_lowercase()),
        });
        rows
    }
    pub(super) fn member_filters(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("status_filter")
                .selected_text(
                    ["所有状态", "在线", "离线", "未知"][self.client.member_status as usize],
                )
                .show_ui(ui, |ui| {
                    for (i, label) in ["所有状态", "在线", "离线", "未知"].iter().enumerate()
                    {
                        ui.selectable_value(&mut self.client.member_status, i as u8, *label);
                    }
                });
            egui::ComboBox::from_id_salt("role_filter")
                .selected_text(
                    ["所有角色", "成员", "管理员", "申请人"][self.client.member_role as usize],
                )
                .show_ui(ui, |ui| {
                    for (i, label) in ["所有角色", "成员", "管理员", "申请人"].iter().enumerate()
                    {
                        ui.selectable_value(&mut self.client.member_role, i as u8, *label);
                    }
                });
            egui::ComboBox::from_id_salt("member_sort")
                .selected_text(
                    ["按名称", "按节点 ID", "按虚拟 IP", "按延迟"]
                        [self.client.member_sort as usize],
                )
                .show_ui(ui, |ui| {
                    for (i, label) in ["按名称", "按节点 ID", "按虚拟 IP", "按延迟"]
                        .iter()
                        .enumerate()
                    {
                        ui.selectable_value(&mut self.client.member_sort, i as u8, *label);
                    }
                });
        });
    }
    pub(super) fn desktop_action(
        &mut self,
        action: DesktopAction,
        address: Option<String>,
        label: &str,
    ) {
        if self.demo {
            self.status = "演示模式不启动真实系统操作".into();
            return;
        }
        self.client.tool_confirm = Some((action, address, label.into()));
    }
    pub(super) fn page_chat(&mut self, ui: &mut egui::Ui) {
        self.page_header(ui, "聊天", "官方互通组件");
        self.hint(
            ui,
            "选择成员后直接调用 Radmin Viewer 的文本聊天、语音聊天或远程控制。",
        );
        let members = self
            .current_network()
            .map(|network| network.members.clone())
            .unwrap_or_default();
        card(ui, self.palette, |ui| {
            ui.label(RichText::new("网络成员").size(21.0).strong());
            ui.add_space(12.0);
            if members.is_empty() {
                ui.label(RichText::new("当前网络还没有成员快照。").color(self.palette.muted));
            }
            for peer in members.iter().take(40) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(peer.label()).strong());
                    ui.label(RichText::new(peer.status_text()).color(self.palette.muted));
                    ui.label(
                        RichText::new(self.latency_label(peer))
                            .monospace()
                            .color(self.palette.muted),
                    );
                    if ui
                        .add_enabled(
                            peer.virtual_ip.is_some() && !self.demo,
                            egui::Button::new("文本聊天"),
                        )
                        .clicked()
                    {
                        self.desktop_action(
                            DesktopAction::Chat,
                            peer.virtual_ip.clone(),
                            "Radmin 文本聊天",
                        );
                    }
                    if ui
                        .add_enabled(
                            peer.virtual_ip.is_some() && !self.demo,
                            egui::Button::new("语音聊天"),
                        )
                        .clicked()
                    {
                        self.desktop_action(
                            DesktopAction::VoiceChat,
                            peer.virtual_ip.clone(),
                            "Radmin 语音聊天",
                        );
                    }
                    if ui
                        .add_enabled(
                            peer.virtual_ip.is_some() && !self.demo,
                            egui::Button::new("远程控制"),
                        )
                        .clicked()
                    {
                        self.desktop_action(
                            DesktopAction::FullControl,
                            peer.virtual_ip.clone(),
                            "Radmin 远程控制",
                        );
                    }
                });
            }
        });
        ui.add_space(16.0);
        card(ui, self.palette, |ui| {
            ui.label("官方客户端聊天");
            if ui
                .add_enabled(!self.demo, egui::Button::new("打开官方聊天与网络窗口"))
                .clicked()
            {
                self.desktop_action(
                    DesktopAction::Official,
                    None,
                    "打开官方客户端，在顶部选择聊天",
                );
            }
            ui.label(
                "Radmin Viewer 需要对端安装 Radmin Server，并且聊天或远程控制权限由对端策略决定。",
            );
        });
    }
    pub(super) fn page_tools(&mut self, ui: &mut egui::Ui) {
        self.page_header(ui, "工具与帮助", "连接、维护与支持");
        egui::ScrollArea::vertical().show(ui,|ui|{
            card(ui,self.palette,|ui|{
                ui.label(RichText::new("连接诊断").strong());ui.add_space(8.0);
                ui.label("在成员列表右键选择 Ping、共享文件夹，或通过 Radmin Viewer 连接。Ping 使用四次 ICMP 请求。");
                if let Some(peer)=self.props.clone(){ui.label(format!("当前成员：{}",peer.label()));self.peer_actions(ui,&peer);}
                ui.horizontal_wrapped(|ui|{
                    for(action,label)in[(DesktopAction::Adapters,"网络适配器"),(DesktopAction::Logs,"打开服务日志"),(DesktopAction::Official,"官方客户端 / 驱动修复 / 防火墙例外")]{if ui.add_enabled(!self.demo,egui::Button::new(label)).clicked(){self.desktop_action(action,None,label);}}
                });
                ui.horizontal_wrapped(|ui|{
                    for(action,label)in[(DesktopAction::IpBackup,"备份 Radmin IP"),(DesktopAction::IpReset,"重置虚拟 IP"),(DesktopAction::IpChangeMac,"切换虚拟 MAC")]{if ui.add_enabled(!self.demo,egui::Button::new(label)).clicked(){self.desktop_action(action,None,label);}}
                });
            });ui.add_space(14.0);
            card(ui,self.palette,|ui|{
                ui.label(RichText::new("Radmin 远程工具").strong());
                ui.label(if desktop::viewer_path().is_some(){"已检测到 Radmin Viewer"}else{"未安装 Radmin Viewer"});
                ui.label("支持完全控制、仅查看、文件传输、Telnet、远程关机、文本/语音聊天和消息。对端需要 Radmin Server 和相应权限。");
                if ui.add_enabled(!self.demo,egui::Button::new("启动官方 Radmin Server 安装向导")).clicked(){self.desktop_action(DesktopAction::InstallServer,None,"启动 Radmin Server 安装向导");}
            });ui.add_space(14.0);
            card(ui,self.palette,|ui|{
                ui.label(RichText::new("帮助与支持").strong());
                ui.horizontal_wrapped(|ui|{for(action,label)in[(DesktopAction::Help,"使用帮助 F1"),(DesktopAction::Community,"社区"),(DesktopAction::Bug,"报告问题"),(DesktopAction::Feature,"建议功能")]{if ui.button(label).clicked(){self.desktop_action(action,None,label);}}});
                ui.separator();ui.label(format!("RvpnKit {} · 非官方开源客户端",env!("CARGO_PKG_VERSION")));ui.label("官方基线：Radmin VPN 2.1.4951.1 · 协议兼容依赖官方服务");
                ui.hyperlink_to("源代码与功能对照表","https://github.com/block-fox/rvpnkit");
            });
        });
    }
    pub(super) fn peer_actions(&mut self, ui: &mut egui::Ui, peer: &MemberInfo) {
        ui.horizontal_wrapped(|ui| {
            for (value, label) in [
                (peer.virtual_ip.as_ref(), "复制 IPv4"),
                (peer.virtual_ipv6.as_ref(), "复制 IPv6"),
                (Some(&peer.label()), "复制名称"),
            ] {
                if ui
                    .add_enabled(value.is_some(), egui::Button::new(label))
                    .clicked()
                {
                    ui.output_mut(|o| o.copied_text = value.cloned().unwrap_or_default());
                }
            }
            for (action, label) in [
                (DesktopAction::Ping, "Ping"),
                (DesktopAction::SharedFolders, "共享文件夹"),
            ] {
                if ui
                    .add_enabled(
                        peer.virtual_ip.is_some() && !self.demo,
                        egui::Button::new(label),
                    )
                    .clicked()
                {
                    self.desktop_action(action, peer.virtual_ip.clone(), label);
                }
            }
        });
        ui.menu_button("Radmin Viewer", |ui| {
            for (action, label) in VIEWER_ACTIONS {
                if ui
                    .add_enabled(
                        peer.virtual_ip.is_some() && !self.demo,
                        egui::Button::new(label),
                    )
                    .clicked()
                {
                    self.desktop_action(action, peer.virtual_ip.clone(), label);
                    ui.close_menu();
                }
            }
        });
    }
    pub(super) fn client_dialogs(&mut self, ctx: &egui::Context) {
        if let Some((action, address, label)) = self.client.tool_confirm.clone() {
            let mut close = false;
            let mut run = false;
            egui::Window::new("打开外部工具")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(RichText::new(label).strong());
                    if let Some(ip) = &address {
                        ui.label(format!("目标虚拟地址：{ip}"));
                    }
                    ui.label("即将启动系统或官方组件。远程功能仍会要求对端授权。");
                    ui.horizontal(|ui| {
                        close = ui.button("取消").clicked();
                        run = ui.button("继续").clicked();
                    });
                });
            if close || run {
                self.client.tool_confirm = None;
            }
            if run {
                self.busy = true;
                self.submit(Job::Desktop(action, address));
            }
        }
        if let Some(output) = self.client.output.clone() {
            let mut open = true;
            egui::Window::new("工具结果")
                .open(&mut open)
                .default_width(650.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(460.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new(&output).monospace());
                        });
                    if ui.button("复制结果").clicked() {
                        ui.output_mut(|o| o.copied_text = output.clone());
                    }
                });
            if !open {
                self.client.output = None;
            }
        }
        if let Some(net) = self.client.network.clone() {
            let mut open = true;
            egui::Window::new(format!("网络属性 · {}", net.name))
                .open(&mut open)
                .default_width(510.0)
                .show(ctx, |ui| {
                    egui::Grid::new("network_properties")
                        .num_columns(2)
                        .spacing([22.0, 12.0])
                        .show(ui, |ui| {
                            for (key, value) in [
                                ("网络名称", net.name.clone()),
                                ("网络 GUID", net.guid_hex()),
                                ("成员", net.members.len().to_string()),
                                (
                                    "我的角色",
                                    match net.role {
                                        Some(2) => "管理员",
                                        Some(1) => "成员",
                                        Some(3) => "申请人",
                                        _ => "未知",
                                    }
                                    .into(),
                                ),
                                (
                                    "类型",
                                    net.network_type
                                        .map(|v| format!("{v}"))
                                        .unwrap_or_else(|| "未知".into()),
                                ),
                                (
                                    "网络状态",
                                    match net.enabled {
                                        Some(true) => "已启用",
                                        Some(false) => "已禁用",
                                        None => "未知",
                                    }
                                    .into(),
                                ),
                            ] {
                                ui.label(key);
                                ui.label(value);
                                ui.end_row();
                            }
                        });
                    ui.separator();
                    ui.label(format!("禁止新成员：{}", bool_text(net.block_new_members)));
                    ui.label(format!(
                        "允许无密码申请：{}",
                        bool_text(net.allow_passwordless)
                    ));
                    ui.label("高级参数和密码修改目前需使用官方窗口；未猜测未验证的写协议。");
                    if ui
                        .add_enabled(
                            !self.demo,
                            egui::Button::new("在官方客户端中管理参数 / 密码"),
                        )
                        .clicked()
                    {
                        self.desktop_action(
                            DesktopAction::Official,
                            None,
                            "打开官方客户端的网络属性",
                        );
                    }
                    if let Some(url) = net.community.as_ref().filter(|s| s.starts_with("https://"))
                    {
                        ui.hyperlink_to("访问网络社区", url);
                    }
                });
            if !open {
                self.client.network = None;
            }
        }
        self.network_form(ctx);
    }
    fn network_form(&mut self, ctx: &egui::Context) {
        let Some(create) = self.client.create else {
            return;
        };
        let mut open = true;
        let mut submit = false;
        egui::Window::new(if create {
            "创建网络"
        } else {
            "加入网络"
        })
        .open(&mut open)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(420.0)
        .show(ctx, |ui| {
            ui.label("网络名称（最多 20 个字符）");
            ui.add(
                egui::TextEdit::singleline(&mut self.join_input)
                    .char_limit(20)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
            ui.label(if create {
                "密码（至少 6 个字符）"
            } else {
                "密码（游戏网络和申请加入时可留空）"
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.password_input)
                    .password(!self.client.reveal_password)
                    .char_limit(256)
                    .desired_width(f32::INFINITY),
            );
            if create {
                ui.label("确认密码");
                ui.add(
                    egui::TextEdit::singleline(&mut self.client.confirm_password)
                        .password(!self.client.reveal_password)
                        .char_limit(256)
                        .desired_width(f32::INFINITY),
                );
            }
            ui.checkbox(&mut self.client.reveal_password, "显示密码");
            ui.add_space(10.0);
            submit = ui
                .add_enabled(
                    self.can_write && !self.busy,
                    egui::Button::new(if create { "创建" } else { "加入" }),
                )
                .clicked();
        });
        if !open {
            self.client.create = None;
            self.password_input.clear();
            self.client.confirm_password.clear();
        }
        if submit {
            let name = self.join_input.trim();
            let validation = rvpn_core::operation::validate_name(name)
                .and_then(|_| {
                    if create || !self.password_input.is_empty() {
                        rvpn_core::operation::validate_password(&self.password_input)
                    } else {
                        Ok(())
                    }
                })
                .and_then(|_| {
                    if create && self.password_input != self.client.confirm_password {
                        Err("两次密码输入不一致".into())
                    } else {
                        Ok(())
                    }
                });
            if let Err(error) = validation {
                self.status = error;
            } else {
                let name = name.to_string();
                let frame = if create {
                    Commands::create_network_with_password(
                        &name,
                        &self.password_input,
                        next_request_id(),
                    )
                } else if self.password_input.is_empty() {
                    Commands::join_network(&name, next_request_id())
                } else {
                    Commands::join_network_with_password(
                        &name,
                        &self.password_input,
                        next_request_id(),
                    )
                };
                self.client.create = None;
                self.client.confirm_password.clear();
                self.queue_send(
                    frame,
                    format!("{} {name}", if create { "创建" } else { "加入" }),
                );
            }
        }
    }
}
fn bool_text(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "是",
        Some(false) => "否",
        None => "未提供",
    }
}
