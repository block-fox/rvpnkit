use super::*;

impl App {
    // ── 属性弹窗
    pub(super) fn props_window(&mut self, ctx: &egui::Context) {
        let Some(m) = self.props.clone() else {
            return;
        };
        let p = self.palette;
        let (net_name, _role_text) = self
            .current_network()
            .map(|n| {
                let r = match n.role {
                    Some(2) => "管理员（你是创建者）",
                    Some(1) => "普通成员",
                    _ => "—（未知）",
                };
                (n.name.clone(), r)
            })
            .unwrap_or_else(|| (String::new(), "—"));
        let mut close = false;

        egui::Window::new("props")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .min_width(430.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(m.alias.clone().unwrap_or_else(|| format!("#{}", m.node_id)))
                            .size(15.0)
                            .strong()
                            .color(p.fg),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("×").clicked() {
                            close = true;
                        }
                    });
                });
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new("名称").size(12.5).color(p.muted)),
                    );
                    ui.label(
                        RichText::new(m.alias.clone().unwrap_or_else(|| "-".into())).size(13.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new("节点 ID").size(12.5).color(p.muted)),
                    );
                    ui.label(
                        RichText::new(m.node_id.to_string())
                            .size(12.5)
                            .color(p.accent)
                            .monospace(),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new("云端节点 IP").size(12.5).color(p.muted)),
                    );
                    ui.label(
                        RichText::new(m.public_ip.clone().unwrap_or_else(|| "-".into()))
                            .size(12.5)
                            .monospace(),
                    );
                });

                ui.add_space(10.0);
                ui.label(RichText::new("网络").size(11.5).strong().color(p.accent));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new("网络名称").size(12.5).color(p.muted)),
                    );
                    ui.label(RichText::new(net_name).size(13.0));
                });
                ui.add_space(10.0);
                ui.label(RichText::new("连接").size(11.5).strong().color(p.accent));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new("角色").size(12.5).color(p.muted)),
                    );
                    ui.label(RichText::new(m.role_text()).size(12.5).color(p.ok));
                });
                for (k, value) in [
                    (
                        "虚拟 IPv4",
                        m.virtual_ip.clone().unwrap_or_else(|| "未提供".into()),
                    ),
                    (
                        "虚拟 IPv6",
                        m.virtual_ipv6.clone().unwrap_or_else(|| "未提供".into()),
                    ),
                    ("状态", m.status_text().into()),
                    (
                        "通道类型",
                        m.channel_type
                            .map(|v| format!("类型 {v}"))
                            .unwrap_or_else(|| "未知".into()),
                    ),
                    (
                        "延迟",
                        self.measured_latency(&m)
                            .filter(|_| m.online() == Some(true))
                            .map(|v| format!("{v} ms"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                    (
                        "客户端版本",
                        m.product_version.clone().unwrap_or_else(|| "未知".into()),
                    ),
                ] {
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [92.0, 18.0],
                            egui::Label::new(RichText::new(k).size(12.5).color(p.muted)),
                        );
                        ui.label(RichText::new(value).size(12.0).italics().color(p.faint));
                    });
                }

                ui.add_space(12.0);
                ui.label(
                RichText::new(
                    "信息来自服务快照。未知状态不会推测为在线。角色是该成员在当前网络内的角色。",
                )
                .size(11.0)
                .color(p.faint),
            );

                ui.add_space(12.0);
                self.peer_actions(ui, &m);
                ui.horizontal(|ui| {
                    if ui.button("复制节点 ID").clicked() {
                        ui.output_mut(|o| o.copied_text = m.node_id.to_string());
                    }
                    if ui.button("关闭").clicked() {
                        close = true;
                    }
                });
            });

        if close {
            self.props = None;
        }
    }
}
