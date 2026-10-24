//! Workspace pages and reusable UI actions, separate from service I/O.
use super::*;
use rvpn_core::presentation::{csv_field, state_json};

impl App {
    pub(super) fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some((frames, label)) = self.confirm.clone() else {
            return;
        };
        let mut confirm = false;
        let mut cancel = false;
        egui::Window::new("确认操作请求")
            .collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(390.0).show(ctx, |ui| {
                ui.label(RichText::new(&label).strong().size(16.0));
                ui.add_space(10.0);
                ui.label("命令发送后由 Radmin VPN 服务处理，发送成功不代表操作已完成。请确认目标网络与成员正确。");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    cancel = ui.button("取消").clicked();
                    confirm = ui.add_enabled(self.can_write && self.connected && !self.busy && !self.demo, egui::Button::new(RichText::new("确认发送请求").color(self.palette.accent))).clicked();
                });
            });
        if cancel {
            self.confirm = None;
        }
        if confirm {
            self.confirm = None;
            self.busy = true;
            self.submit(Job::Send(frames, label));
        }
    }

    pub(super) fn page_overview(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        egui::ScrollArea::vertical().show(ui, |ui| {
            self.page_header(ui, "一切就绪，准备联机。", "YOUR NETWORK, AT A GLANCE");
            self.hint(ui, "网络、伙伴和下一场冒险，都在这里。");
            if self.demo {
                ui.label(
                    RichText::new("演示工作空间 · 示例数据 · 所有真实服务写入已禁用")
                        .color(p.accent),
                );
            } else if !self.connected {
                card(ui, p, |ui| {
                    ui.label(RichText::new("暂时无法连接本地服务").strong().color(p.warn));
                    ui.label("请启动 Radmin VPN，然后点击顶部刷新。已有数据会保留供你查看。");
                });
                ui.add_space(12.0);
            }
            let hero_fill = if self.dark {
                p.panel2
            } else {
                Color32::from_rgb(234, 242, 238)
            };
            egui::Frame::default()
                .fill(hero_fill)
                .rounding(14.0)
                .inner_margin(26.0)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 176.0),
                        egui::Sense::hover(),
                    );
                    let painter = ui.painter();
                    let fg = if self.dark {
                        p.fg
                    } else {
                        Color32::from_rgb(49, 76, 69)
                    };
                    painter.text(
                        rect.min,
                        egui::Align2::LEFT_TOP,
                        if self.demo {
                            "●  只读演示工作空间"
                        } else if self.connected {
                            "●  已读取本地服务快照"
                        } else {
                            "○  等待连接本地服务"
                        },
                        egui::FontId::proportional(11.0),
                        p.ok,
                    );
                    painter.text(
                        rect.min + egui::vec2(0.0, 31.0),
                        egui::Align2::LEFT_TOP,
                        "让每一次联机，\n都近在身边。",
                        egui::FontId::proportional(28.0),
                        fg,
                    );
                    painter.text(
                        rect.left_bottom(),
                        egui::Align2::LEFT_BOTTOM,
                        "一个安静、有序的网络工作空间。和伙伴们一起，从这里出发。",
                        egui::FontId::proportional(11.0),
                        p.muted,
                    );
                    if rect.width() > 660.0 {
                        let center = rect.right_center() - egui::vec2(113.0, 6.0);
                        painter.circle_stroke(
                            center,
                            72.0,
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(187, 207, 195)),
                        );
                        for (offset, label) in [
                            (egui::vec2(-80.0, -51.0), "伙伴"),
                            (egui::vec2(81.0, -45.0), "游戏"),
                            (egui::vec2(70.0, 60.0), "网络"),
                            (egui::vec2(-66.0, 63.0), "设备"),
                        ] {
                            let point = center + offset;
                            painter.line_segment(
                                [center, point],
                                egui::Stroke::new(1.0_f32, Color32::from_rgb(175, 197, 186)),
                            );
                            painter.circle_filled(point, 21.0, p.panel);
                            painter.text(
                                point,
                                egui::Align2::CENTER_CENTER,
                                label,
                                egui::FontId::proportional(10.0),
                                p.muted,
                            );
                        }
                        painter.circle_filled(center, 32.0, Color32::from_rgb(96, 135, 121));
                        painter.text(
                            center,
                            egui::Align2::CENTER_CENTER,
                            "R↗",
                            egui::FontId::proportional(25.0),
                            Color32::WHITE,
                        );
                    }
                });
            ui.add_space(18.0);
            let st = self.state.clone().unwrap_or_default();
            let unique = st
                .networks
                .iter()
                .flat_map(|n| n.members.iter().map(|m| m.node_id))
                .collect::<HashSet<_>>()
                .len();
            let favorites = st
                .networks
                .iter()
                .filter(|n| self.preferences.favorites.contains(&n.guid_hex()))
                .count();
            ui.columns(4, |cols| {
                for (i, (label, value, note)) in [
                    ("我的网络", st.networks.len(), "个联机空间"),
                    ("网络成员", unique, "位去重成员"),
                    ("成员记录", st.member_count(), "条快照记录"),
                    ("收藏网络", favorites, "个常去的地方"),
                ]
                .iter()
                .enumerate()
                {
                    card(&mut cols[i], p, |ui| {
                        ui.label(RichText::new(*label).size(11.0).color(p.muted));
                        ui.label(RichText::new(value.to_string()).size(30.0).strong());
                        ui.label(RichText::new(*note).size(10.0).color(p.faint));
                    });
                }
            });
            ui.add_space(22.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("我的网络").size(17.0).strong());
                ui.label(
                    RichText::new(format!("{} 个", st.networks.len()))
                        .size(11.0)
                        .color(p.faint),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("查看全部 →").clicked() {
                        self.page = Page::Networks;
                    }
                });
            });
            ui.add_space(10.0);
            if st.networks.is_empty() {
                card(ui, p, |ui| {
                    ui.label("还没有加入网络。前往「我的网络」，加入或创建你的第一个联机空间。");
                });
            }
            let mut preview: Vec<_> = st.networks.iter().enumerate().collect();
            preview.sort_by_key(|(_, n)| !self.preferences.favorites.contains(&n.guid_hex()));
            ui.columns(3, |cols| {
                for (col, (index, n)) in preview.into_iter().take(3).enumerate() {
                    let guid = n.guid_hex();
                    let favorite = self.preferences.favorites.contains(&guid);
                    card(&mut cols[col], p, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("网").color(p.ok).size(24.0));
                            ui.label(
                                RichText::new(if n.role == Some(2) {
                                    "管理员"
                                } else {
                                    "成员"
                                })
                                .color(p.muted)
                                .size(10.0),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .small_button(
                                            RichText::new(if favorite { "★" } else { "☆" })
                                                .color(p.accent),
                                        )
                                        .clicked()
                                    {
                                        if !self.preferences.favorites.remove(&guid) {
                                            self.preferences.favorites.insert(guid.clone());
                                        }
                                        self.save_preferences();
                                    }
                                },
                            );
                        });
                        ui.add(
                            egui::Label::new(RichText::new(&n.name).strong().size(13.0)).truncate(),
                        );
                        ui.label(
                            RichText::new(&guid[..8])
                                .monospace()
                                .size(10.0)
                                .color(p.faint),
                        );
                        ui.add_space(12.0);
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{} 位成员", n.members.len()))
                                    .color(p.muted)
                                    .size(10.0),
                            );
                            if ui.small_button("查看成员 →").clicked() {
                                self.selected_network = Some(index);
                                self.selected_members.clear();
                                self.page = Page::Members;
                            }
                        });
                    });
                }
            });
            ui.add_space(20.0);
            ui.columns(2, |cols| {
                card(&mut cols[0], p, |ui| {
                    ui.label(RichText::new("本机设备").strong());
                    ui.add_space(8.0);
                    if let Some(me) = &st.me {
                        ui.label(
                            RichText::new(me.alias.as_deref().unwrap_or("未提供别名")).size(16.0),
                        );
                        ui.label(
                            RichText::new(format!("节点 #{}", me.node_id))
                                .size(11.0)
                                .color(p.muted),
                        );
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(me.virtual_ip.as_deref().unwrap_or("虚拟 IP 未提供"))
                                    .monospace()
                                    .size(18.0),
                            );
                            if let Some(ip) = &me.virtual_ip {
                                if ui.small_button("复制 IP").clicked() {
                                    ui.output_mut(|o| o.copied_text = ip.clone());
                                }
                            }
                        });
                    } else {
                        ui.label(RichText::new("等待设备信息").color(p.muted));
                    }
                });
                card(&mut cols[1], p, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("最近活动").strong());
                        if ui.small_button("全部 →").clicked() {
                            self.page = Page::Activity;
                        }
                    });
                    for (time, message) in self.activity.iter().take(3) {
                        ui.label(RichText::new(time).size(9.0).color(p.faint));
                        ui.add(egui::Label::new(RichText::new(message).size(11.0)).truncate());
                    }
                    if self.activity.is_empty() {
                        ui.label(RichText::new("新的活动会记录在这里").color(p.muted));
                    }
                });
            });
            ui.add_space(18.0);
            ui.label(
                RichText::new("RvpnKit  ·  为一起玩的时刻而造    /    状态来自服务快照")
                    .size(10.0)
                    .color(p.faint),
            );
        });
    }

    pub(super) fn page_activity(&mut self, ui: &mut egui::Ui) {
        self.page_header(ui, "活动记录", "当前会话 · 最多 100 条");
        self.hint(ui, "记录实际收到的服务状态、操作请求和错误。时间使用 UTC。");
        if ui.button("导出活动记录").clicked() {
            let content = self
                .activity
                .iter()
                .map(|(t, m)| format!("{t}\t{m}"))
                .collect::<Vec<_>>()
                .join("\r\n");
            self.export_file("activity.txt", content.as_bytes());
        }
        ui.add_space(12.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.activity.is_empty() {
                ui.label("暂时没有活动，连接服务后新的变化会出现在这里。");
            }
            for (time, message) in &self.activity {
                card(ui, self.palette, |ui| {
                    ui.label(RichText::new(time).size(10.0).color(self.palette.faint));
                    ui.label(message);
                });
                ui.add_space(8.0);
            }
        });
    }

    pub(super) fn workspace_settings(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        card(ui, self.palette, |ui| {
            ui.horizontal(|ui| {
                ui.label("自动刷新");
                egui::ComboBox::from_id_salt("refresh_interval")
                    .selected_text(if self.preferences.refresh_seconds == 0 {
                        "手动刷新".into()
                    } else {
                        format!("每 {} 秒", self.preferences.refresh_seconds)
                    })
                    .show_ui(ui, |ui| {
                        for seconds in [0, 5, 10, 30] {
                            changed |= ui
                                .selectable_value(
                                    &mut self.preferences.refresh_seconds,
                                    seconds,
                                    if seconds == 0 {
                                        "手动刷新".into()
                                    } else {
                                        format!("每 {seconds} 秒")
                                    },
                                )
                                .changed();
                        }
                    });
                changed |= ui
                    .checkbox(&mut self.preferences.compact, "紧凑成员列表")
                    .changed();
            });
            ui.add_space(10.0);
            ui.label(
                RichText::new("导出目录（可修改）")
                    .size(11.0)
                    .color(self.palette.muted),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.export_directory)
                    .desired_width(ui.available_width()),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.state.is_some(), egui::Button::new("导出快照 JSON"))
                    .clicked()
                {
                    if let Some(st) = &self.state {
                        match serde_json::to_vec_pretty(&state_json(st, self.can_write, self.demo))
                        {
                            Ok(bytes) => self.export_file("snapshot.json", &bytes),
                            Err(e) => self.status = e.to_string(),
                        }
                    }
                }
                ui.label(
                    RichText::new("不含密码令牌；包含成员地址，请妥善保管。")
                        .size(10.0)
                        .color(self.palette.muted),
                );
            });
        });
        if changed {
            self.save_preferences();
        }
        ui.add_space(12.0);
    }

    pub(super) fn member_tools(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let previous = self.selected_network;
            egui::ComboBox::from_id_salt("member_network")
                .selected_text(
                    self.current_network()
                        .map(|n| n.name.as_str())
                        .unwrap_or("选择网络"),
                )
                .show_ui(ui, |ui| {
                    if let Some(st) = &self.state {
                        for (i, n) in st.networks.iter().enumerate() {
                            ui.selectable_value(&mut self.selected_network, Some(i), &n.name);
                        }
                    }
                });
            if previous != self.selected_network {
                self.selected_members.clear();
            }
            if ui.button("导出当前筛选 CSV").clicked() {
                if let Some(n) = self.current_network() {
                    let q = self.filter.trim().to_lowercase();
                    let mut content = String::from("\u{feff}网络,别名,节点 ID,公网 IP,虚拟 IPv4,虚拟 IPv6,状态,角色,延迟 ms\r\n");
                    for m in &self.member_rows(n) {
                        if format!(
                            "{} {} {}",
                            m.node_id,
                            m.alias.as_deref().unwrap_or(""),
                            m.public_ip.as_deref().unwrap_or("")
                        )
                        .to_lowercase()
                        .contains(&q)
                        {
                            content.push_str(
                                &[
                                    n.name.as_str(),
                                    m.alias.as_deref().unwrap_or(""),
                                    &m.node_id.to_string(),
                                    m.public_ip.as_deref().unwrap_or(""),
                                    m.virtual_ip.as_deref().unwrap_or(""),m.virtual_ipv6.as_deref().unwrap_or(""),m.status_text(),m.role_text(),&m.latency_ms.map(|v|v.to_string()).unwrap_or_default(),
                                ]
                                .iter()
                                .map(|s| csv_field(s))
                                .collect::<Vec<_>>()
                                .join(","),
                            );
                            content.push_str("\r\n");
                        }
                    }
                    self.export_file("members.csv", content.as_bytes());
                }
            }
        });
        ui.add_space(10.0);
    }

    fn export_file(&mut self, suffix: &str, bytes: &[u8]) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let directory = std::path::PathBuf::from(self.export_directory.trim());
        let path = directory.join(format!("rvpnkit-{timestamp}-{suffix}"));
        let result = std::fs::create_dir_all(&directory).and_then(|_| std::fs::write(&path, bytes));
        self.status = match result {
            Ok(()) => format!("已导出：{}", path.display()),
            Err(e) => format!("导出失败：{e}"),
        };
        let message = self.status.clone();
        self.record(&message);
    }
}
