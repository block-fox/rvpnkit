use super::*;
use crate::client_ui::fuzzy_match;

impl App {
    // ── 网络页
    pub(super) fn page_networks(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let count = self.state.as_ref().map(|s| s.networks.len()).unwrap_or(0);
        self.page_header(
            ui,
            "网络",
            &if count > 0 {
                format!("{count} 个")
            } else {
                String::new()
            },
        );
        self.hint(ui, "双击查看成员 · 右键管理网络 · ☆ 收藏常用网络");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.network_filter)
                    .hint_text("搜索网络名称或 GUID…")
                    .desired_width(260.0),
            );
            ui.checkbox(&mut self.favorites_only, "只看收藏");
            ui.checkbox(&mut self.private_only, "只看私有网络");
        });
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            for (create, label) in [(false, "加入私有 / 游戏网络"), (true, "创建网络")]
            {
                if ui
                    .add_enabled(self.can_write && !self.busy, egui::Button::new(label))
                    .clicked()
                {
                    self.client.create = Some(create);
                    self.password_input.clear();
                    self.client.confirm_password.clear();
                }
            }
        });
        ui.add_space(12.0);

        let Some(st) = self.state.clone() else {
            ui.label(RichText::new("暂无数据，等待刷新…").color(p.muted));
            return;
        };

        let mut pending: Option<(Vec<u8>, String)> = None;
        let mut go_members: Option<usize> = None;

        card(ui, self.palette, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, net) in st.networks.iter().enumerate() {
                        let q = self.network_filter.trim().to_lowercase();
                        if !fuzzy_match(&format!("{} {}", net.name, net.guid_hex()), &q)
                            || (self.favorites_only
                                && !self.preferences.favorites.contains(&net.guid_hex()))
                            || (self.private_only && net.network_type != Some(0))
                        {
                            continue;
                        }
                        let selected = self.selected_network == Some(i);
                        let (rect, resp) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 64.0),
                            egui::Sense::click(),
                        );
                        if ui.is_rect_visible(rect) {
                            let painter = ui.painter();
                            let fill = if selected {
                                p.accent_soft
                            } else if resp.hovered() {
                                p.panel2
                            } else {
                                Color32::TRANSPARENT
                            };
                            painter.rect_filled(rect, 6.0, fill);
                            painter.text(
                                rect.left_center() + egui::vec2(12.0, 0.0),
                                egui::Align2::LEFT_CENTER,
                                format!(
                                    "{}  {}",
                                    if self.preferences.favorites.contains(&net.guid_hex()) {
                                        "★"
                                    } else {
                                        "◇"
                                    },
                                    format!(
                                        "{}  [{}]",
                                        net.name,
                                        if net.network_type == Some(0) {
                                            "私有"
                                        } else {
                                            "公共 / 未知"
                                        }
                                    )
                                ),
                                egui::FontId::proportional(13.0),
                                if selected { p.accent } else { p.fg },
                            );
                            painter.text(
                                rect.right_center() - egui::vec2(12.0, 0.0),
                                egui::Align2::RIGHT_CENTER,
                                format!("{} 人", net.members.len()),
                                egui::FontId::proportional(11.5),
                                p.faint,
                            );
                        }

                        if resp.clicked() {
                            self.selected_network = Some(i);
                            self.selected_members.clear();
                        }
                        if resp.double_clicked() {
                            go_members = Some(i);
                        }

                        let guid = net.guid.clone();
                        let name = net.name.clone();
                        let guid_hex = net.guid_hex();
                        resp.context_menu(|ui| {
                            ui.label(RichText::new(&name).size(11.0).color(p.faint));
                            if ui
                                .button(if self.preferences.favorites.contains(&guid_hex) {
                                    "★ 取消收藏"
                                } else {
                                    "☆ 收藏网络"
                                })
                                .clicked()
                            {
                                if !self.preferences.favorites.remove(&guid_hex) {
                                    self.preferences.favorites.insert(guid_hex.clone());
                                }
                                self.save_preferences();
                                ui.close_menu();
                            }
                            if ui.button("网络属性").clicked() {
                                self.client.network = Some(net.clone());
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("查看成员").clicked() {
                                go_members = Some(i);
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("启用网络").clicked() {
                                pending = Some((
                                    Commands::set_network_enabled(&guid, true, next_request_id()),
                                    format!("启用 {name}"),
                                ));
                                ui.close_menu();
                            }
                            if ui.button("禁用网络").clicked() {
                                pending = Some((
                                    Commands::set_network_enabled(&guid, false, next_request_id()),
                                    format!("禁用 {name}"),
                                ));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("复制 GUID").clicked() {
                                ui.output_mut(|o| o.copied_text = guid_hex.clone());
                                ui.close_menu();
                            }
                            if ui.button("复制网络名").clicked() {
                                ui.output_mut(|o| o.copied_text = name.clone());
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .add_enabled(self.can_write, egui::Button::new("离开网络"))
                                .clicked()
                            {
                                pending = Some((
                                    Commands::leave_network(&guid, next_request_id()),
                                    format!("离开 {name}"),
                                ));
                                ui.close_menu();
                            }
                            if ui
                                .button(RichText::new("删除网络").color(p.danger))
                                .clicked()
                            {
                                pending = Some((
                                    Commands::delete_network(&guid, next_request_id()),
                                    format!("删除 {name}"),
                                ));
                                ui.close_menu();
                            }
                        });
                    }
                });
        });

        if let Some(i) = go_members {
            self.selected_network = Some(i);
            self.selected_members.clear();
            self.page = Page::Members;
        }
        if let Some((frame, label)) = pending {
            self.queue_send(frame, label);
        }
    }

    // ── 成员页
    pub(super) fn page_members(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let Some(net) = self.current_network().cloned() else {
            self.page_header(ui, "成员", "");
            self.hint(ui, "先在「我的网络」页选中一个网络");
            return;
        };

        self.page_header(
            ui,
            "成员",
            &format!("{} · {} 人", net.name, net.members.len()),
        );
        self.hint(
            ui,
            "双击查看属性 · 右键 Ping / 共享 / 远程工具 · 状态来自服务快照",
        );
        self.member_tools(ui);

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("筛选别名 / IP / 节点 ID")
                    .desired_width(230.0),
            );
            if ui.button("全选").clicked() {
                let q = self.filter.trim().to_lowercase();
                for m in &net.members {
                    if format!(
                        "{} {} {}",
                        m.node_id,
                        m.alias.as_deref().unwrap_or(""),
                        m.public_ip.as_deref().unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&q)
                    {
                        if self
                            .state
                            .as_ref()
                            .and_then(|s| s.me.as_ref())
                            .is_none_or(|me| me.node_id != m.node_id)
                        {
                            self.selected_members.insert(m.node_id);
                        }
                    }
                }
            }
            if ui.button("清空选择").clicked() {
                self.selected_members.clear();
            }
        });
        ui.add_space(10.0);

        if !self.selected_members.is_empty() {
            let ids: Vec<u64> = self.selected_members.iter().copied().collect();
            let mut op: Option<&str> = None;
            let mut copy_ids = false;

            egui::Frame::default()
                .fill(p.accent_soft)
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{} 个已选", ids.len()))
                                .size(12.5)
                                .strong()
                                .color(p.accent),
                        );
                        ui.add_space(6.0);
                        if ui
                            .add_enabled(
                                self.can_write && !self.busy && net.can_manage(),
                                egui::Button::new("授权管理员"),
                            )
                            .clicked()
                        {
                            op = Some("grant");
                        }
                        if ui
                            .add_enabled(
                                self.can_write && !self.busy && net.can_manage(),
                                egui::Button::new("撤销管理员"),
                            )
                            .clicked()
                        {
                            op = Some("revoke");
                        }
                        if ui
                            .button(RichText::new("踢出网络").color(p.danger))
                            .clicked()
                        {
                            op = Some("kick");
                        }
                        if ui.button("复制节点 ID").clicked() {
                            copy_ids = true;
                        }
                    });
                });
            ui.add_space(10.0);

            if copy_ids {
                let joined = ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                ui.output_mut(|o| o.copied_text = joined);
            }
            if let Some(op) = op {
                let code = match op {
                    "grant" => rvpn_core::CommandCode::GrantAdmin,
                    "revoke" => rvpn_core::CommandCode::RevokeAdmin,
                    _ => rvpn_core::CommandCode::KickNode,
                };
                let frames = ids
                    .iter()
                    .map(|id| {
                        Commands::member_operation(
                            code,
                            &net.guid,
                            *id,
                            &net.name,
                            next_request_id(),
                        )
                    })
                    .collect();
                self.queue_commands(frames, format!("{op} {} 位成员 · {}", ids.len(), net.name));
            }
        }

        self.member_filters(ui);
        let rows = self.member_rows(&net);

        if rows.is_empty() {
            ui.label(RichText::new("没有匹配的成员").color(p.muted));
            return;
        }

        let mut toggle: Option<(u64, bool)> = None;
        let mut open_props: Option<MemberInfo> = None;
        let mut pending: Option<(Vec<u8>, String)> = None;

        card(ui, self.palette, |ui| {
            egui_extras::TableBuilder::new(ui)
                .striped(false)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(egui_extras::Column::exact(34.0))
                .column(egui_extras::Column::exact(120.0))
                .column(egui_extras::Column::remainder())
                .column(egui_extras::Column::exact(150.0))
                .column(egui_extras::Column::exact(110.0))
                .header(24.0, |mut header| {
                    header.col(|_ui| {});
                    header.col(|ui| {
                        ui.label(RichText::new("节点 ID").size(11.5).color(p.faint));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("别名").size(11.5).color(p.faint));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("云端节点 IP").size(11.5).color(p.faint));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("虚拟 IP").size(11.5).color(p.faint));
                    });
                })
                .body(|body| {
                    body.rows(
                        if self.preferences.compact { 28.0 } else { 40.0 },
                        rows.len(),
                        |mut row| {
                            let i = row.index();
                            let m = rows[i].clone();
                            let checked = self.selected_members.contains(&m.node_id);

                            row.col(|ui| {
                                let mut c = checked;
                                if ui
                                    .add_enabled(
                                        self.state
                                            .as_ref()
                                            .and_then(|s| s.me.as_ref())
                                            .is_none_or(|me| me.node_id != m.node_id),
                                        egui::Checkbox::new(&mut c, ""),
                                    )
                                    .changed()
                                {
                                    toggle = Some((m.node_id, c));
                                }
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(m.node_id.to_string())
                                        .size(12.0)
                                        .color(p.accent)
                                        .monospace(),
                                );
                            });
                            row.col(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(m.label()).size(12.5));
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · {} · {}",
                                            m.status_text(),
                                            m.connection_text(),
                                            self.latency_label(&m)
                                        ))
                                        .size(10.0)
                                        .color(p.muted),
                                    );
                                });
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(
                                        m.public_ip.clone().unwrap_or_else(|| "-".into()),
                                    )
                                    .size(12.0)
                                    .color(p.muted)
                                    .monospace(),
                                );
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(m.virtual_ip.as_deref().unwrap_or("—"))
                                        .size(12.0)
                                        .color(p.muted)
                                        .monospace(),
                                );
                            });

                            let resp = row.response();
                            if resp.double_clicked() {
                                open_props = Some(m.clone());
                            }

                            let node = m.node_id;
                            let guid = net.guid.clone();
                            let name = net.name.clone();
                            let label = m.alias.clone().unwrap_or_else(|| format!("#{node}"));
                            let m2 = m.clone();
                            resp.context_menu(|ui| {
                                ui.label(RichText::new(&label).size(11.0).color(p.faint));
                                self.peer_actions(ui, &m2);
                                if ui
                                    .add_enabled(
                                        net.can_manage() && self.can_write,
                                        egui::Button::new("批准加入"),
                                    )
                                    .clicked()
                                {
                                    pending = Some((
                                        Commands::member_operation(
                                            rvpn_core::CommandCode::ApproveJoin,
                                            &guid,
                                            node,
                                            &name,
                                            next_request_id(),
                                        ),
                                        format!("批准 {label}"),
                                    ));
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("查看属性").clicked() {
                                    open_props = Some(m2.clone());
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui
                                    .add_enabled(
                                        net.can_manage() && self.can_write,
                                        egui::Button::new("授权管理员"),
                                    )
                                    .clicked()
                                {
                                    pending = Some((
                                        Commands::member_operation(
                                            rvpn_core::CommandCode::GrantAdmin,
                                            &guid,
                                            node,
                                            &name,
                                            next_request_id(),
                                        ),
                                        format!("授权 {label}"),
                                    ));
                                    ui.close_menu();
                                }
                                if ui
                                    .add_enabled(
                                        net.can_manage() && self.can_write,
                                        egui::Button::new("撤销管理员"),
                                    )
                                    .clicked()
                                {
                                    pending = Some((
                                        Commands::member_operation(
                                            rvpn_core::CommandCode::RevokeAdmin,
                                            &guid,
                                            node,
                                            &name,
                                            next_request_id(),
                                        ),
                                        format!("撤权 {label}"),
                                    ));
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("复制节点 ID").clicked() {
                                    ui.output_mut(|o| o.copied_text = node.to_string());
                                    ui.close_menu();
                                }
                                if ui.button("复制云端节点 IP").clicked() {
                                    let ip = m2.public_ip.clone().unwrap_or_default();
                                    ui.output_mut(|o| o.copied_text = ip);
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui
                                    .button(RichText::new("踢出网络").color(p.danger))
                                    .clicked()
                                {
                                    pending = Some((
                                        Commands::member_operation(
                                            rvpn_core::CommandCode::KickNode,
                                            &guid,
                                            node,
                                            &name,
                                            next_request_id(),
                                        ),
                                        format!("踢出 {label}"),
                                    ));
                                    ui.close_menu();
                                }
                            });
                        },
                    );
                });
        });

        if let Some((id, on)) = toggle {
            if on {
                self.selected_members.insert(id);
            } else {
                self.selected_members.remove(&id);
            }
        }
        if let Some(m) = open_props {
            self.props = Some(m);
        }
        if let Some((frame, label)) = pending {
            self.queue_send(frame, label);
        }
    }

    // ── 公共网络页
    pub(super) fn page_public(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        self.page_header(
            ui,
            "公共网络",
            &if self.public_list.is_empty() {
                String::new()
            } else {
                format!("{} 个可加入", self.public_list.len())
            },
        );
        self.hint(ui, "这里只列出可加入的网络；成员、踢人等操作在「成员」页");

        let mut do_search = false;
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("搜索：DOTA / Minecraft / Valorant …")
                    .desired_width(300.0),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                do_search = true;
            }
            if ui.button("搜索").clicked() {
                do_search = true;
            }
            if ui.button("加入选中").clicked() {
                if let Some(i) = self.public_selected {
                    if let Some(name) = self.public_list.get(i).cloned() {
                        self.queue_send(
                            Commands::join_network(&name, next_request_id()),
                            format!("加入 {name}"),
                        );
                    }
                }
            }
        });
        ui.add_space(10.0);

        if do_search && !self.busy {
            if self.demo {
                self.public_list = vec!["Minecraft · 像素之旅".into(), "Terraria · 新世界".into()];
                self.public_list
                    .retain(|n| n.to_lowercase().contains(&self.search.to_lowercase()));
                self.public_selected = (!self.public_list.is_empty()).then_some(0);
            } else {
                self.busy = true;
                self.submit(Job::Public(self.search.clone()));
            }
        }

        if self.public_list.is_empty() {
            ui.label(
                RichText::new("点击搜索，从服务获取可加入的公共网络")
                    .size(12.0)
                    .color(p.muted),
            );
            return;
        }

        let mut join: Option<String> = None;
        let items = self.public_list.clone();
        card(ui, self.palette, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, name) in items.iter().enumerate() {
                        let selected = self.public_selected == Some(i);
                        let (rect, resp) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::Sense::click(),
                        );
                        if ui.is_rect_visible(rect) {
                            let painter = ui.painter();
                            let fill = if selected {
                                p.accent_soft
                            } else if resp.hovered() {
                                p.panel2
                            } else {
                                Color32::TRANSPARENT
                            };
                            painter.rect_filled(rect, 6.0, fill);
                            painter.text(
                                rect.left_center() + egui::vec2(12.0, 0.0),
                                egui::Align2::LEFT_CENTER,
                                name,
                                egui::FontId::proportional(12.5),
                                if selected { p.accent } else { p.fg },
                            );
                        }
                        if resp.clicked() {
                            self.public_selected = Some(i);
                        }
                        if resp.double_clicked() {
                            join = Some(name.clone());
                        }
                        let n2 = name.clone();
                        resp.context_menu(|ui| {
                            if ui.button("加入这个网络").clicked() {
                                join = Some(n2.clone());
                                ui.close_menu();
                            }
                            if ui.button("复制网络名").clicked() {
                                ui.output_mut(|o| o.copied_text = n2.clone());
                                ui.close_menu();
                            }
                        });
                    }
                });
        });

        if let Some(name) = join {
            self.queue_send(
                Commands::join_network(&name, next_request_id()),
                format!("加入 {name}"),
            );
        }
    }

    // ── 设置页
    pub(super) fn page_settings(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        self.page_header(ui, "设置", "");
        self.hint(ui, "外观、别名与连接信息");
        self.workspace_settings(ui);

        card(ui, self.palette, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("主题").size(13.0).color(p.fg));
                    ui.label(
                        RichText::new("浅色 / 深色，立即生效并记住选择")
                            .size(11.0)
                            .color(p.faint),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.selectable_label(self.dark, "深色").clicked() && !self.dark {
                        self.dark = true;
                        self.palette = Palette::by_dark(true);
                        self.save_preferences();
                    }
                    if ui.selectable_label(!self.dark, "浅色").clicked() && self.dark {
                        self.dark = false;
                        self.palette = Palette::by_dark(false);
                        self.save_preferences();
                    }
                });
            });
        });

        ui.add_space(12.0);

        card(ui, self.palette, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("本机别名").size(13.0).color(p.fg));
                    ui.label(
                        RichText::new("改名后其他成员看到的名字会变")
                            .size(11.0)
                            .color(p.faint),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(self.can_write && !self.busy, egui::Button::new("应用"))
                        .clicked()
                    {
                        let alias = self.alias_input.trim().to_string();
                        if !alias.is_empty() {
                            self.queue_send(
                                Commands::change_alias(&alias, next_request_id()),
                                format!("改别名 → {alias}"),
                            );
                        }
                    }
                    if self.alias_input.is_empty() {
                        let cur = self
                            .state
                            .as_ref()
                            .and_then(|s| s.me.as_ref())
                            .and_then(|m| m.alias.clone())
                            .unwrap_or_default();
                        self.alias_input = cur;
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.alias_input)
                            .char_limit(64)
                            .hint_text("新别名")
                            .desired_width(200.0),
                    );
                });
            });
        });

        ui.add_space(12.0);

        card(ui, self.palette, |ui| {
            let kv = |ui: &mut egui::Ui, k: &str, v: RichText| {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [96.0, 18.0],
                        egui::Label::new(RichText::new(k).size(12.5).color(p.muted)),
                    );
                    ui.label(v);
                });
            };
            kv(
                ui,
                "管道路径",
                RichText::new(DEFAULT_PIPE)
                    .size(12.0)
                    .monospace()
                    .color(p.muted),
            );
            kv(ui, "后端", RichText::new(&self.backend).size(12.5));
            kv(
                ui,
                "权限",
                if self.can_write {
                    RichText::new("可读写").size(12.5).color(p.ok)
                } else {
                    RichText::new(if self.demo {
                        "演示模式 · 所有服务写入已禁用"
                    } else {
                        "只读连接 · 请检查服务权限"
                    })
                    .size(12.5)
                    .color(p.warn)
                },
            );
            let node = self
                .state
                .as_ref()
                .and_then(|s| s.me.as_ref())
                .map(|m| format!("#{}", m.node_id))
                .unwrap_or_else(|| "—".into());
            kv(
                ui,
                "本机节点 ID",
                RichText::new(node).size(12.0).monospace().color(p.muted),
            );
        });

        ui.add_space(12.0);

        card(ui, self.palette, |ui| {
            ui.label(RichText::new("已知限制").size(13.0).strong().color(p.fg));
            ui.add_space(6.0);
            let items = [
                (
                    "密码网络",
                    "已支持。令牌算法逆向自客户端并通过五组抓包样本与活体加入验证；界面里填密码即可加入或创建。",
                ),
                (
                    "成员的虚拟 IP / IPv6 / 通道类型",
                    "这些属于数据面信息，控制面快照只提供别名、云端节点 IP 和节点 ID。",
                ),
                (
                    "网络改名",
                    "官方客户端本身也没有入口（CUpdateNetwork 不可达）。",
                ),
            ];
            for (title, detail) in items {
                ui.label(RichText::new(title).size(12.5).color(p.fg));
                ui.label(RichText::new(detail).size(11.0).color(p.faint));
                ui.add_space(7.0);
            }
        });
    }
}
