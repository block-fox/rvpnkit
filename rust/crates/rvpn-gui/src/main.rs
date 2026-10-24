//! Radmin VPN 图形客户端（egui）。
//!
//! 布局按「左侧分页栏 + 右键上下文菜单」设计，避免把所有按钮挤在一行：
//!
//! ```text
//! ┌──────────┬────────────────────────────────────────────┐
//! │ Radmin   │ 顶栏：电源开关 · 本机信息 · 刷新           │
//! │ Kit      ├────────────────────────────────────────────┤
//! │          │                                            │
//! │ 网络     │   内容区（随左侧页面切换）                 │
//! │ 成员     │   右键行可弹出上下文菜单                   │
//! │ 公共网络 │                                            │
//! │ 设置     │                                            │
//! ├──────────┴────────────────────────────────────────────┤
//! │ 状态栏：后端 / 只读提示 / 最近操作                     │
//! └───────────────────────────────────────────────────────┘
//! ```

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use rvpn_core::commands::next_request_id;
use rvpn_core::pipe::PipeClient;
use rvpn_core::{Commands, PublicNetworks, SnapshotState, DEFAULT_PIPE};

// ───────────────────────────────────────────────────────── 主题色
const BG: Color32 = Color32::from_rgb(0x14, 0x17, 0x1e);
const PANEL: Color32 = Color32::from_rgb(0x1a, 0x1e, 0x27);
const ACCENT: Color32 = Color32::from_rgb(0x7a, 0xa2, 0xf7);
const GOOD: Color32 = Color32::from_rgb(0x9e, 0xce, 0x6a);
const WARN: Color32 = Color32::from_rgb(0xe0, 0xaf, 0x68);
const DIM: Color32 = Color32::from_rgb(0x8b, 0x98, 0xab);

/// 左侧页面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Networks,
    Members,
    Public,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Page::Networks => "网络",
            Page::Members => "成员",
            Page::Public => "公共网络",
            Page::Settings => "设置",
        }
    }

    fn all() -> [Page; 4] {
        [Page::Networks, Page::Members, Page::Public, Page::Settings]
    }
}

/// 后台线程回传的消息。
enum Msg {
    State(SnapshotState, bool),
    Public(Vec<String>),
    Sent(String),
    Error(String),
}

/// 待执行的后台任务。
enum Job {
    Refresh,
    Public(String),
    Send(Vec<u8>, String),
}

struct App {
    page: Page,
    state: Option<SnapshotState>,
    selected_network: Option<usize>,
    selected_member: Option<usize>,
    public_list: Vec<String>,
    public_selected: Option<usize>,
    search: String,
    alias_input: String,
    join_input: String,
    status: String,
    can_write: bool,
    busy: bool,
    power_on: bool,
    last_refresh: Instant,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    job_tx: Option<Sender<Job>>,
    backend: String,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        setup_style(&cc.egui_ctx);

        let (tx, rx) = channel();

        // 后台工作线程：所有管道 I/O 都在这里，避免卡界面
        let (job_tx, job_rx) = channel::<Job>();
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    match job {
                        Job::Refresh => match read_state() {
                            Ok((st, can_write)) => {
                                let _ = tx.send(Msg::State(st, can_write));
                            }
                            Err(e) => {
                                let _ = tx.send(Msg::Error(e));
                            }
                        },
                        Job::Public(search) => match read_public(&search) {
                            Ok(list) => {
                                let _ = tx.send(Msg::Public(list));
                            }
                            Err(e) => {
                                let _ = tx.send(Msg::Error(e));
                            }
                        },
                        Job::Send(frame, label) => match send_frame(&frame) {
                            Ok(()) => {
                                let _ = tx.send(Msg::Sent(label));
                            }
                            Err(e) => {
                                let _ = tx.send(Msg::Error(e));
                            }
                        },
                    }
                }
            });
        }

        let mut app = Self {
            page: Page::Networks,
            state: None,
            selected_network: None,
            selected_member: None,
            public_list: Vec::new(),
            public_selected: None,
            search: String::new(),
            alias_input: String::new(),
            join_input: String::new(),
            status: "正在读取状态…".into(),
            can_write: true,
            busy: true,
            power_on: true,
            last_refresh: Instant::now(),
            tx: tx.clone(),
            rx,
            job_tx: Some(job_tx),
            backend: "直连管道".into(),
        };
        app.submit(Job::Refresh);
        app
    }

    fn submit(&self, job: Job) {
        if let Some(tx) = &self.job_tx {
            let _ = tx.send(job);
        }
    }

    fn queue_send(&mut self, frame: Vec<u8>, label: impl Into<String>) {
        if !self.can_write {
            self.status = "只读连接，无法下发命令".into();
            return;
        }
        self.busy = true;
        self.submit(Job::Send(frame, label.into()));
    }

    fn pump(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::State(st, can_write) => {
                    self.can_write = can_write;
                    self.state = Some(st);
                    self.busy = false;
                    self.last_refresh = Instant::now();
                    self.clamp_selection();
                    self.status = self.summary();
                }
                Msg::Public(list) => {
                    self.busy = false;
                    self.status = format!("公共网络 {} 个", list.len());
                    self.public_list = list;
                    self.public_selected = if self.public_list.is_empty() {
                        None
                    } else {
                        Some(0)
                    };
                }
                Msg::Sent(label) => {
                    self.busy = false;
                    self.status = format!("已请求：{label}");
                    self.submit(Job::Refresh);
                }
                Msg::Error(e) => {
                    self.busy = false;
                    self.status = format!("错误：{e}");
                }
            }
        }
    }

    fn clamp_selection(&mut self) {
        let n = self.state.as_ref().map(|s| s.networks.len()).unwrap_or(0);
        if n == 0 {
            self.selected_network = None;
            self.selected_member = None;
            return;
        }
        if self.selected_network.unwrap_or(0) >= n {
            self.selected_network = Some(n - 1);
        }
        self.selected_network.get_or_insert(0);
        self.clamp_member();
    }

    fn clamp_member(&mut self) {
        let count = self.current_network().map(|n| n.members.len()).unwrap_or(0);
        if count == 0 {
            self.selected_member = None;
        } else if self.selected_member.unwrap_or(0) >= count {
            self.selected_member = Some(count - 1);
        }
    }

    fn current_network(&self) -> Option<&rvpn_core::NetworkInfo> {
        let st = self.state.as_ref()?;
        st.networks.get(self.selected_network?)
    }

    fn summary(&self) -> String {
        match &self.state {
            None => "无状态".into(),
            Some(st) => {
                let me = st
                    .me
                    .as_ref()
                    .map(|m| {
                        format!(
                            "{} · #{} · {}",
                            m.alias.clone().unwrap_or_else(|| "?".into()),
                            m.node_id,
                            m.public_ip.clone().unwrap_or_else(|| "?".into())
                        )
                    })
                    .unwrap_or_else(|| "本机信息不可用".into());
                format!(
                    "{me}    |    网络 {} · 成员 {} · 节点 {}",
                    st.networks.len(),
                    st.member_count(),
                    st.nodes.len()
                )
            }
        }
    }
}

// ───────────────────────────────────────────────────────── 字体与样式

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // egui 默认字体不含中文，必须从系统加载一份 CJK 字体，否则全是方块。
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\Deng.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\NotoSansCJKsc-Regular.otf",
    ];

    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
            if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                list.insert(0, "cjk".to_owned());
            }
            if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                list.push("cjk".to_owned());
            }
            ctx.set_fonts(fonts);
            return;
        }
    }
}

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(0x0f, 0x12, 0x18);
    style.visuals.widgets.noninteractive.bg_fill = PANEL;
    style.visuals.selection.bg_fill = Color32::from_rgb(0x2c, 0x3d, 0x66);
    style.visuals.selection.stroke.color = ACCENT;
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    ctx.set_style(style);
}

// ───────────────────────────────────────────────────────── 管道操作

fn read_state() -> Result<(SnapshotState, bool), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    let can_write = pipe.can_write();
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;
    Ok((SnapshotState::parse(&raw), can_write))
}

fn read_public(search: &str) -> Result<Vec<String>, String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("只读连接无法枚举公共网络（需要可写）".into());
    }
    let frame = Commands::enum_public_networks("", next_request_id());
    pipe.send(&frame).map_err(|e| e.to_string())?;
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;

    // 已加入的名字要排除
    let joined: Vec<String> = {
        let mut p2 = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
        let r2 = p2
            .read_snapshot(Duration::from_millis(1500))
            .map_err(|e| e.to_string())?;
        SnapshotState::parse(&r2)
            .networks
            .into_iter()
            .map(|n| n.name)
            .collect()
    };

    Ok(PublicNetworks::available(&raw, &joined, Some(search)))
}

fn send_frame(frame: &[u8]) -> Result<(), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("当前为只读连接。若程序运行在受限环境（Low 完整性），\
                    请用普通用户身份直接启动。"
            .into());
    }
    pipe.send(frame).map_err(|e| e.to_string())
}

// ───────────────────────────────────────────────────────── UI

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump();

        // 空闲时每 6 秒自动刷新一次，让界面不至于太陈旧
        if !self.busy && self.last_refresh.elapsed() > Duration::from_secs(6) {
            self.busy = true;
            self.submit(Job::Refresh);
        }
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        self.sidebar(ctx);
        self.top_bar(ctx);
        self.status_bar(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(BG).inner_margin(egui::Margin::same(14)))
            .show(ctx, |ui| match self.page {
                Page::Networks => self.page_networks(ui),
                Page::Members => self.page_members(ui),
                Page::Public => self.page_public(ui),
                Page::Settings => self.page_settings(ui),
            });
    }
}

impl App {
    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(168.0)
            .frame(
                egui::Frame::default()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(10, 14)),
            )
            .show(ctx, |ui| {
                ui.label(RichText::new("RvpnKit").size(20.0).color(ACCENT).strong());
                ui.label(RichText::new("Radmin VPN").size(11.0).color(DIM));
                ui.add_space(16.0);

                for page in Page::all() {
                    let selected = self.page == page;
                    let text = RichText::new(page.title()).size(14.0).color(if selected {
                        Color32::WHITE
                    } else {
                        DIM
                    });

                    let resp = ui.add_sized(
                        [148.0, 32.0],
                        egui::SelectableLabel::new(selected, text),
                    );
                    if resp.clicked() {
                        self.page = page;
                    }
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(RichText::new(&self.backend).size(11.0).color(DIM));
                if !self.can_write {
                    ui.label(RichText::new("只读").size(11.0).color(WARN));
                }
            });
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top")
            .frame(
                egui::Frame::default()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(14, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // 电源开关 —— 这一次是真的接到命令上了
                    let label = if self.power_on { "⏻ 已开启" } else { "⏻ 已关闭" };
                    let btn = egui::Button::new(
                        RichText::new(label)
                            .color(if self.power_on { GOOD } else { WARN })
                            .strong(),
                    );
                    if ui.add(btn).on_hover_text("切换 VPN 总电源").clicked() {
                        let target = !self.power_on;
                        self.power_on = target;
                        self.queue_send(
                            Commands::switch_power(target, next_request_id()),
                            if target { "打开 VPN" } else { "关闭 VPN" },
                        );
                    }

                    ui.separator();

                    if ui.button("刷新").clicked() {
                        self.busy = true;
                        self.submit(Job::Refresh);
                    }

                    ui.separator();

                    let summary = self.summary();
                    ui.label(RichText::new(summary).size(12.0).color(DIM));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.busy {
                            ui.add(egui::Spinner::new().size(14.0));
                        }
                    });
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::default()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(14, 6)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.status).size(11.0).color(DIM));
                });
            });
    }

    // ── 网络页
    fn page_networks(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("网络").size(16.0).strong());
            ui.label(
                RichText::new("右键行可操作")
                    .size(11.0)
                    .color(DIM),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let hint = self
                    .join_input
                    .is_empty()
                    .then_some("网络名")
                    .unwrap_or("");
                ui.add(egui::TextEdit::singleline(&mut self.join_input).hint_text(hint).desired_width(200.0));
                if ui.button("加入").clicked() && !self.join_input.trim().is_empty() {
                    let name = self.join_input.trim().to_string();
                    self.queue_send(Commands::join_network(&name, next_request_id()), format!("加入 {name}"));
                }
                if ui.button("创建").clicked() && !self.join_input.trim().is_empty() {
                    let name = self.join_input.trim().to_string();
                    self.queue_send(
                        Commands::create_network(&name, next_request_id(), None),
                        format!("创建 {name}"),
                    );
                }
            });
        });
        ui.add_space(8.0);

        let Some(st) = self.state.clone() else {
            ui.label(RichText::new("暂无数据，等待刷新…").color(DIM));
            return;
        };

        let mut pending: Option<(Vec<u8>, String)> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, net) in st.networks.iter().enumerate() {
                let selected = self.selected_network == Some(i);
                let resp = ui.add_sized(
                    [ui.available_width(), 34.0],
                    egui::SelectableLabel::new(
                        selected,
                        RichText::new(format!("{}    ({} 人)", net.name, net.members.len()))
                            .size(13.0),
                    ),
                );

                if resp.clicked() {
                    self.selected_network = Some(i);
                    self.selected_member = None;
                }
                if resp.double_clicked() {
                    self.selected_network = Some(i);
                    self.page = Page::Members;
                }

                // 右键上下文菜单
                let guid = net.guid.clone();
                let name = net.name.clone();
                resp.context_menu(|ui| {
                    ui.label(RichText::new(&name).size(11.0).color(DIM));
                    ui.separator();
                    if ui.button("查看成员").clicked() {
                        self.selected_network = Some(i);
                        self.selected_member = None;
                        self.page = Page::Members;
                        ui.close_menu();
                    }
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
                        ui.output_mut(|o| o.copied_text = net.guid_hex());
                        ui.close_menu();
                    }
                    if ui.button("离开网络").clicked() {
                        pending = Some((
                            Commands::leave_network(&guid, next_request_id()),
                            format!("离开 {name}"),
                        ));
                        ui.close_menu();
                    }
                    if ui.button(RichText::new("删除网络").color(WARN)).clicked() {
                        pending = Some((
                            Commands::delete_network(&guid, next_request_id()),
                            format!("删除 {name}"),
                        ));
                        ui.close_menu();
                    }
                });
            }
        });

        if let Some((frame, label)) = pending {
            self.queue_send(frame, label);
        }
    }

    // ── 成员页
    fn page_members(&mut self, ui: &mut egui::Ui) {
        let Some(net) = self.current_network().cloned() else {
            ui.label(RichText::new("先在「网络」页选中一个网络").color(DIM));
            return;
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("成员 · {}", net.name)).size(16.0).strong());
            ui.label(RichText::new(format!("{} 人", net.members.len())).size(12.0).color(DIM));
            ui.label(RichText::new("右键成员可操作").size(11.0).color(DIM));
        });
        ui.add_space(8.0);

        let mut pending: Option<(Vec<u8>, String)> = None;

        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(egui_extras::Column::exact(110.0))
            .column(egui_extras::Column::remainder())
            .column(egui_extras::Column::exact(150.0))
            .header(22.0, |mut header| {
                header.col(|ui| {
                    ui.label(RichText::new("节点 ID").size(12.0).color(DIM));
                });
                header.col(|ui| {
                    ui.label(RichText::new("别名").size(12.0).color(DIM));
                });
                header.col(|ui| {
                    ui.label(RichText::new("公网 IP").size(12.0).color(DIM));
                });
            })
            .body(|body| {
                body.rows(24.0, net.members.len(), |mut row| {
                    let i = row.index();
                    let m = &net.members[i];
                    row.col(|ui| {
                        ui.label(RichText::new(m.node_id.to_string()).size(12.0).color(ACCENT));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(m.alias.clone().unwrap_or_else(|| "-".into())).size(12.0));
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(m.public_ip.clone().unwrap_or_else(|| "-".into()))
                                .size(12.0)
                                .color(GOOD),
                        );
                    });

                    let resp = row.response();
                    if resp.clicked() {
                        self.selected_member = Some(i);
                    }

                    let node = m.node_id;
                    let guid = net.guid.clone();
                    let name = net.name.clone();
                    let label = m.label();
                    resp.context_menu(|ui| {
                        ui.label(RichText::new(&label).size(11.0).color(DIM));
                        ui.separator();
                        if ui.button("授权（管理员）").clicked() {
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
                        if ui.button("撤销管理员").clicked() {
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
                        if ui.button("批准加入").clicked() {
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
                        if ui.button("复制节点 ID").clicked() {
                            ui.output_mut(|o| o.copied_text = node.to_string());
                            ui.close_menu();
                        }
                        if ui
                            .button(RichText::new("踢出网络").color(WARN))
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
                });
            });

        if let Some((frame, label)) = pending {
            self.queue_send(frame, label);
        }
    }

    // ── 公共网络页
    fn page_public(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("公共网络").size(16.0).strong());
            ui.label(RichText::new("只显示尚未加入的").size(11.0).color(DIM));
        });
        ui.add_space(6.0);

        let mut do_search = false;
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text("搜索：DOTA / Minecraft / Valorant …")
                        .desired_width(300.0),
                )
                .lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter))
            {
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

        if do_search {
            self.busy = true;
            self.submit(Job::Public(self.search.clone()));
        }

        ui.add_space(8.0);

        if self.public_list.is_empty() {
            ui.label(
                RichText::new("点「搜索」从服务器拉取可加入的公共网络（约 300 个）")
                    .size(12.0)
                    .color(DIM),
            );
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, name) in self.public_list.clone().iter().enumerate() {
                let selected = self.public_selected == Some(i);
                let resp = ui.add_sized(
                    [ui.available_width(), 26.0],
                    egui::SelectableLabel::new(selected, RichText::new(name).size(12.0)),
                );
                if resp.clicked() {
                    self.public_selected = Some(i);
                }
                if resp.double_clicked() {
                    self.queue_send(
                        Commands::join_network(name, next_request_id()),
                        format!("加入 {name}"),
                    );
                }
                resp.context_menu(|ui| {
                    if ui.button("加入这个网络").clicked() {
                        self.queue_send(
                            Commands::join_network(name, next_request_id()),
                            format!("加入 {name}"),
                        );
                        ui.close_menu();
                    }
                    if ui.button("复制网络名").clicked() {
                        ui.output_mut(|o| o.copied_text = name.clone());
                        ui.close_menu();
                    }
                });
            }
        });
    }

    // ── 设置页
    fn page_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("设置").size(16.0).strong());
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label(RichText::new("本机别名").strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let cur = self
                    .state
                    .as_ref()
                    .and_then(|s| s.me.as_ref())
                    .and_then(|m| m.alias.clone())
                    .unwrap_or_default();
                if self.alias_input.is_empty() {
                    self.alias_input = cur;
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.alias_input)
                        .hint_text("新别名")
                        .desired_width(220.0),
                );
                if ui.button("应用").clicked() {
                    let alias = self.alias_input.trim().to_string();
                    if !alias.is_empty() {
                        self.queue_send(
                            Commands::change_alias(&alias, next_request_id()),
                            format!("改别名 → {alias}"),
                        );
                    }
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label(RichText::new("连接").strong());
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("管道：{}", DEFAULT_PIPE))
                    .size(12.0)
                    .color(DIM),
            );
            ui.label(
                RichText::new(format!("后端：{}", self.backend))
                    .size(12.0)
                    .color(DIM),
            );
            ui.label(
                RichText::new(if self.can_write {
                    "权限：可读写"
                } else {
                    "权限：只读（受限环境会降低完整性级别，请用普通用户身份启动）"
                })
                .size(12.0)
                .color(if self.can_write { GOOD } else { WARN }),
            );
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label(RichText::new("已知限制").strong());
            ui.add_space(4.0);
            for line in [
                "· 创建网络暂不支持设置密码：抓到的所有创建帧都是免密码网络，密码字段位置未解",
                "· 公共网络只能加入，踢人要在「成员」页对已加入网络操作",
                "· 网络改名（CUpdateNetwork）官方客户端也没有入口，未解",
            ] {
                ui.label(RichText::new(line).size(12.0).color(DIM));
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([880.0, 560.0])
            .with_title("RvpnKit · Radmin VPN"),
        ..Default::default()
    };

    eframe::run_native(
        "RvpnKit",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
