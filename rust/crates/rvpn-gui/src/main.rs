#![cfg_attr(windows, windows_subsystem = "windows")]

//! Radmin VPN 图形客户端（egui 原生窗口）。
//!
//! 布局：
//! ```text
//! ┌──────────┬────────────────────────────────────────────┐
//! │ RvpnKit  │ 电源 · 刷新 · 本机信息                     │
//! │          ├────────────────────────────────────────────┤
//! │ 网络     │                                            │
//! │ 成员     │   内容区（随左侧页面切换）                 │
//! │ 公共网络 │   右键行可操作，双击成员看属性             │
//! │ 设置     │                                            │
//! ├──────────┴────────────────────────────────────────────┤
//! │ 状态栏                                                 │
//! └───────────────────────────────────────────────────────┘
//! ```

mod backend;
mod client_ui;
mod pages;
mod preferences;
mod properties;
mod theme;
mod visual_audit;
mod workspace;
use backend::{read_public, read_state, send_frame};
use preferences::Preferences;
use theme::Palette;

use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use rvpn_core::commands::next_request_id;
use rvpn_core::{Commands, MemberInfo, NetworkInfo, SnapshotState, DEFAULT_PIPE};

// ───────────────────────────────────────────────────────── 主题

// ───────────────────────────────────────────────────────── 页面

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Activity,
    Networks,
    Members,
    Public,
    Settings,
    Chat,
    Tools,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Page::Overview => "总览",
            Page::Activity => "活动记录",
            Page::Networks => "我的网络",
            Page::Members => "成员",
            Page::Public => "公共网络",
            Page::Settings => "设置",
            Page::Chat => "聊天",
            Page::Tools => "工具与帮助",
        }
    }

    fn all() -> [Page; 8] {
        [
            Page::Overview,
            Page::Networks,
            Page::Members,
            Page::Public,
            Page::Chat,
            Page::Tools,
            Page::Activity,
            Page::Settings,
        ]
    }
}

// ───────────────────────────────────────────────────────── 后台任务

enum Msg {
    State(SnapshotState, bool),
    Public(Vec<String>),
    Sent(String),
    Error(String),
    Tool(Result<String, String>),
}

enum Job {
    Refresh,
    Public(String),
    Send(Vec<Vec<u8>>, String),
    Desktop(rvpn_core::desktop::DesktopAction, Option<String>),
}

// ───────────────────────────────────────────────────────── 应用状态

struct App {
    page: Page,
    client: client_ui::ClientUi,
    dark: bool,
    state: Option<SnapshotState>,
    selected_network: Option<usize>,
    selected_members: HashSet<u64>,
    filter: String,
    props: Option<MemberInfo>,
    /// 首次拿到状态后自动打开第一个成员的属性（仅 --props 调试用）
    want_props: bool,
    public_list: Vec<String>,
    public_selected: Option<usize>,
    search: String,
    alias_input: String,
    join_input: String,
    /// 加入 / 创建时用的密码，留空表示免密码网络
    password_input: String,
    status: String,
    can_write: bool,
    busy: bool,
    demo: bool,
    connected: bool,
    preferences: Preferences,
    network_filter: String,
    favorites_only: bool,
    activity: VecDeque<(String, String)>,
    confirm: Option<(Vec<Vec<u8>>, String)>,
    export_directory: String,
    audit: Option<visual_audit::VisualAudit>,
    last_refresh: Instant,
    rx: Receiver<Msg>,
    job_tx: Option<Sender<Job>>,
    backend: String,
    palette: Palette,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);

        let (tx, rx) = channel();
        let (job_tx, job_rx) = channel::<Job>();
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    match job {
                        Job::Desktop(action, address) => {
                            let _ = tx.send(Msg::Tool(rvpn_core::desktop::execute(
                                action,
                                address.as_deref(),
                            )));
                        }
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
                        Job::Send(frames, label) => {
                            let mut sent = 0;
                            let result = frames.iter().try_for_each(|frame| {
                                send_frame(frame)?;
                                sent += 1;
                                Ok::<_, String>(())
                            });
                            match result {
                                Ok(()) => {
                                    let _ = tx.send(Msg::Sent(label));
                                }
                                Err(e) => {
                                    let _ = tx.send(Msg::Error(format!(
                                        "{label}：已发送 {sent} / {} 个请求；{e}",
                                        frames.len()
                                    )));
                                }
                            }
                        }
                    }
                }
            });
        }

        // 调试参数：--page=members / --dark / --props，方便截图与验证
        let preferences = Preferences::load();
        let mut dark = preferences.dark;
        let audit = visual_audit::VisualAudit::from_args();
        let demo = audit.is_some() || std::env::args().any(|a| a == "--demo");
        let mut start_page = Page::Overview;
        let mut want_props = false;
        for a in std::env::args() {
            if a == "--dark" {
                dark = true;
            } else if a == "--light" {
                dark = false;
            } else if a == "--props" {
                want_props = true;
            } else if let Some(v) = a.strip_prefix("--page=") {
                start_page = match v {
                    "overview" => Page::Overview,
                    "activity" => Page::Activity,
                    "members" => Page::Members,
                    "public" => Page::Public,
                    "settings" => Page::Settings,
                    "chat" => Page::Chat,
                    "tools" => Page::Tools,
                    _ => Page::Networks,
                };
            }
        }
        if audit.is_some() {
            dark = false;
            start_page = Page::Overview;
        }
        let mut app = Self {
            page: start_page,
            client: Default::default(),
            dark,
            state: None,
            want_props,
            selected_network: None,
            selected_members: HashSet::new(),
            filter: String::new(),
            props: None,
            public_list: Vec::new(),
            public_selected: None,
            search: String::new(),
            alias_input: String::new(),
            join_input: String::new(),
            password_input: String::new(),
            status: "正在读取状态…".into(),
            can_write: false,
            busy: true,
            audit,
            demo,
            connected: false,
            preferences,
            network_filter: String::new(),
            favorites_only: false,
            activity: VecDeque::new(),
            confirm: None,
            export_directory: std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .display()
                .to_string(),
            last_refresh: Instant::now(),
            rx,
            job_tx: Some(job_tx),
            backend: "直连管道".into(),
            palette: Palette::by_dark(dark),
        };
        if demo {
            app.state = Some(rvpn_core::presentation::demo_state());
            app.busy = false;
            app.connected = true;
            app.backend = "演示模式 · 只读".into();
            app.clamp_selection();
            app.status = "演示数据 · 不连接真实服务".into();
            app.record("已打开只读演示工作空间");
        } else {
            app.submit(Job::Refresh);
        }
        app
    }

    fn submit(&self, job: Job) {
        if let Some(tx) = &self.job_tx {
            let _ = tx.send(job);
        }
    }

    fn queue_send(&mut self, frame: Vec<u8>, label: impl Into<String>) {
        self.queue_commands(vec![frame], label.into());
    }
    fn queue_commands(&mut self, frames: Vec<Vec<u8>>, label: String) {
        if !self.can_write || !self.connected || self.demo {
            self.status = "当前连接不可写".into();
            return;
        }
        if self.busy {
            self.status = "请等待当前操作完成".into();
            return;
        }
        if let Some(state) = &self.state {
            for frame in &frames {
                if let Err(error) = rvpn_core::permissions::authorize(frame, state) {
                    self.status = error;
                    return;
                }
            }
        }
        self.confirm = Some((frames, label));
    }
    fn refresh(&mut self) {
        if self.demo || self.busy {
            return;
        }
        self.busy = true;
        self.last_refresh = Instant::now();
        self.submit(Job::Refresh);
    }
    fn save_preferences(&mut self) {
        self.preferences.dark = self.dark;
        if let Err(e) = self.preferences.save() {
            self.status = format!("无法保存设置：{e}");
        }
    }
    fn record(&mut self, message: &str) {
        if self.activity.front().is_some_and(|(_, m)| m == message) {
            return;
        }
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.activity.push_front((
            format!(
                "UTC {:02}:{:02}:{:02}",
                seconds / 3600 % 24,
                seconds / 60 % 60,
                seconds % 60
            ),
            message.to_owned(),
        ));
        self.activity.truncate(100);
    }
    fn pump(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::State(st, can_write) => {
                    let selected_guid = self.current_network().map(|n| n.guid.clone());
                    let old = self
                        .state
                        .as_ref()
                        .map(|s| (s.networks.len(), s.member_count()));
                    let counts = (st.networks.len(), st.member_count());
                    self.selected_network =
                        selected_guid.and_then(|g| st.networks.iter().position(|n| n.guid == g));
                    if !self.connected {
                        self.record("已连接服务并读取快照");
                    }
                    if old.is_some_and(|previous| previous != counts) {
                        self.record(&format!(
                            "快照变化：{} 个网络，{} 条成员记录",
                            counts.0, counts.1
                        ));
                    }
                    self.connected = true;
                    self.can_write = can_write;
                    if self.selected_network.is_none() {
                        self.selected_members.clear();
                    }
                    self.state = Some(st);
                    self.busy = false;
                    self.last_refresh = Instant::now();
                    self.clamp_selection();
                    let ids: HashSet<_> = self
                        .current_network()
                        .map(|n| n.members.iter().map(|m| m.node_id).collect())
                        .unwrap_or_default();
                    self.selected_members.retain(|id| ids.contains(id));
                    self.status = self.summary();
                    if self.want_props {
                        self.want_props = false;
                        if let Some(n) = self.current_network() {
                            if let Some(m) = n.members.first() {
                                self.props = Some(m.clone());
                            }
                        }
                    }
                }
                Msg::Public(list) => {
                    self.busy = false;
                    self.status = format!("公共网络 {} 个", list.len());
                    self.public_selected = if list.is_empty() { None } else { Some(0) };
                    self.public_list = list;
                    self.last_refresh = Instant::now();
                    self.record(&format!("公共网络搜索：{} 个结果", self.public_list.len()));
                }
                Msg::Sent(label) => {
                    self.busy = false;
                    self.status = format!("服务已确认：{label}");
                    self.record(&format!("服务已确认：{label}"));
                    self.password_input.clear();
                    self.refresh();
                }
                Msg::Error(e) => {
                    self.busy = false;
                    self.last_refresh = Instant::now();
                    self.connected = false;
                    self.can_write = false;
                    self.status = format!("错误：{e}");
                    self.record(&format!("服务错误：{e}"));
                }
                Msg::Tool(result) => {
                    self.busy = false;
                    self.last_refresh = Instant::now();
                    match result {
                        Ok(text) => {
                            self.status = "系统工具执行完成".into();
                            self.client.output = Some(text);
                        }
                        Err(error) => {
                            self.status = error.clone();
                            self.client.output = Some(error);
                        }
                    }
                }
            }
        }
        self.apply_style(ctx);
    }

    fn clamp_selection(&mut self) {
        let n = self.state.as_ref().map(|s| s.networks.len()).unwrap_or(0);
        if n == 0 {
            self.selected_network = None;
            return;
        }
        if self.selected_network.unwrap_or(0) >= n {
            self.selected_network = Some(n - 1);
        }
        self.selected_network.get_or_insert(0);
    }

    fn current_network(&self) -> Option<&NetworkInfo> {
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

    /// 按当前配色设置 egui 样式。
    fn apply_style(&self, ctx: &egui::Context) {
        let p = self.palette;
        let mut style = (*ctx.style()).clone();

        style.visuals = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        style.visuals.panel_fill = p.bg;
        style.visuals.window_fill = p.panel;
        style.visuals.faint_bg_color = p.panel2;
        style.visuals.extreme_bg_color = if self.dark {
            Color32::from_rgb(0x0b, 0x0d, 0x11)
        } else {
            Color32::from_rgb(0xfa, 0xfb, 0xfd)
        };
        style.visuals.window_stroke.color = p.border;
        style.visuals.widgets.noninteractive.bg_fill = p.panel;
        style.visuals.widgets.noninteractive.fg_stroke.color = p.fg;
        style.visuals.widgets.noninteractive.bg_stroke.color = p.border;
        style.visuals.widgets.inactive.bg_fill = p.panel2;
        style.visuals.widgets.inactive.fg_stroke.color = p.fg;
        style.visuals.widgets.inactive.bg_stroke.color = p.border;
        style.visuals.widgets.hovered.bg_fill = p.accent_soft;
        style.visuals.widgets.hovered.fg_stroke.color = p.accent;
        style.visuals.widgets.hovered.bg_stroke.color = p.accent;
        style.visuals.widgets.active.bg_fill = p.accent;
        style.visuals.widgets.active.fg_stroke.color = p.fg;
        style.visuals.selection.bg_fill = p.accent_soft;
        style.visuals.selection.stroke.color = p.accent;
        style.visuals.override_text_color = Some(p.fg);

        style.spacing.item_spacing = egui::vec2(10.0, 9.0);
        style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(10.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        style.visuals.window_rounding = egui::Rounding::same(14.0);
        style.spacing.button_padding = egui::vec2(11.0, 6.0);
        style.spacing.menu_margin = egui::Margin::same(6.0);

        ctx.set_style(style);
    }

    // ── 通用小部件

    fn page_header(&self, ui: &mut egui::Ui, title: &str, sub: &str) {
        let p = self.palette;
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).size(24.0).strong().color(p.fg));
            if !sub.is_empty() {
                ui.label(RichText::new(sub).size(12.0).color(p.faint));
            }
        });
        ui.add_space(2.0);
    }

    fn hint(&self, ui: &mut egui::Ui, text: &str) {
        ui.label(RichText::new(text).size(11.5).color(self.palette.muted));
        ui.add_space(8.0);
    }
}

// ───────────────────────────────────────────────────────── 字体

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
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
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
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

// ───────────────────────────────────────────────────────── 管道

/// 统一的「卡片」容器：面板底色 + 细边框 + 内边距。
fn card<R>(ui: &mut egui::Ui, p: Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::default()
        .fill(p.panel)
        .stroke(egui::Stroke::new(1.0_f32, p.border))
        .inner_margin(egui::Margin::same(18.0))
        .rounding(12.0)
        .show(ui, |ui| {
            // 让卡片撑满整行，而不是缩到内容宽度
            ui.set_min_width(ui.available_width());
            add(ui)
        })
        .inner
}

// ───────────────────────────────────────────────────────── eframe

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump(ctx);

        if self.preferences.refresh_seconds > 0
            && self.last_refresh.elapsed() > Duration::from_secs(self.preferences.refresh_seconds)
        {
            self.refresh();
        }
        // 即使空闲也保持低频重绘：否则某些合成器会留着上一帧的残影，
        // 表现为界面上出现窗外的桌面图案。
        ctx.request_repaint_after(if self.busy {
            Duration::from_millis(120)
        } else {
            Duration::from_millis(400)
        });

        self.sidebar(ctx);
        self.top_bar(ctx);
        self.status_bar(ctx);
        self.props_window(ctx);
        self.confirm_window(ctx);
        self.client_dialogs(ctx);
        ctx.input(|i| {
            if i.key_pressed(egui::Key::F1) {
                self.page = Page::Tools;
            }
            if i.key_pressed(egui::Key::F5) {
                self.refresh();
            }
        });

        let p = self.palette;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(p.bg)
                    .inner_margin(egui::Margin::symmetric(22.0, 18.0)),
            )
            .show(ctx, |ui| match self.page {
                Page::Overview => self.page_overview(ui),
                Page::Activity => self.page_activity(ui),
                Page::Networks => self.page_networks(ui),
                Page::Members => self.page_members(ui),
                Page::Public => self.page_public(ui),
                Page::Settings => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.page_settings(ui));
                }
                Page::Chat => self.page_chat(ui),
                Page::Tools => self.page_tools(ui),
            });
        self.visual_audit_tick(ctx);
    }
}

impl App {
    // ── 左侧栏
    fn sidebar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(204.0)
            .frame(
                egui::Frame::default()
                    .fill(Color32::from_rgb(32, 45, 61))
                    .inner_margin(egui::Margin::symmetric(12.0, 18.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("RvpnKit").size(19.0).strong().color(p.accent));
                        ui.label(RichText::new("你的联机小管家").size(10.5).color(p.faint));
                    });
                });
                ui.add_space(20.0);

                let counts = [
                    0,
                    self.state.as_ref().map(|s| s.networks.len()).unwrap_or(0),
                    self.current_network().map(|n| n.members.len()).unwrap_or(0),
                    self.public_list.len(),
                ];

                for (i, page) in Page::all().iter().enumerate() {
                    let selected = self.page == *page;
                    let bg = if selected {
                        Color32::from_rgb(52, 64, 82)
                    } else {
                        Color32::TRANSPARENT
                    };
                    let fg = if selected {
                        Color32::WHITE
                    } else {
                        Color32::from_rgb(164, 179, 196)
                    };

                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 34.0),
                        egui::Sense::click(),
                    );
                    if ui.is_rect_visible(rect) {
                        let painter = ui.painter();
                        let fill = if resp.hovered() && !selected {
                            Color32::from_rgb(44, 58, 76)
                        } else {
                            bg
                        };
                        painter.rect_filled(rect, 8.0, fill);
                        theme::nav_icon(
                            painter,
                            rect.left_center() + egui::vec2(19.0, 0.0),
                            *page,
                            fg,
                        );
                        painter.text(
                            rect.left_center() + egui::vec2(34.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            page.title(),
                            egui::FontId::proportional(13.5),
                            fg,
                        );
                        let c = counts.get(i).copied().unwrap_or(0);
                        if c > 0 {
                            painter.text(
                                rect.right_center() - egui::vec2(12.0, 0.0),
                                egui::Align2::RIGHT_CENTER,
                                c.to_string(),
                                egui::FontId::proportional(11.0),
                                if selected { p.accent } else { p.faint },
                            );
                        }
                    }
                    if resp.clicked() {
                        self.page = *page;
                    }
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(concat!("v", env!("CARGO_PKG_VERSION"), " · 本地工作空间"))
                            .size(10.5)
                            .color(p.faint),
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").size(9.0).color(if self.can_write {
                            p.ok
                        } else {
                            p.warn
                        }));
                        ui.label(
                            RichText::new(if self.can_write {
                                "可读写"
                            } else {
                                "只读"
                            })
                            .size(10.5)
                            .color(p.faint),
                        );
                    });
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").size(9.0).color(if self.connected {
                            p.ok
                        } else {
                            p.warn
                        }));
                        ui.label(RichText::new(&self.backend).size(10.5).color(p.faint));
                    });
                });
            });
    }

    // ── 顶栏
    fn top_bar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::TopBottomPanel::top("top")
            .frame(
                egui::Frame::default()
                    .fill(p.panel)
                    .inner_margin(egui::Margin::symmetric(20.0, 11.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("工作空间  /  ").color(p.muted).size(11.0));
                    ui.label(RichText::new(self.page.title()).size(12.0));
                    ui.add_space(14.0);
                    ui.menu_button("系统", |ui| {
                        if ui.button("更改名称").clicked() {
                            self.page = Page::Settings;
                            ui.close_menu();
                        }
                        if ui.button("日志与诊断").clicked() {
                            self.page = Page::Tools;
                            ui.close_menu();
                        }
                        if ui.button("设置").clicked() {
                            self.page = Page::Settings;
                            ui.close_menu();
                        }
                        if ui.button("退出").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("网络", |ui| {
                        for (create, label) in [(false, "加入网络"), (true, "创建网络")] {
                            if ui.button(label).clicked() {
                                self.client.create = Some(create);
                                self.password_input.clear();
                                self.client.confirm_password.clear();
                                ui.close_menu();
                            }
                        }
                    });
                    ui.menu_button("帮助", |ui| {
                        if ui.button("帮助与关于 F1").clicked() {
                            self.page = Page::Tools;
                            ui.close_menu();
                        }
                        if ui.button("聊天").clicked() {
                            self.page = Page::Chat;
                            ui.close_menu();
                        }
                    });
                    if ui
                        .add_enabled(!self.busy && !self.demo, egui::Button::new("↻  刷新"))
                        .clicked()
                    {
                        self.refresh();
                    }
                    ui.add_enabled_ui(
                        self.can_write && self.connected && !self.busy && !self.demo,
                        |ui| {
                            ui.menu_button("VPN 电源", |ui| {
                                ui.label(
                                    RichText::new(
                                        match self.state.as_ref().and_then(|s| s.power) {
                                            Some(true) => "当前 VPN 已开启",
                                            Some(false) => "当前 VPN 已关闭",
                                            None => "电源状态未知",
                                        },
                                    )
                                    .size(10.0),
                                );
                                for (on, label) in [(true, "请求开启 VPN"), (false, "请求关闭 VPN")]
                                {
                                    if ui.button(label).clicked() {
                                        self.queue_send(
                                            Commands::switch_power(on, next_request_id()),
                                            label,
                                        );
                                        ui.close_menu();
                                    }
                                }
                            });
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.busy {
                            ui.add(egui::Spinner::new().size(13.0));
                        }
                        let s = self
                            .state
                            .as_ref()
                            .and_then(|s| s.me.as_ref())
                            .map(|m| {
                                format!(
                                    "{}  ·  {}",
                                    m.alias.as_deref().unwrap_or("本机设备"),
                                    m.virtual_ip.as_deref().unwrap_or("虚拟 IP 未提供")
                                )
                            })
                            .unwrap_or_else(|| "等待本机设备信息".into());
                        ui.label(RichText::new(s).size(12.0).color(p.muted));
                    });
                });
            });
    }

    // ── 状态栏
    fn status_bar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::default()
                    .fill(p.panel)
                    .inner_margin(egui::Margin::symmetric(20.0, 5.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.status).size(11.0).color(p.faint));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(st) = &self.state {
                            ui.label(
                                RichText::new(format!(
                                    "网络 {} · 成员 {}",
                                    st.networks.len(),
                                    st.member_count()
                                ))
                                .size(11.0)
                                .color(p.faint),
                            );
                        }
                    });
                });
            });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(if std::env::args().any(|a| a == "--screenshot-dir") {
                [1320.0, 1040.0]
            } else {
                [1240.0, 840.0]
            })
            .with_min_inner_size([920.0, 580.0])
            .with_title("RvpnKit · 你的联机小管家"),
        ..Default::default()
    };

    eframe::run_native(
        "RvpnKit",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
