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

use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use rvpn_core::commands::next_request_id;
use rvpn_core::pipe::PipeClient;
use rvpn_core::{Commands, MemberInfo, NetworkInfo, PublicNetworks, SnapshotState, DEFAULT_PIPE};

// ───────────────────────────────────────────────────────── 主题

/// 配色。深浅两套，字段一一对应。
#[derive(Clone, Copy, PartialEq, Eq)]
struct Palette {
    bg: Color32,
    panel: Color32,
    panel2: Color32,
    border: Color32,
    fg: Color32,
    muted: Color32,
    faint: Color32,
    accent: Color32,
    accent_soft: Color32,
    ok: Color32,
    warn: Color32,
    danger: Color32,
}

const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x0f, 0x11, 0x15),
    panel: Color32::from_rgb(0x16, 0x1a, 0x21),
    panel2: Color32::from_rgb(0x1b, 0x20, 0x29),
    border: Color32::from_rgb(0x26, 0x2d, 0x3a),
    fg: Color32::from_rgb(0xd7, 0xde, 0xe9),
    muted: Color32::from_rgb(0x8b, 0x95, 0xa7),
    faint: Color32::from_rgb(0x5d, 0x66, 0x75),
    accent: Color32::from_rgb(0x5b, 0x8d, 0xef),
    accent_soft: Color32::from_rgb(0x1e, 0x2c, 0x46),
    ok: Color32::from_rgb(0x57, 0xc0, 0x7a),
    warn: Color32::from_rgb(0xe0, 0xa4, 0x58),
    danger: Color32::from_rgb(0xe0, 0x6c, 0x75),
};

const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xf4, 0xf6, 0xfa),
    panel: Color32::from_rgb(0xff, 0xff, 0xff),
    panel2: Color32::from_rgb(0xee, 0xf1, 0xf6),
    border: Color32::from_rgb(0xdd, 0xe3, 0xec),
    fg: Color32::from_rgb(0x1e, 0x24, 0x30),
    muted: Color32::from_rgb(0x66, 0x70, 0x7f),
    faint: Color32::from_rgb(0x9a, 0xa3, 0xb2),
    accent: Color32::from_rgb(0x3b, 0x6f, 0xd4),
    accent_soft: Color32::from_rgb(0xe3, 0xeb, 0xfb),
    ok: Color32::from_rgb(0x24, 0x8a, 0x4a),
    warn: Color32::from_rgb(0x9a, 0x6a, 0x12),
    danger: Color32::from_rgb(0xc0, 0x39, 0x2b),
};

impl Palette {
    fn by_dark(dark: bool) -> Self {
        if dark {
            DARK
        } else {
            LIGHT
        }
    }
}

fn config_path() -> std::path::PathBuf {
    let base = std::env::var("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    base.join("RvpnKit").join("ui.conf")
}

/// 读主题设置。默认浅色 —— 上一版全黑被吐槽「要瞎了」。
fn load_dark() -> bool {
    std::fs::read_to_string(config_path())
        .ok()
        .map(|s| s.trim() == "dark")
        .unwrap_or(false)
}

fn save_dark(dark: bool) {
    let p = config_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, if dark { "dark" } else { "light" });
}

// ───────────────────────────────────────────────────────── 页面

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

    fn icon(self) -> &'static str {
        match self {
            Page::Networks => "◈",
            Page::Members => "◇",
            Page::Public => "⊕",
            Page::Settings => "⚙",
        }
    }

    fn all() -> [Page; 4] {
        [Page::Networks, Page::Members, Page::Public, Page::Settings]
    }
}

// ───────────────────────────────────────────────────────── 后台任务

enum Msg {
    State(SnapshotState, bool),
    Public(Vec<String>),
    Sent(String),
    Error(String),
}

enum Job {
    Refresh,
    Public(String),
    Send(Vec<u8>, String),
}

// ───────────────────────────────────────────────────────── 应用状态

struct App {
    page: Page,
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
    status: String,
    can_write: bool,
    busy: bool,
    power_on: bool,
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

        // 调试参数：--page=members / --dark / --props，方便截图与验证
        let mut dark = load_dark();
        let mut start_page = Page::Networks;
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
                    "members" => Page::Members,
                    "public" => Page::Public,
                    "settings" => Page::Settings,
                    _ => Page::Networks,
                };
            }
        }
        let app = Self {
            page: start_page,
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
            status: "正在读取状态…".into(),
            can_write: true,
            busy: true,
            power_on: true,
            last_refresh: Instant::now(),
            rx,
            job_tx: Some(job_tx),
            backend: "直连管道".into(),
            palette: Palette::by_dark(dark),
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

    fn pump(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::State(st, can_write) => {
                    self.can_write = can_write;
                    self.state = Some(st);
                    self.busy = false;
                    self.last_refresh = Instant::now();
                    self.clamp_selection();
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
        style.visuals.widgets.active.fg_stroke.color = Color32::WHITE;
        style.visuals.selection.bg_fill = p.accent_soft;
        style.visuals.selection.stroke.color = p.accent;
        style.visuals.override_text_color = Some(p.fg);

        style.spacing.item_spacing = egui::vec2(8.0, 7.0);
        style.spacing.button_padding = egui::vec2(11.0, 6.0);
        style.spacing.menu_margin = egui::Margin::same(6.0);

        ctx.set_style(style);
    }

    // ── 通用小部件


    fn page_header(&self, ui: &mut egui::Ui, title: &str, sub: &str) {
        let p = self.palette;
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).size(18.0).strong().color(p.fg));
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

fn read_state() -> Result<(SnapshotState, bool), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    let can_write = pipe.can_write();
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;
    Ok((SnapshotState::parse(&raw), can_write))
}

fn read_public(search: &str) -> Result<Vec<String>, String> {
    let joined: Vec<String> = {
        let mut p = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
        let raw = p
            .read_snapshot(Duration::from_millis(1500))
            .map_err(|e| e.to_string())?;
        SnapshotState::parse(&raw)
            .networks
            .into_iter()
            .map(|n| n.name)
            .collect()
    };

    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("只读连接无法枚举公共网络（需要可写）".into());
    }
    pipe.send(&Commands::enum_public_networks("", next_request_id()))
        .map_err(|e| e.to_string())?;
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;
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

/// 统一的「卡片」容器：面板底色 + 细边框 + 内边距。
fn card<R>(ui: &mut egui::Ui, p: Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::default()
        .fill(p.panel)
        .stroke(egui::Stroke::new(1.0_f32, p.border))
        .inner_margin(egui::Margin::same(14.0))
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

        if !self.busy && self.last_refresh.elapsed() > Duration::from_secs(6) {
            self.busy = true;
            self.submit(Job::Refresh);
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

        let p = self.palette;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(p.bg)
                    .inner_margin(egui::Margin::symmetric(22.0, 18.0)),
            )
            .show(ctx, |ui| match self.page {
                Page::Networks => self.page_networks(ui),
                Page::Members => self.page_members(ui),
                Page::Public => self.page_public(ui),
                Page::Settings => self.page_settings(ui),
            });
    }
}

impl App {
    // ── 左侧栏
    fn sidebar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(196.0)
            .frame(
                egui::Frame::default()
                    .fill(p.panel)
                    .inner_margin(egui::Margin::symmetric(12.0, 18.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("RvpnKit").size(19.0).strong().color(p.accent));
                        ui.label(RichText::new("Radmin VPN 客户端").size(10.5).color(p.faint));
                    });
                });
                ui.add_space(20.0);

                let counts = [
                    self.state.as_ref().map(|s| s.networks.len()).unwrap_or(0),
                    self.current_network().map(|n| n.members.len()).unwrap_or(0),
                    self.public_list.len(),
                ];

                for (i, page) in Page::all().iter().enumerate() {
                    let selected = self.page == *page;
                    let bg = if selected { p.accent_soft } else { Color32::TRANSPARENT };
                    let fg = if selected { p.accent } else { p.muted };

                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 34.0),
                        egui::Sense::click(),
                    );
                    if ui.is_rect_visible(rect) {
                        let painter = ui.painter();
                        let fill = if resp.hovered() && !selected {
                            p.panel2
                        } else {
                            bg
                        };
                        painter.rect_filled(rect, 8.0, fill);
                        painter.text(
                            rect.left_center() + egui::vec2(12.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            page.icon(),
                            egui::FontId::proportional(13.0),
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
                    ui.label(RichText::new("右键行可操作").size(10.5).color(p.faint));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("●")
                                .size(9.0)
                                .color(if self.can_write { p.ok } else { p.warn }),
                        );
                        ui.label(
                            RichText::new(if self.can_write { "可读写" } else { "只读" })
                                .size(10.5)
                                .color(p.faint),
                        );
                    });
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").size(9.0).color(p.ok));
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
                    let dot_col = if self.power_on { p.ok } else { p.faint };
                    let txt = if self.power_on { "已开启" } else { "已关闭" };
                    let btn = egui::Button::new(
                        RichText::new(format!("●  {txt}"))
                            .size(13.0)
                            .strong()
                            .color(dot_col),
                    );
                    if ui.add(btn).on_hover_text("切换 VPN 总电源").clicked() {
                        let target = !self.power_on;
                        self.power_on = target;
                        self.queue_send(
                            Commands::switch_power(target, next_request_id()),
                            if target { "打开 VPN" } else { "关闭 VPN" },
                        );
                    }

                    if ui.button("刷新").clicked() {
                        self.busy = true;
                        self.submit(Job::Refresh);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.busy {
                            ui.add(egui::Spinner::new().size(13.0));
                        }
                        let s = self.summary();
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

    // ── 属性弹窗
    fn props_window(&mut self, ctx: &egui::Context) {
        let Some(m) = self.props.clone() else {
            return;
        };
        let p = self.palette;
        let net_name = self
            .current_network()
            .map(|n| n.name.clone())
            .unwrap_or_default();
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
                        RichText::new(
                            m.alias.clone().unwrap_or_else(|| format!("#{}", m.node_id)),
                        )
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
                    egui::Label::new(RichText::new("公网 IP").size(12.5).color(p.muted)),
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
            for k in ["角色", "虚拟 IPv4", "虚拟 IPv6", "状态", "通道类型"] {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [92.0, 18.0],
                        egui::Label::new(RichText::new(k).size(12.5).color(p.muted)),
                    );
                    ui.label(
                        RichText::new("—（控制面快照未提供）")
                            .size(12.0)
                            .italics()
                            .color(p.faint),
                    );
                });
            }

            ui.add_space(12.0);
            ui.label(
                RichText::new(
                    "节点 ID 是 Radmin 内部给每个成员编的号，踢人 / 授权时用它定位，不是 IP 地址。\n\
                     虚拟 IP、角色、通道类型属于数据面信息，控制面快照里没有。",
                )
                .size(11.0)
                .color(p.faint),
            );

            ui.add_space(12.0);
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

    // ── 网络页
    fn page_networks(&mut self, ui: &mut egui::Ui) {
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
        self.hint(ui, "双击进入成员列表 · 右键行可执行操作");

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.join_input)
                    .hint_text("网络名")
                    .desired_width(220.0),
            );
            if ui.button("加入").clicked() && !self.join_input.trim().is_empty() {
                let name = self.join_input.trim().to_string();
                self.queue_send(
                    Commands::join_network(&name, next_request_id()),
                    format!("加入 {name}"),
                );
            }
            if ui.button("创建").clicked() && !self.join_input.trim().is_empty() {
                let name = self.join_input.trim().to_string();
                self.queue_send(
                    Commands::create_network(&name, next_request_id(), None),
                    format!("创建 {name}"),
                );
            }
        });
        ui.add_space(10.0);

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
                        let selected = self.selected_network == Some(i);
                        let (rect, resp) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 30.0),
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
                                &net.name,
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
                            if ui.button("离开网络").clicked() {
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
    fn page_members(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let Some(net) = self.current_network().cloned() else {
            self.page_header(ui, "成员", "");
            self.hint(ui, "先在「网络」页选中一个网络");
            return;
        };

        self.page_header(
            ui,
            "成员",
            &format!("{} · {} 人", net.name, net.members.len()),
        );
        self.hint(ui, "勾选可批量操作 · 右键或双击查看属性");

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("筛选别名 / IP / 节点 ID")
                    .desired_width(230.0),
            );
            if ui.button("全选").clicked() {
                for m in &net.members {
                    self.selected_members.insert(m.node_id);
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
                        if ui.button("授权管理员").clicked() {
                            op = Some("grant");
                        }
                        if ui.button("撤销管理员").clicked() {
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
                for id in &ids {
                    let code = match op {
                        "grant" => rvpn_core::CommandCode::GrantAdmin,
                        "revoke" => rvpn_core::CommandCode::RevokeAdmin,
                        _ => rvpn_core::CommandCode::KickNode,
                    };
                    self.queue_send(
                        Commands::member_operation(
                            code,
                            &net.guid,
                            *id,
                            &net.name,
                            next_request_id(),
                        ),
                        format!("{} {} 个成员", op, ids.len()),
                    );
                }
                self.selected_members.clear();
            }
        }

        let filter = self.filter.trim().to_lowercase();
        let rows: Vec<MemberInfo> = net
            .members
            .iter()
            .filter(|m| {
                filter.is_empty()
                    || m.node_id.to_string().contains(&filter)
                    || m.alias
                        .as_deref()
                        .map(|a| a.to_lowercase().contains(&filter))
                        .unwrap_or(false)
                    || m.public_ip
                        .as_deref()
                        .map(|ip| ip.contains(&filter))
                        .unwrap_or(false)
            })
            .cloned()
            .collect();

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
                        ui.label(RichText::new("公网 IP").size(11.5).color(p.faint));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("虚拟 IP").size(11.5).color(p.faint));
                    });
                })
                .body(|body| {
                    body.rows(26.0, rows.len(), |mut row| {
                        let i = row.index();
                        let m = rows[i].clone();
                        let checked = self.selected_members.contains(&m.node_id);

                        row.col(|ui| {
                            let mut c = checked;
                            if ui.checkbox(&mut c, "").changed() {
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
                            ui.label(
                                RichText::new(m.alias.clone().unwrap_or_else(|| "-".into()))
                                    .size(12.5),
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(m.public_ip.clone().unwrap_or_else(|| "-".into()))
                                    .size(12.0)
                                    .color(p.muted)
                                    .monospace(),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new("—").size(12.0).color(p.faint));
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
                            ui.separator();
                            if ui.button("查看属性").clicked() {
                                open_props = Some(m2.clone());
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("授权管理员").clicked() {
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
                            ui.separator();
                            if ui.button("复制节点 ID").clicked() {
                                ui.output_mut(|o| o.copied_text = node.to_string());
                                ui.close_menu();
                            }
                            if ui.button("复制公网 IP").clicked() {
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
                    });
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
    fn page_public(&mut self, ui: &mut egui::Ui) {
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

        if do_search {
            self.busy = true;
            self.submit(Job::Public(self.search.clone()));
        }

        if self.public_list.is_empty() {
            ui.label(
                RichText::new("点「搜索」从服务器拉取可加入的公共网络（约 300 个）")
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
    fn page_settings(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        self.page_header(ui, "设置", "");
        self.hint(ui, "外观、别名与连接信息");

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
                        save_dark(true);
                    }
                    if ui.selectable_label(!self.dark, "浅色").clicked() && self.dark {
                        self.dark = false;
                        self.palette = Palette::by_dark(false);
                        save_dark(false);
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
                    if ui.button("应用").clicked() {
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
                RichText::new(DEFAULT_PIPE).size(12.0).monospace().color(p.muted),
            );
            kv(ui, "后端", RichText::new(&self.backend).size(12.5));
            kv(
                ui,
                "权限",
                if self.can_write {
                    RichText::new("可读写").size(12.5).color(p.ok)
                } else {
                    RichText::new("只读（受限环境会降低完整性级别，请用普通用户身份启动）")
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
                    "创建 / 加入网络设密码",
                    "抓到的创建与加入请求都是免密码网络；撞过 57 个候选字段号都没命中，密码不在普通字符串字段里。需要一个带密码网络的抓包样本。",
                ),
                (
                    "成员的虚拟 IP / IPv6 / 角色 / 通道类型",
                    "这些属于数据面信息，控制面快照只提供别名、公网 IP 和节点 ID。",
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

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1150.0, 760.0])
            .with_min_inner_size([920.0, 580.0])
            .with_title("RvpnKit · Radmin VPN"),
        ..Default::default()
    };

    eframe::run_native(
        "RvpnKit",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
