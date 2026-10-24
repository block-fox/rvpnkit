//! Reproducible screenshots of the real egui renderer, always with demo data.
use super::{App, Page, Palette};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

const PAGES: [(&str, Page, bool); 9] = [
    ("gui-overview", Page::Overview, false),
    ("gui-networks", Page::Networks, false),
    ("gui-members", Page::Members, false),
    ("gui-public", Page::Public, false),
    ("gui-chat", Page::Chat, false),
    ("gui-tools", Page::Tools, false),
    ("gui-settings", Page::Settings, false),
    ("gui-activity", Page::Activity, false),
    ("gui-dark", Page::Overview, true),
];

pub(super) struct VisualAudit {
    directory: PathBuf,
    index: usize,
    since: Instant,
    requested: bool,
}
impl VisualAudit {
    pub fn from_args() -> Option<Self> {
        let args: Vec<_> = std::env::args().collect();
        let i = args.iter().position(|a| a == "--screenshot-dir")?;
        Some(Self {
            directory: args.get(i + 1)?.into(),
            index: 0,
            since: Instant::now(),
            requested: false,
        })
    }
}

impl App {
    pub(super) fn visual_audit_tick(&mut self, ctx: &egui::Context) {
        let Some(mut audit) = self.audit.take() else {
            return;
        };
        let screenshot = ctx.input(|input| {
            input.events.iter().find_map(|event| {
                if let egui::Event::Screenshot { image, .. } = event {
                    Some(image.clone())
                } else {
                    None
                }
            })
        });
        if let Some(screenshot) = screenshot {
            let pixels: Vec<u8> = screenshot
                .pixels
                .iter()
                .flat_map(|color| color.to_array())
                .collect();
            let path = audit
                .directory
                .join(format!("{}.png", PAGES[audit.index].0));
            let result = std::fs::create_dir_all(&audit.directory)
                .map_err(|e| e.to_string())
                .and_then(|_| {
                    image::save_buffer(
                        &path,
                        &pixels,
                        screenshot.size[0] as u32,
                        screenshot.size[1] as u32,
                        image::ColorType::Rgba8,
                    )
                    .map_err(|e| e.to_string())
                });
            if let Err(error) = result {
                eprintln!("Screenshot failed: {error}");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            println!("Screenshot: {}", path.display());
            audit.index += 1;
            if audit.index == PAGES.len() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            self.page = PAGES[audit.index].1;
            self.dark = PAGES[audit.index].2;
            self.palette = Palette::by_dark(self.dark);
            audit.since = Instant::now();
            audit.requested = false;
        } else if !audit.requested && audit.since.elapsed() > Duration::from_millis(400) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            audit.requested = true;
        }
        self.audit = Some(audit);
        ctx.request_repaint_after(Duration::from_millis(50));
    }
}
