use egui::Color32;

/// 配色。深浅两套，字段一一对应。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Palette {
    pub(super) bg: Color32,
    pub(super) panel: Color32,
    pub(super) panel2: Color32,
    pub(super) border: Color32,
    pub(super) fg: Color32,
    pub(super) muted: Color32,
    pub(super) faint: Color32,
    pub(super) accent: Color32,
    pub(super) accent_soft: Color32,
    pub(super) ok: Color32,
    pub(super) warn: Color32,
    pub(super) danger: Color32,
}

const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x15, 0x1d, 0x27),
    panel: Color32::from_rgb(0x1e, 0x28, 0x35),
    panel2: Color32::from_rgb(0x26, 0x32, 0x40),
    border: Color32::from_rgb(0x30, 0x3c, 0x4c),
    fg: Color32::from_rgb(0xe4, 0xea, 0xf1),
    muted: Color32::from_rgb(0x8b, 0x95, 0xa7),
    faint: Color32::from_rgb(0x5d, 0x66, 0x75),
    accent: Color32::from_rgb(0xf0, 0x98, 0x70),
    accent_soft: Color32::from_rgb(0x3c, 0x2d, 0x29),
    ok: Color32::from_rgb(0x57, 0xc0, 0x7a),
    warn: Color32::from_rgb(0xe0, 0xa4, 0x58),
    danger: Color32::from_rgb(0xe0, 0x6c, 0x75),
};

const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xf7, 0xf8, 0xfa),
    panel: Color32::from_rgb(0xff, 0xff, 0xff),
    panel2: Color32::from_rgb(0xf4, 0xf6, 0xf8),
    border: Color32::from_rgb(0xe9, 0xed, 0xf1),
    fg: Color32::from_rgb(0x25, 0x33, 0x44),
    muted: Color32::from_rgb(0x7c, 0x8b, 0x9c),
    faint: Color32::from_rgb(0x9a, 0xa3, 0xb2),
    accent: Color32::from_rgb(0xeb, 0x79, 0x50),
    accent_soft: Color32::from_rgb(0xff, 0xf0, 0xe9),
    ok: Color32::from_rgb(0x3c, 0x9d, 0x83),
    warn: Color32::from_rgb(0x9a, 0x6a, 0x12),
    danger: Color32::from_rgb(0xc0, 0x39, 0x2b),
};

impl Palette {
    pub(super) fn by_dark(dark: bool) -> Self {
        if dark {
            DARK
        } else {
            LIGHT
        }
    }
}

/// Small vector icons avoid missing symbol glyphs in system CJK fonts.
pub(super) fn nav_icon(
    painter: &egui::Painter,
    center: egui::Pos2,
    page: super::Page,
    color: Color32,
) {
    use egui::{vec2, Rect, Stroke};
    let stroke = Stroke::new(1.2_f32, color);
    let point = |x, y| center + vec2(x, y);
    match page {
        super::Page::Overview => {
            for (x, y) in [(-7.0, -7.0), (2.0, -7.0), (-7.0, 2.0), (2.0, 2.0)] {
                painter.rect_stroke(
                    Rect::from_min_size(point(x, y), vec2(5.0, 5.0)),
                    1.0,
                    stroke,
                );
            }
        }
        super::Page::Networks => {
            painter.rect_stroke(
                Rect::from_center_size(point(0.0, -5.0), vec2(7.0, 5.0)),
                1.0,
                stroke,
            );
            painter.line_segment([point(0.0, -2.0), point(0.0, 2.0)], stroke);
            painter.line_segment([point(-6.0, 2.0), point(6.0, 2.0)], stroke);
            for x in [-6.0, 6.0] {
                painter.rect_stroke(
                    Rect::from_center_size(point(x, 5.0), vec2(5.0, 5.0)),
                    1.0,
                    stroke,
                );
            }
        }
        super::Page::Members => {
            painter.circle_stroke(point(-2.0, -4.0), 3.0, stroke);
            painter.circle_stroke(point(6.0, -3.0), 2.0, stroke);
            painter.add(egui::Shape::line(
                vec![
                    point(-8.0, 7.0),
                    point(-7.0, 2.0),
                    point(-2.0, 0.0),
                    point(3.0, 2.0),
                    point(4.0, 7.0),
                ],
                stroke,
            ));
            painter.line_segment([point(7.0, 1.0), point(9.0, 6.0)], stroke);
        }
        super::Page::Public => {
            painter.circle_stroke(center, 8.0, stroke);
            painter.add(egui::Shape::closed_line(
                vec![
                    point(4.0, -4.0),
                    point(1.0, 2.0),
                    point(-4.0, 4.0),
                    point(-1.0, -2.0),
                ],
                stroke,
            ));
        }
        super::Page::Activity => {
            for y in [-5.0, 0.0, 5.0] {
                painter.circle_filled(point(-7.0, y), 1.0, color);
                painter.line_segment([point(-2.0, y), point(7.0, y)], stroke);
            }
        }
        super::Page::Settings | super::Page::Tools | super::Page::Chat => {
            painter.circle_stroke(center, 5.0, stroke);
            painter.circle_stroke(center, 1.5, stroke);
            for i in 0..8 {
                let direction = vec2(
                    (i as f32 * std::f32::consts::FRAC_PI_4).cos(),
                    (i as f32 * std::f32::consts::FRAC_PI_4).sin(),
                );
                painter.line_segment([center + direction * 5.0, center + direction * 8.0], stroke);
            }
        }
    }
}
