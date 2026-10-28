//! The console's mark and the two field icons. `webapp/docs/design.ja.md`.
//!
//! The mark is a shield with three lines running through it (packets passing),
//! the middle one cut by an amber notch (the one that is stopped). It is drawn
//! as flat filled shapes in tones that hold on both grounds, so one drawing
//! serves the dark and the light theme.

use dioxus::prelude::*;

#[component]
pub fn Mark(size: u32) -> Element {
    rsx! {
        svg { class: "mark", view_box: "0 0 128 128", width: "{size}", height: "{size}", "aria-hidden": "true",
            path { d: "M64 6 L112 24 V62 C112 92 92 112 64 122 C36 112 16 92 16 62 V24 Z", fill: "#3a4468" }
            path { d: "M64 14 L104 29 V62 C104 87 88 104 64 114 C40 104 24 87 24 62 V29 Z", fill: "#56628f" }
            rect { x: "38", y: "42", width: "52", height: "8", rx: "4", fill: "#e8ebf5" }
            rect { x: "38", y: "60", width: "30", height: "8", rx: "4", fill: "#e8ebf5" }
            rect { x: "76", y: "60", width: "14", height: "8", rx: "4", fill: "#e8ebf5" }
            rect { x: "38", y: "78", width: "52", height: "8", rx: "4", fill: "#e8ebf5" }
            path { d: "M68 54 L78 54 L72 74 L62 74 Z", fill: "#f0b44a" }
        }
    }
}

/// Icon: `user` from Lucide (<https://lucide.dev/icons/user>). Licence: ISC, Copyright (c) Lucide Icons and Contributors.
#[component]
pub fn PersonIcon() -> Element {
    rsx! {
        svg { class: "field-icon", view_box: "0 0 24 24", width: "20", height: "20", fill: "none",
            stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round", "aria-hidden": "true",
            path { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }
            circle { cx: "12", cy: "7", r: "4" }
        }
    }
}

/// Icon: `lock` from Lucide (<https://lucide.dev/icons/lock>). Licence: ISC, Copyright (c) Lucide Icons and Contributors.
#[component]
pub fn LockIcon() -> Element {
    rsx! {
        svg { class: "field-icon", view_box: "0 0 24 24", width: "20", height: "20", fill: "none",
            stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round", "aria-hidden": "true",
            rect { width: "18", height: "11", x: "3", y: "11", rx: "2", ry: "2" }
            path { d: "M7 11V7a5 5 0 0 1 10 0v4" }
        }
    }
}
