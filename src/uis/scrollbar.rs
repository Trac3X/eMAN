use ratatui::{
    Frame,
    layout::{Margin, Rect},
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState},
};

pub fn render_scrollbar(scroll_state: &mut ScrollbarState, frame: &mut Frame, area: Rect) {
    frame.render_stateful_widget(
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None),
        area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        scroll_state,
    );
}
