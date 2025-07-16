use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::Text,
    widgets::{Block, BorderType, Paragraph},
};

pub fn render_header(info_text: &[&str], frame: &mut Frame, area: Rect) {
    let info_footer = Paragraph::new(Text::from_iter(info_text.iter().copied()))
        .style(Style::new())
        .centered()
        .block(Block::bordered().border_type(BorderType::Double));
    frame.render_widget(info_footer, area);
}
