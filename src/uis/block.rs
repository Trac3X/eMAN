use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render_kv_block<'a>(title: &'a str, fields: &'a [(&'a str, String)]) -> Paragraph<'a> {
    let lines = fields
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k}: "), Style::new().bold()),
                Span::raw(v),
            ])
        })
        .collect::<Vec<_>>();
    Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: true })
}
