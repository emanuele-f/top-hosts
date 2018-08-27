use std::io;
use std::cmp;
use engine::flow::Flow;
use engine::packet_handler::PacketHandler;
use tui::Terminal;
use tui::terminal::Terminal as TerminalType;
use tui::backend::RawBackend;
use std::slice::Iter;

use tui::widgets::*;
use tui::layout::*;
use tui::style::*;

// https://github.com/banyan/rust-pretty-bytes/blob/master/src/converter.rs
pub fn format_value(num: f64, units: &[&str], factor: f64) -> String {
  let negative = if num.is_sign_positive() { "" } else { "-" };
  let num = num.abs();
  if num < 1_f64 {
    return format!("{}{} {}", negative, num, units[0]);
  }

  let exponent = cmp::min((num.ln() / factor.ln()).floor() as i32, (units.len() - 1) as i32);
  let pretty_bytes = format!("{:.2}", num / factor.powi(exponent));
  let no_comma = pretty_bytes.parse::<f64>().unwrap() * 1_f64;
  let unit = units[exponent as usize];
  format!("{}{} {}", negative, no_comma, unit)
}

pub fn format_bytes(num: f64) -> String {
  let units = ["B", "KB", "MB", "GB", "TB"];
  format_value(num, &units, 1000_f64)
}

pub fn format_bits(num: f64) -> String {
  let units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  format_value(num, &units, 1000_f64)
}

pub struct Ui {
  term: TerminalType<RawBackend>,
}

impl Ui {
  pub fn new() -> Ui {
    let backend = RawBackend::new().unwrap();

    Ui {
      term: Terminal::new(backend).unwrap()
    }
  }

  pub fn draw(&mut self, flows: &Vec<&Flow>, handler: &PacketHandler) -> Result<(), io::Error> {
    let size = self.term.size()?;
    let width = size.width;
    let main_style = Style::default().fg(Color::White).bg(Color::Rgb(0,0,0));
    let alt_style = Style::default().fg(Color::Rgb(0,0,0)).bg(Color::White);

    let perc_w = |perc| -> u16 {
      (width * perc / 100) as u16
    };

    let to_show = flows.iter().map(|flow| {
      let v = vec![
        format!("{}:{}", flow.shost.ip, flow.sport),
        format!("{}:{}", flow.dhost.ip, flow.dport),
        format!("{}", handler.get_protocol_name(&flow.protocol)),
        format_bytes(flow.stats.bytes() as f64),
        format_bits(flow.stats.throughput * 8 as f64)];

      Row::StyledData(v.into_iter(), &main_style)
    });

    Table::new(
        ["Source", "Destination", "Proto", "Traffic", "Thpt"].into_iter(),
        to_show
    )
    .block(Block::default())
    .header_style(alt_style)
    .widths(&[perc_w(25), perc_w(25), perc_w(20), perc_w(10), perc_w(10)])
    .style(main_style)
    .column_spacing(1)
    .render(&mut self.term, &size);

    self.term.draw()
  }
}
