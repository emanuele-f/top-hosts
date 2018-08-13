use std::io;
use tui::Terminal;
use tui::terminal::Terminal as TerminalType;
use tui::backend::RawBackend;
use tui::widgets::{Widget, Block, Borders};
use tui::layout::{Group, Size, Direction};

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

  pub fn draw(&mut self) -> Result<(), io::Error> {
    let size = self.term.size()?;

    Block::default()
        .title("Block")
        .borders(Borders::ALL)
        .render(&mut self.term, &size);

    self.term.draw()
  }
}
