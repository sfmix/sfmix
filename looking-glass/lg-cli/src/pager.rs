//! Output pager for the telnet and SSH CLI.
//!
//! Output that fits on one screen is written inline, exactly as before (the
//! `less -F` behaviour). Once a command's output would scroll more than a
//! screenful past the user, the pager switches to the terminal's alternate
//! screen and shows it a page at a time. The view reflows to the window width
//! whenever the client reports a resize, keeping the top line anchored. On
//! quit, the lines the user paged through are printed to the normal screen so
//! they land in the scrollback, the way an IOS `--More--` session would leave
//! them.
//!
//! The pager does no I/O. Command output and keystrokes go in, and the bytes to
//! send to the client come out. Rendering is ratatui with a crossterm backend
//! writing into a `Vec<u8>` (a fixed viewport, since there is no local tty to
//! query), and ansi-to-tui lifts the colored table output into styled text so
//! colors survive rewrapping. Bytes use `\n` line endings like every other
//! frontend output; the frontend's writer does the CRLF transform.
//!
//! Paging needs a known window height: an SSH PTY, a telnet client that does
//! NAWS, or an explicit `terminal length <n>`. Without one (SSH exec, `nc`,
//! `terminal length 0`) output passes straight through, so scripts never hang
//! on a pager prompt.

use ansi_to_tui::IntoText;
use looking_glass::frontend::common::SessionWriter;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{cursor, queue, terminal as ct};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::{Terminal, TerminalOptions, Viewport};

/// Width assumed when the client reported a height (or `terminal length` set
/// one) but no width.
const DEFAULT_COLS: u16 = 80;

/// Largest `terminal length` accepted.
const MAX_LENGTH: u16 = 512;

/// Cap on lines buffered for one command. Real output (the full MAC table on
/// every device) is a few thousand lines; this only bounds memory if something
/// upstream goes wrong. Lines past it are dropped and the quit summary says so.
const MAX_LINES: usize = 50_000;

/// Columns moved by one Left/Right press in chop (no-wrap) mode.
const HSCROLL_STEP: u16 = 8;

/// Search patterns longer than this are not extended.
const MAX_SEARCH_LEN: usize = 256;

/// ASCII box for the help overlay: telnet clients are not reliably UTF-8.
const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

const HELP_LINES: &[&str] = &[
    "SPACE f PgDn     forward one page",
    "b PgUp           back one page",
    "ENTER j Down     forward one line",
    "k Up             back one line",
    "d / u            forward / back half a page",
    "g Home <         first line",
    "G End >          last line",
    "/pattern         search forward (case-insensitive)",
    "n / N            next / previous match",
    "S                toggle wrap / chop long lines",
    "Left / Right     scroll sideways (chop mode)",
    "Ctrl-L           redraw",
    "q Ctrl-C         quit (paged lines stay in scrollback)",
    "",
    "terminal length 0 | <n> | auto   at the prompt",
    "",
    "Press any key to return.",
];

/// The session's `terminal length` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    /// Follow the window height the client reports (default).
    Auto,
    /// Never page.
    Off,
    /// Page at this many rows regardless of the reported height.
    Lines(u16),
}

/// Per-session pager: terminal geometry, the `terminal length` setting, and
/// the output of the command currently being paged.
pub struct Pager {
    /// Window size reported by the client; 0 = unknown.
    cols: u16,
    rows: u16,
    length: Length,
    run: Option<Run>,
}

impl Default for Pager {
    fn default() -> Self {
        Self::new()
    }
}

impl Pager {
    pub fn new() -> Self {
        Self {
            cols: 0,
            rows: 0,
            length: Length::Auto,
            run: None,
        }
    }

    /// The (cols, rows) to page at, or `None` when output should not be paged.
    fn geometry(&self) -> Option<(u16, u16)> {
        let rows = match self.length {
            Length::Off => return None,
            Length::Lines(n) => n,
            Length::Auto => self.rows,
        };
        // One row of content plus the status line is the minimum to page at.
        if rows < 2 {
            return None;
        }
        let cols = if self.cols == 0 { DEFAULT_COLS } else { self.cols };
        Some((cols, rows))
    }

    /// The client reported its window size (SSH pty-req / window-change,
    /// telnet NAWS). Returns bytes to send: a reflowed redraw if the pager is
    /// on screen.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Vec<u8> {
        self.cols = cols;
        self.rows = rows;
        match (self.geometry(), self.run.as_mut()) {
            (Some((c, r)), Some(run)) => run.resize(c, r),
            _ => Vec::new(),
        }
    }

    /// Apply `terminal length <arg>` and describe the result for the user.
    pub fn set_length(&mut self, arg: Option<&str>) -> String {
        let arg = arg.unwrap_or("").trim();
        let length = if arg.eq_ignore_ascii_case("auto") {
            Length::Auto
        } else {
            match arg.parse::<u16>() {
                Ok(0) => Length::Off,
                Ok(n) if (2..=MAX_LENGTH).contains(&n) => Length::Lines(n),
                _ => {
                    return format!(
                        "% Invalid length '{arg}': use auto, 0, or 2-{MAX_LENGTH}\n"
                    )
                }
            }
        };
        self.length = length;
        match length {
            Length::Off => "Pager disabled.\n".to_string(),
            Length::Lines(n) => format!("Pager: {n} lines per page.\n"),
            Length::Auto if self.rows >= 2 => format!(
                "Pager follows the window size (currently {}x{}).\n",
                if self.cols == 0 { DEFAULT_COLS } else { self.cols },
                self.rows
            ),
            Length::Auto => {
                "Pager follows the window size (none reported yet, so not paging).\n".to_string()
            }
        }
    }

    /// Start a command's output. `interactive` is false for one-shot
    /// commands (SSH exec), which are never paged.
    pub fn begin(&mut self, interactive: bool) {
        self.run = if interactive {
            self.geometry().map(|(c, r)| Run::new(c, r))
        } else {
            None
        };
    }

    /// Command output. Returns the bytes to send now.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        match self.run.as_mut() {
            Some(run) => run.feed(data),
            None => data.to_vec(),
        }
    }

    /// The command finished. Returns bytes to send; afterwards
    /// [`is_active`](Self::is_active) says whether the pager is on screen and
    /// owns the keyboard (the frontend then holds the prompt until
    /// [`input`](Self::input) reports done).
    pub fn finish(&mut self) -> Vec<u8> {
        let Some(run) = self.run.as_mut() else {
            return Vec::new();
        };
        let out = run.finish();
        if run.view.is_none() {
            self.run = None;
        }
        out
    }

    /// Whether the pager is on screen, waiting for keys.
    pub fn is_active(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.view.is_some())
    }

    /// Keystrokes while the pager is active. Returns bytes to send and
    /// whether the pager has exited (the frontend then prints its prompt).
    /// Typeahead after the quit key is discarded, as `less` does.
    pub fn input(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let Some(run) = self.run.as_mut() else {
            return (Vec::new(), true);
        };
        let (out, done) = run.input(data);
        if done {
            self.run = None;
        }
        (out, done)
    }
}

/// A [`SessionWriter`] that routes command output through the pager on its
/// way to the frontend's own writer.
pub struct PagedWriter<'a, W> {
    pub pager: &'a mut Pager,
    pub inner: W,
}

impl<W: SessionWriter> SessionWriter for PagedWriter<'_, W> {
    async fn write_bytes(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let out = self.pager.feed(data);
        if out.is_empty() {
            return Ok(());
        }
        self.inner.write_bytes(&out).await
    }
}

// ---------------------------------------------------------------------------
// One command's output
// ---------------------------------------------------------------------------

struct Run {
    cols: u16,
    rows: u16,
    /// Each logical line as received (with any ANSI color), for the
    /// scrollback dump on quit.
    raw: Vec<String>,
    /// The same lines as styled ratatui text, for rendering and reflow.
    lines: Vec<Line<'static>>,
    /// Bytes after the last newline, waiting for the rest of their line.
    pending: Vec<u8>,
    /// Terminal rows used by the lines written inline so far.
    inline_rows: usize,
    /// Lines `[0, inline_lines)` were written inline before paging began.
    inline_lines: usize,
    /// Lines dropped past [`MAX_LINES`].
    dropped: usize,
    complete: bool,
    /// Set once the output overflowed one screen.
    view: Option<View>,
}

impl Run {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols,
            rows,
            raw: Vec::new(),
            lines: Vec::new(),
            pending: Vec::new(),
            inline_rows: 0,
            inline_lines: 0,
            dropped: 0,
            complete: false,
            view: None,
        }
    }

    fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        let Some(nl) = self.pending.iter().rposition(|&b| b == b'\n') else {
            return Vec::new();
        };
        let mut chunk: Vec<u8> = self.pending.drain(..=nl).collect();
        chunk.pop();
        self.push_lines(&chunk)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.complete = true;
        let mut out = if self.pending.is_empty() {
            Vec::new()
        } else {
            let rest = std::mem::take(&mut self.pending);
            self.push_lines(&rest)
        };
        // Redraw so the status line drops its "loading" marker.
        if self.view.is_some() {
            out.extend(self.render());
        }
        out
    }

    /// Store newline-separated `chunk` and emit whatever should be shown now.
    fn push_lines(&mut self, chunk: &[u8]) -> Vec<u8> {
        let first_new = self.lines.len();
        for raw in chunk.split(|&b| b == b'\n') {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            if self.lines.len() >= MAX_LINES {
                self.dropped += 1;
                continue;
            }
            self.lines.push(styled_line(raw));
            self.raw.push(String::from_utf8_lossy(raw).into_owned());
        }

        if let Some(view) = self.view.as_mut() {
            view.extend(&self.lines[first_new..]);
            return self.render();
        }

        // Inline phase: write lines through until one would push output past
        // a screenful (the last row is left for the prompt).
        let budget = usize::from(self.rows - 1);
        let mut out = Vec::new();
        while self.inline_lines < self.lines.len() {
            let width = self.lines[self.inline_lines].width();
            let height = width.div_ceil(usize::from(self.cols)).max(1);
            if self.inline_rows + height > budget {
                break;
            }
            self.inline_rows += height;
            out.extend_from_slice(self.raw[self.inline_lines].as_bytes());
            out.push(b'\n');
            self.inline_lines += 1;
        }
        if self.inline_lines < self.lines.len() {
            // Overflow: take over the screen, starting from the first line.
            out.extend(self.enter());
        }
        out
    }

    fn enter(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        // Writes into a Vec cannot fail.
        let _ = queue!(
            out,
            ct::EnterAlternateScreen,
            ct::Clear(ct::ClearType::All),
            cursor::MoveTo(0, 0)
        );
        self.view = Some(View::new(self.cols, self.rows, &self.lines));
        out.extend(self.render());
        out
    }

    fn resize(&mut self, cols: u16, rows: u16) -> Vec<u8> {
        self.cols = cols;
        self.rows = rows;
        match self.view.as_mut() {
            Some(view) => {
                view.resize(cols, rows, &self.lines);
                self.render()
            }
            // Still inline: the new size just changes the remaining budget.
            None => Vec::new(),
        }
    }

    fn render(&mut self) -> Vec<u8> {
        let Some(view) = self.view.as_mut() else {
            return Vec::new();
        };
        view.render(&self.lines, self.complete)
    }

    fn input(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let Some(view) = self.view.as_mut() else {
            return (Vec::new(), true);
        };
        let mut quit = false;
        for key in view.keys.decode(data) {
            if view.handle_key(key, &self.lines) {
                quit = true;
                break;
            }
        }
        if quit {
            (self.leave(), true)
        } else {
            (self.render(), false)
        }
    }

    /// Leave the alternate screen and put the lines the user paged through
    /// (after those already written inline) into the normal scrollback.
    fn leave(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let seen = self.view.as_ref().map_or(0, |v| v.seen);
        let _ = queue!(out, ct::LeaveAlternateScreen, cursor::Show);
        out.extend_from_slice(b"\x1b[0m");
        for raw in &self.raw[self.inline_lines.min(seen)..seen] {
            out.extend_from_slice(raw.as_bytes());
            out.push(b'\n');
        }
        let unseen = self.lines.len() - seen + self.dropped;
        if unseen > 0 {
            let s = if unseen == 1 { "" } else { "s" };
            out.extend_from_slice(format!("[{unseen} more line{s} not shown]\n").as_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Full-screen view
// ---------------------------------------------------------------------------

enum Mode {
    Normal,
    /// Typing a `/` search pattern.
    Search(String),
    Help,
}

struct View {
    term: Terminal<CrosstermBackend<Vec<u8>>>,
    cols: u16,
    rows: u16,
    /// Chop long lines (scroll sideways) instead of wrapping them.
    chop: bool,
    hscroll: u16,
    /// Screen rows each logical line takes at the current width.
    heights: Vec<usize>,
    /// `starts[i]` = first row of line `i`; `starts[len]` = total rows.
    starts: Vec<usize>,
    /// First row on screen.
    row: usize,
    /// Lines `[0, seen)` have been fully on screen at some point.
    seen: usize,
    mode: Mode,
    /// Last search pattern, lowercased.
    pattern: Option<String>,
    /// Line of the last match, so `n`/`N` continue from it.
    last_match: Option<usize>,
    /// Transient status message ("Pattern not found").
    message: Option<String>,
    keys: KeyDecoder,
}

impl View {
    fn new(cols: u16, rows: u16, lines: &[Line<'static>]) -> Self {
        let term = Terminal::with_options(
            CrosstermBackend::new(Vec::new()),
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, cols, rows)),
            },
        )
        .expect("a fixed viewport never queries the backend");
        let mut view = Self {
            term,
            cols,
            rows,
            chop: false,
            hscroll: 0,
            heights: Vec::new(),
            starts: vec![0],
            row: 0,
            seen: 0,
            mode: Mode::Normal,
            pattern: None,
            last_match: None,
            message: None,
            keys: KeyDecoder::default(),
        };
        view.extend(lines);
        view
    }

    fn page_rows(&self) -> usize {
        usize::from(self.rows.saturating_sub(1)).max(1)
    }

    fn total_rows(&self) -> usize {
        *self.starts.last().unwrap_or(&0)
    }

    fn max_row(&self) -> usize {
        self.total_rows().saturating_sub(self.page_rows())
    }

    fn line_height(&self, line: &Line<'_>) -> usize {
        if self.chop || line.width() <= usize::from(self.cols) {
            return 1;
        }
        // Ask the renderer, so the row accounting matches how the paragraph
        // actually word-wraps the line.
        Paragraph::new(line.clone())
            .wrap(Wrap { trim: false })
            .line_count(self.cols)
            .max(1)
    }

    fn extend(&mut self, new: &[Line<'static>]) {
        for line in new {
            let h = self.line_height(line);
            self.heights.push(h);
            self.starts.push(self.total_rows() + h);
        }
    }

    /// Recompute row geometry for the current width / wrap mode, keeping the
    /// line at the top of the screen anchored.
    fn reflow(&mut self, lines: &[Line<'static>]) {
        let (top, off) = self.locate(self.row);
        let old_h = self.heights.get(top).copied().unwrap_or(1);
        self.heights.clear();
        self.starts = vec![0];
        self.extend(lines);
        let new_h = self.heights.get(top).copied().unwrap_or(1);
        // Keep roughly the same fraction of a tall wrapped line scrolled off.
        let off = (off * new_h / old_h.max(1)).min(new_h - 1);
        self.row = (self.starts.get(top).copied().unwrap_or(0) + off).min(self.max_row());
    }

    fn resize(&mut self, cols: u16, rows: u16, lines: &[Line<'static>]) {
        let width_changed = cols != self.cols;
        self.cols = cols;
        self.rows = rows;
        let _ = self.term.resize(Rect::new(0, 0, cols, rows));
        if width_changed {
            self.reflow(lines);
        } else {
            self.row = self.row.min(self.max_row());
        }
    }

    /// (line, row offset within it) for a screen row.
    fn locate(&self, row: usize) -> (usize, usize) {
        let line = self.starts[1..].partition_point(|&end| end <= row);
        (line, row - self.starts.get(line).copied().unwrap_or(row))
    }

    fn scroll_to(&mut self, row: usize) {
        self.row = row.min(self.max_row());
    }

    fn scroll_by(&mut self, delta: isize) {
        self.last_match = None;
        self.scroll_to(self.row.saturating_add_signed(delta));
    }

    /// Handle one key. Returns true to quit.
    fn handle_key(&mut self, key: Key, lines: &[Line<'static>]) -> bool {
        self.message = None;
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Help => {} // any key closes help
            Mode::Search(mut pat) => match key {
                Key::Enter => self.search_new(pat, lines),
                Key::Esc | Key::Ctrl(b'c') | Key::Ctrl(b'g') => {}
                Key::Backspace if pat.is_empty() => {}
                Key::Backspace => {
                    pat.pop();
                    self.mode = Mode::Search(pat);
                }
                Key::Char(c) => {
                    if pat.len() < MAX_SEARCH_LEN {
                        pat.push(c);
                    }
                    self.mode = Mode::Search(pat);
                }
                _ => self.mode = Mode::Search(pat),
            },
            Mode::Normal => {
                let page = self.page_rows() as isize;
                match key {
                    Key::Char('q') | Key::Char('Q') | Key::Ctrl(b'c') => return true,
                    Key::Char(' ') | Key::Char('f') | Key::Ctrl(b'f') | Key::Ctrl(b'v')
                    | Key::PageDown => self.scroll_by(page),
                    Key::Char('b') | Key::Ctrl(b'b') | Key::PageUp => self.scroll_by(-page),
                    Key::Enter | Key::Char('j') | Key::Char('e') | Key::Ctrl(b'n')
                    | Key::Ctrl(b'e') | Key::Down => self.scroll_by(1),
                    Key::Char('k') | Key::Char('y') | Key::Ctrl(b'p') | Key::Ctrl(b'y')
                    | Key::Up => self.scroll_by(-1),
                    Key::Char('d') | Key::Ctrl(b'd') => self.scroll_by(page / 2),
                    Key::Char('u') | Key::Ctrl(b'u') => self.scroll_by(-page / 2),
                    Key::Char('g') | Key::Char('<') | Key::Home => self.scroll_by(isize::MIN),
                    Key::Char('G') | Key::Char('>') | Key::End => self.scroll_by(isize::MAX),
                    Key::Char('/') => self.mode = Mode::Search(String::new()),
                    Key::Char('n') => self.search_again(true, lines),
                    Key::Char('N') => self.search_again(false, lines),
                    Key::Char('S') => {
                        self.chop = !self.chop;
                        self.hscroll = 0;
                        self.reflow(lines);
                        self.message = Some(
                            if self.chop { "Chopping long lines" } else { "Wrapping long lines" }
                                .to_string(),
                        );
                    }
                    Key::Right if self.chop => self.hscroll = self.hscroll.saturating_add(HSCROLL_STEP),
                    Key::Left if self.chop => self.hscroll = self.hscroll.saturating_sub(HSCROLL_STEP),
                    Key::Char('h') | Key::Char('H') | Key::Char('?') => self.mode = Mode::Help,
                    Key::Ctrl(b'l') | Key::Char('r') => {
                        let _ = self.term.clear();
                    }
                    _ => {}
                }
            }
        }
        false
    }

    fn search_new(&mut self, pat: String, lines: &[Line<'static>]) {
        if !pat.is_empty() {
            self.pattern = Some(lowercase(&pat));
        }
        self.last_match = None;
        self.search_again(true, lines);
    }

    fn search_again(&mut self, forward: bool, lines: &[Line<'static>]) {
        let Some(pat) = self.pattern.clone() else {
            self.message = Some("No previous search".to_string());
            return;
        };
        let from = self.last_match.unwrap_or_else(|| self.locate(self.row).0);
        let matches = |i: &usize| lowercase(&plain(&lines[*i])).contains(&pat);
        let found = if forward {
            (from + 1..lines.len()).find(matches)
        } else {
            (0..from).rev().find(matches)
        };
        match found {
            Some(i) => {
                self.scroll_to(self.starts[i]);
                self.last_match = Some(i);
            }
            None => self.message = Some("Pattern not found".to_string()),
        }
    }

    fn render(&mut self, lines: &[Line<'static>], complete: bool) -> Vec<u8> {
        let page = self.page_rows();
        let (top, off) = self.locate(self.row);
        // Logical lines that reach onto the screen.
        let end = self.starts[..lines.len()].partition_point(|&s| s < self.row + page);
        let visible: Vec<Line<'static>> = lines[top..end]
            .iter()
            .map(|l| match &self.pattern {
                Some(p) => highlight(l, p),
                None => l.clone(),
            })
            .collect();

        // Lines whose last row is on screen have now been seen in full.
        let fully_shown = self.starts[1..].partition_point(|&e| e <= self.row + page);
        self.seen = self.seen.max(fully_shown);

        let status = self.status_line(top, end, lines.len(), complete);
        let mut body = Paragraph::new(Text::from(visible));
        body = if self.chop {
            body.scroll((0, self.hscroll))
        } else {
            body.wrap(Wrap { trim: false }).scroll((off as u16, 0))
        };
        let rows = self.rows;
        let help = matches!(self.mode, Mode::Help);
        let cursor = match &self.mode {
            Mode::Search(p) => {
                Some((1 + p.chars().count()).min(usize::from(self.cols) - 1) as u16)
            }
            _ => None,
        };

        let _ = self.term.draw(|frame| {
            let area = frame.area();
            let body_area = Rect::new(0, 0, area.width, area.height.saturating_sub(1));
            let status_area = Rect::new(0, area.height.saturating_sub(1), area.width, 1);
            frame.render_widget(body, body_area);
            frame.render_widget(Paragraph::new(status), status_area);
            if help {
                let w = (HELP_LINES.iter().map(|l| l.len()).max().unwrap_or(0) as u16 + 4)
                    .min(area.width);
                let h = (HELP_LINES.len() as u16 + 2).min(body_area.height);
                let popup = Rect::new(
                    (area.width - w) / 2,
                    (body_area.height - h) / 2,
                    w,
                    h,
                );
                frame.render_widget(Clear, popup);
                frame.render_widget(
                    Paragraph::new(HELP_LINES.iter().map(|l| Line::from(*l)).collect::<Vec<_>>())
                        .block(
                            Block::bordered()
                                .border_set(ASCII_BORDER)
                                .title(" pager keys "),
                        ),
                    popup,
                );
            }
            if let Some(x) = cursor {
                frame.set_cursor_position((x, rows - 1));
            }
        });
        std::mem::take(self.term.backend_mut().writer_mut())
    }

    fn status_line(&self, top: usize, end: usize, total: usize, complete: bool) -> Line<'static> {
        let rev = Style::default().add_modifier(Modifier::REVERSED);
        if let Mode::Search(p) = &self.mode {
            return Line::from(vec![Span::raw("/"), Span::raw(p.clone())]);
        }
        let at_end = self.row >= self.max_row();
        let position = if total == 0 {
            "(empty)".to_string()
        } else if at_end && complete {
            format!("lines {}-{} of {} (END)", top + 1, end, total)
        } else {
            let pct = self.starts[end] * 100 / self.total_rows().max(1);
            let more = if complete { "" } else { "+" };
            format!("lines {}-{} of {}{} ({}%)", top + 1, end, total, more, pct)
        };
        let left = format!(" {position} ");
        let room = usize::from(self.cols).saturating_sub(left.len() + 2);
        const FULL_HINT: &str = "SPACE/b page  j/k line  / search  S wrap  h help  q quit";
        let hint = match &self.message {
            Some(m) => m.clone(),
            None if !complete => "loading...".to_string(),
            None if FULL_HINT.len() <= room => FULL_HINT.to_string(),
            None => "h help  q quit".to_string(),
        };
        let hint: String = hint.chars().take(room).collect();
        Line::from(vec![
            Span::styled(left, rev),
            Span::raw("  "),
            Span::raw(hint),
        ])
    }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Parse one output line (which may carry ANSI SGR color) into styled text,
/// expanding tabs and dropping control characters the renderer can't place.
fn styled_line(raw: &[u8]) -> Line<'static> {
    let parsed = raw
        .into_text()
        .ok()
        .and_then(|t| t.lines.into_iter().next())
        .unwrap_or_else(|| Line::from(String::from_utf8_lossy(raw).into_owned()));
    let mut col = 0usize;
    let spans = parsed
        .spans
        .into_iter()
        .map(|span| {
            let mut content = String::with_capacity(span.content.len());
            for c in span.content.chars() {
                if c == '\t' {
                    let stop = (col / 8 + 1) * 8;
                    content.extend(std::iter::repeat_n(' ', stop - col));
                    col = stop;
                } else if !c.is_control() {
                    content.push(c);
                    col += 1;
                }
            }
            Span::styled(content, span.style)
        })
        .collect::<Vec<_>>();
    Line::from(spans).style(parsed.style)
}

fn plain(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

/// Lowercase one char to one char, so char positions in the result line up
/// with the original (needed to place search highlights).
fn lowercase(s: &str) -> String {
    s.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect()
}

/// Reverse-video every case-insensitive occurrence of `pat` (already
/// lowercased) in `line`.
fn highlight(line: &Line<'static>, pat: &str) -> Line<'static> {
    let hay = lowercase(&plain(line));
    if pat.is_empty() || !hay.contains(pat) {
        return line.clone();
    }
    // Match ranges in chars.
    let pat_chars = pat.chars().count();
    let mut ranges = Vec::new();
    let mut byte_to_char = 0usize;
    let mut last_byte = 0usize;
    for (b, _) in hay.match_indices(pat) {
        byte_to_char += hay[last_byte..b].chars().count();
        last_byte = b;
        let start = byte_to_char;
        if ranges.last().is_some_and(|&(_, e)| start < e) {
            continue; // overlapping match
        }
        ranges.push((start, start + pat_chars));
    }
    let hit = |i: usize| ranges.iter().any(|&(s, e)| i >= s && i < e);

    let mut spans = Vec::new();
    let mut i = 0usize;
    for span in &line.spans {
        let mut buf = String::new();
        let mut buf_hit = None;
        for c in span.content.chars() {
            let h = hit(i);
            if buf_hit.is_some_and(|b| b != h) {
                spans.push(styled_piece(std::mem::take(&mut buf), span.style, buf_hit == Some(true)));
            }
            buf_hit = Some(h);
            buf.push(c);
            i += 1;
        }
        if !buf.is_empty() {
            spans.push(styled_piece(buf, span.style, buf_hit == Some(true)));
        }
    }
    Line::from(spans).style(line.style)
}

fn styled_piece(content: String, style: Style, hit: bool) -> Span<'static> {
    if hit {
        Span::styled(content, style.add_modifier(Modifier::REVERSED))
    } else {
        Span::styled(content, style)
    }
}

// ---------------------------------------------------------------------------
// Key decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(char),
    /// Ctrl + letter, as the lowercase letter.
    Ctrl(u8),
    Enter,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
}

#[derive(Default)]
enum EscState {
    #[default]
    Ground,
    Esc,
    Csi(Vec<u8>),
    Ss3,
}

/// Raw terminal input bytes to keys. Keeps escape-sequence state across
/// calls, since a sequence can straddle two reads.
#[derive(Default)]
struct KeyDecoder {
    state: EscState,
    /// Previous byte was CR, so a following LF (or NUL) is the same Enter.
    after_cr: bool,
}

impl KeyDecoder {
    fn decode(&mut self, data: &[u8]) -> Vec<Key> {
        let mut keys = Vec::new();
        for &b in data {
            let after_cr = std::mem::take(&mut self.after_cr);
            match std::mem::take(&mut self.state) {
                EscState::Ground => match b {
                    0x1b => self.state = EscState::Esc,
                    b'\r' => {
                        self.after_cr = true;
                        keys.push(Key::Enter);
                    }
                    b'\n' | 0 if after_cr => {}
                    b'\n' => keys.push(Key::Enter),
                    0x7f | 0x08 => keys.push(Key::Backspace),
                    0x01..=0x1a => keys.push(Key::Ctrl(b'a' + b - 1)),
                    0x20..=0x7e => keys.push(Key::Char(b as char)),
                    _ => {}
                },
                EscState::Esc => match b {
                    b'[' => self.state = EscState::Csi(Vec::new()),
                    b'O' => self.state = EscState::Ss3,
                    0x1b => {
                        keys.push(Key::Esc);
                        self.state = EscState::Esc;
                    }
                    // Alt+key: treat as the bare key.
                    0x20..=0x7e => keys.push(Key::Char(b as char)),
                    _ => keys.push(Key::Esc),
                },
                EscState::Csi(mut params) => match b {
                    0x20..=0x3f => {
                        if params.len() < 16 {
                            params.push(b);
                        }
                        self.state = EscState::Csi(params);
                    }
                    0x40..=0x7e => keys.extend(csi_key(&params, b)),
                    _ => {}
                },
                EscState::Ss3 => keys.extend(csi_key(&[], b)),
            }
        }
        // A lone ESC at the end of a read is the Escape key itself: arrow and
        // paging sequences arrive in one write from the client.
        if matches!(self.state, EscState::Esc) {
            self.state = EscState::Ground;
            keys.push(Key::Esc);
        }
        keys
    }
}

fn csi_key(params: &[u8], fin: u8) -> Option<Key> {
    Some(match (params, fin) {
        (_, b'A') => Key::Up,
        (_, b'B') => Key::Down,
        (_, b'C') => Key::Right,
        (_, b'D') => Key::Left,
        (_, b'H') | (b"1" | b"7", b'~') => Key::Home,
        (_, b'F') | (b"4" | b"8", b'~') => Key::End,
        (b"5", b'~') => Key::PageUp,
        (b"6", b'~') => Key::PageDown,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ALT_ON: &[u8] = b"\x1b[?1049h";
    const ALT_OFF: &[u8] = b"\x1b[?1049l";

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn numbered(n: usize) -> Vec<u8> {
        (1..=n).map(|i| format!("line {i}\n")).collect::<String>().into_bytes()
    }

    fn pager(cols: u16, rows: u16) -> Pager {
        let mut p = Pager::new();
        p.resize(cols, rows);
        p
    }

    #[test]
    fn no_geometry_passes_through() {
        let mut p = Pager::new();
        p.begin(true);
        assert_eq!(p.feed(&numbered(500)), numbered(500));
        assert!(p.finish().is_empty());
        assert!(!p.is_active());
    }

    #[test]
    fn exec_sessions_are_never_paged() {
        let mut p = pager(80, 10);
        p.begin(false);
        assert_eq!(p.feed(&numbered(500)), numbered(500));
        p.finish();
        assert!(!p.is_active());
    }

    #[test]
    fn short_output_is_written_inline() {
        let mut p = pager(80, 10);
        p.begin(true);
        let mut out = p.feed(b"one\ntwo");
        out.extend(p.finish());
        assert_eq!(out, b"one\ntwo\n");
        assert!(!p.is_active());
    }

    #[test]
    fn overflow_switches_to_the_pager() {
        let mut p = pager(80, 10);
        p.begin(true);
        let out = p.feed(&numbered(50));
        // Nine rows' budget (one kept for the prompt) goes inline first.
        assert!(out.starts_with(b"line 1\n"));
        assert!(contains(&out, b"line 9\n"));
        assert!(!contains(&out, b"line 10\n"));
        assert!(contains(&out, ALT_ON));
        p.finish();
        assert!(p.is_active());
    }

    #[test]
    fn wrapped_lines_count_against_the_inline_budget() {
        let mut p = pager(10, 5);
        p.begin(true);
        // Each 25-char line takes three rows at width 10: two fit in four.
        let long = "x".repeat(25);
        let out = p.feed(format!("{long}\n{long}\n").as_bytes());
        assert!(contains(&out, ALT_ON));
    }

    #[test]
    fn quit_leaves_paged_lines_in_scrollback() {
        let mut p = pager(80, 10);
        p.begin(true);
        p.feed(&numbered(50));
        p.finish();
        // One page forward, then quit.
        let (_, done) = p.input(b" ");
        assert!(!done);
        let (out, done) = p.input(b"q");
        assert!(done);
        assert!(!p.is_active());
        assert!(contains(&out, ALT_OFF));
        let text = String::from_utf8_lossy(&out);
        // Inline lines 1-9 are not repeated; the two pages viewed (1-18) are
        // printed from line 10 on.
        assert!(!text.contains("line 9\n"));
        assert!(text.contains("line 10\n"));
        assert!(text.contains("line 18\n"));
        assert!(!text.contains("line 19\n"));
        assert!(text.contains("[32 more lines not shown]"));
    }

    #[test]
    fn end_key_shows_everything() {
        let mut p = pager(80, 10);
        p.begin(true);
        p.feed(&numbered(50));
        p.finish();
        p.input(b"G");
        let (out, _) = p.input(b"q");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("line 50\n"));
        assert!(!text.contains("more line"));
    }

    #[test]
    fn resize_reflows_and_keeps_the_top_line() {
        let mut p = pager(40, 10);
        p.begin(true);
        let long = "word ".repeat(20); // 100 columns
        let mut data = Vec::new();
        for i in 1..=30 {
            data.extend(format!("{i:02} {long}\n").as_bytes());
        }
        p.feed(&data);
        p.finish();
        p.input(b"jjjjjjj"); // seven rows down at width 40
        let top_before = {
            let view = p.run.as_ref().unwrap().view.as_ref().unwrap();
            view.locate(view.row).0
        };
        let out = p.resize(120, 20);
        assert!(!out.is_empty());
        let view = p.run.as_ref().unwrap().view.as_ref().unwrap();
        assert_eq!(view.heights[0], 1, "line fits on one row at width 120");
        assert_eq!(view.locate(view.row).0, top_before);
    }

    #[test]
    fn search_moves_to_the_match() {
        let mut p = pager(80, 10);
        p.begin(true);
        p.feed(&numbered(100));
        p.finish();
        p.input(b"/LINE 42\r");
        let view = p.run.as_ref().unwrap().view.as_ref().unwrap();
        assert_eq!(view.locate(view.row).0, 41);
        assert_eq!(view.last_match, Some(41));
    }

    #[test]
    fn terminal_length_setting() {
        let mut p = Pager::new();
        assert!(p.set_length(Some("abc")).starts_with('%'));
        assert!(p.set_length(Some("1")).starts_with('%'));
        p.set_length(Some("12"));
        assert_eq!(p.geometry(), Some((DEFAULT_COLS, 12)));
        p.set_length(Some("0"));
        assert_eq!(p.geometry(), None);
        p.set_length(Some("auto"));
        assert_eq!(p.geometry(), None);
        p.resize(100, 30);
        assert_eq!(p.geometry(), Some((100, 30)));
    }

    #[test]
    fn keys_decode_across_reads() {
        let mut d = KeyDecoder::default();
        assert_eq!(d.decode(b"\x1b[5~\x1bOB q"), vec![Key::PageUp, Key::Down, Key::Char(' '), Key::Char('q')]);
        assert_eq!(d.decode(b"\x1b[6"), vec![]);
        assert_eq!(d.decode(b"~"), vec![Key::PageDown]);
        assert_eq!(d.decode(b"\r\n\r\0\x03"), vec![Key::Enter, Key::Enter, Key::Ctrl(b'c')]);
        assert_eq!(d.decode(b"\x1b"), vec![Key::Esc]);
    }

    #[test]
    fn ansi_color_and_tabs_are_parsed() {
        let line = styled_line(b"\x1b[31mred\x1b[0m\tx");
        assert_eq!(plain(&line), "red     x");
        assert_eq!(line.spans[0].style.fg, Some(ratatui::style::Color::Red));
    }

    #[test]
    fn highlight_splits_spans() {
        let line = Line::from(vec![Span::raw("AS13335 "), Span::raw("cloudflare")]);
        let h = highlight(&line, "35 cl");
        let hit: String = h
            .spans
            .iter()
            .filter(|s| s.style.add_modifier.contains(Modifier::REVERSED))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(hit, "35 cl");
        assert_eq!(plain(&h), "AS13335 cloudflare");
    }
}
