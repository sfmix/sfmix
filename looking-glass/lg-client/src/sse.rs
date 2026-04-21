/// Minimal SSE (Server-Sent Events) line parser.
///
/// Parses a raw SSE byte stream into typed events. Handles the `event:` and
/// `data:` fields per the SSE spec. Ignores comments (`:` prefix) and
/// unknown fields.

/// A single parsed SSE event.
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// Event type (from `event:` field, defaults to "message").
    pub event: String,
    /// Event data (from `data:` field(s), joined with newlines).
    pub data: String,
}

/// Parses a complete SSE text body into a vec of events.
///
/// This is for non-streaming use (e.g. collecting the full response).
/// For streaming, use `SseLineParser`.
pub fn parse_sse_body(body: &str) -> Vec<SseEvent> {
    let mut parser = SseLineParser::new();
    let mut events = Vec::new();
    for line in body.lines() {
        if let Some(ev) = parser.feed_line(line) {
            events.push(ev);
        }
    }
    // Flush any trailing event (SSE spec: dispatch on blank line)
    if let Some(ev) = parser.flush() {
        events.push(ev);
    }
    events
}

/// Incremental SSE parser that processes one line at a time.
///
/// Feed lines from the stream; when a blank line is encountered,
/// the accumulated event is dispatched.
pub struct SseLineParser {
    event_type: Option<String>,
    data_buf: String,
}

impl SseLineParser {
    pub fn new() -> Self {
        Self {
            event_type: None,
            data_buf: String::new(),
        }
    }

    /// Feed a single line (without trailing newline). Returns `Some(event)` if
    /// a blank line was encountered, dispatching the accumulated event.
    pub fn feed_line(&mut self, line: &str) -> Option<SseEvent> {
        // Blank line = dispatch event
        if line.is_empty() {
            return self.flush();
        }

        // Comment line
        if line.starts_with(':') {
            return None;
        }

        // Parse "field: value" or "field:value"
        if let Some((field, value)) = line.split_once(':') {
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => {
                    self.event_type = Some(value.to_string());
                }
                "data" => {
                    if !self.data_buf.is_empty() {
                        self.data_buf.push('\n');
                    }
                    self.data_buf.push_str(value);
                }
                _ => {} // ignore id, retry, unknown fields
            }
        }

        None
    }

    /// Flush any accumulated event data. Returns `None` if no data was accumulated.
    pub fn flush(&mut self) -> Option<SseEvent> {
        if self.data_buf.is_empty() && self.event_type.is_none() {
            return None;
        }

        let event = SseEvent {
            event: self.event_type.take().unwrap_or_else(|| "message".to_string()),
            data: std::mem::take(&mut self.data_buf),
        };
        Some(event)
    }
}
