use crate::events::Event;
use crate::detector::Alert;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Paragraph, Row, Table, Scrollbar, ScrollbarOrientation, ScrollbarState, Chart, Dataset, Axis, GraphType},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct DashboardState {
    pub events: Vec<Event>,
    pub alerts: Vec<Alert>,
    pub total_events: usize,
    pub total_alerts: usize,
    pub show_epoll: bool,
    pub show_normal: bool,
    pub scroll_offset: usize,
    pub prevention_mode: bool,
    pub sparkline_data: Vec<u64>,
    pub last_event_count: usize,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            alerts: Vec::new(),
            total_events: 0,
            total_alerts: 0,
            show_epoll: false,
            show_normal: true,
            scroll_offset: 0,
            prevention_mode: false,
            sparkline_data: vec![0; 100],
            last_event_count: 0,
        }
    }

    pub fn add_event(&mut self, event: Event) {
        self.total_events += 1;
        self.events.push(event);
        if self.events.len() > 5000 {
            self.events.remove(0);
        }
    }

    pub fn add_alert(&mut self, alert: Alert) {
        self.total_alerts += 1;
        self.alerts.push(alert);
        if self.alerts.len() > 1000 {
            self.alerts.remove(0);
        }
    }
}

pub fn run_dashboard(state: Arc<Mutex<DashboardState>>) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| {
            let mut st = state.lock().unwrap();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(3),
                ])
                .split(f.area());
            
            // Sparkline update logic (IOPS tracking)
            let current_events = st.total_events;
            let diff = current_events.saturating_sub(st.last_event_count);
            st.last_event_count = current_events;
            st.sparkline_data.push(diff as u64);
            
            // We trim the array to ensure new data is visible immediately, not pushed off-screen
            while st.sparkline_data.len() > 100 { // Max buffer size
                st.sparkline_data.remove(0);
            }

            let middle_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(75),
                ])
                .split(chunks[1]);

            let left_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(10), // Threat Matrix
                    Constraint::Min(0),     // Sparkline
                ])
                .split(middle_chunks[0]);

            let filter_status = if st.show_epoll { "OFF (Show All)" } else { "ON (Hide Epoll)" };
            let normal_status = if st.show_normal { "ALL" } else { "ALERTS ONLY" };
            let scroll_status = if st.scroll_offset > 0 { format!(" | SCROLL: -{}", st.scroll_offset) } else { "".to_string() };
            
            let (mode_text, mode_color) = if st.prevention_mode {
                ("ACTIVE PREVENTION", Color::Red)
            } else {
                ("PASSIVE DETECTION", Color::Cyan)
            };
            
            let header = Paragraph::new(Line::from(vec![
                Span::styled(format!(" IORing Guard ({}) ", mode_text), Style::default().add_modifier(Modifier::BOLD).fg(mode_color)),
                Span::styled(format!(" | Filter: {} | Display: {}{}", filter_status, normal_status, scroll_status), Style::default().fg(Color::Gray)),
            ]))
            .alignment(ratatui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(header, chunks[0]);

            // === THREAT MATRIX ===
            let lpe_active = st.alerts.iter().any(|a| a.reason.contains("EDB-50808") || a.reason.contains("EDB-50828") || a.reason.contains("Privilege"));
            let exfil_active = st.alerts.iter().any(|a| a.reason.contains("ARMO") || a.reason.contains("/etc/shadow") || a.reason.contains("id_rsa") || a.reason.contains("passwd"));
            let dos_active = st.alerts.iter().any(|a| a.reason.contains("Denial of Service"));
            let c2_active = st.alerts.iter().any(|a| a.reason.contains("Network I/O"));

            let format_threat = |active: bool| -> Span {
                if active {
                    Span::styled(" [DETECTED] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD).add_modifier(Modifier::RAPID_BLINK))
                } else {
                    Span::styled(" [CLEAR]    ", Style::default().fg(Color::Green))
                }
            };

            let threat_lines = vec![
                Line::from(vec![format_threat(lpe_active), Span::styled("Local Privilege Esc (LPE)", Style::default().fg(Color::White))]),
                Line::from(vec![format_threat(exfil_active), Span::styled("Data Exfiltration", Style::default().fg(Color::White))]),
                Line::from(vec![format_threat(dos_active), Span::styled("Denial of Service (DoS)", Style::default().fg(Color::White))]),
                Line::from(vec![format_threat(c2_active), Span::styled("Malware C2 / Network", Style::default().fg(Color::White))]),
                Line::from(""),
                Line::from(Span::styled("Powered by Exploit-DB", Style::default().fg(Color::DarkGray))),
            ];

            let threat_matrix = Paragraph::new(threat_lines)
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)).title(" Threat Matrix "));
            f.render_widget(threat_matrix, left_chunks[0]);

            let max_val = st.sparkline_data.iter().max().unwrap_or(&0).clone() as f64;
            let y_upper = if max_val > 10.0 { max_val } else { 10.0 };

            // Create (x, y) coordinates for the chart
            let chart_data: Vec<(f64, f64)> = st.sparkline_data
                .iter()
                .enumerate()
                .map(|(i, &v)| (i as f64, v as f64))
                .collect();

            let datasets = vec![
                Dataset::default()
                    .name("IOPS")
                    .marker(ratatui::symbols::Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(Color::Green))
                    .data(&chart_data)
            ];

            let x_axis = Axis::default()
                .title("Time")
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, 100.0])
                .labels(vec![Span::from("-5s"), Span::from("Now")]);

            let y_axis = Axis::default()
                .title("Ops")
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, y_upper])
                .labels(vec![Span::from("0"), Span::from(format!("{}", y_upper))]);

            let chart = Chart::new(datasets)
                .block(Block::default().title(" Live IOPS ").borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)))
                .x_axis(x_axis)
                .y_axis(y_axis);
            f.render_widget(chart, left_chunks[1]);

            let selected_style = Style::default().add_modifier(Modifier::REVERSED);
            let header_table = Row::new(vec!["ID", "PID", "PROCESS", "OPERATION", "TARGET", "STATUS", "DETAILS"])
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .height(1)
                .bottom_margin(1);
            
            let mut rows = vec![];
            
            let total_filtered = st.events.iter()
                .filter(|e| st.show_epoll || e.opcode_name != "EPOLL_CTL")
                .filter(|e| st.show_normal || st.alerts.iter().any(|a| a.event.timestamp == e.timestamp))
                .count();
            if st.scroll_offset > total_filtered.saturating_sub(1) {
                st.scroll_offset = total_filtered.saturating_sub(1);
            }

            let display_events: Vec<&Event> = st.events.iter()
                .filter(|e| st.show_epoll || e.opcode_name != "EPOLL_CTL")
                .filter(|e| st.show_normal || st.alerts.iter().any(|a| a.event.timestamp == e.timestamp))
                .rev()
                .skip(st.scroll_offset)
                .take(100)
                .collect();

            for (i, e) in display_events.iter().enumerate() {
                let mut status_str = "OK";
                let mut color = Color::Green;
                let mut details_str = String::new();
                
                for alert in &st.alerts {
                    if alert.event.timestamp == e.timestamp {
                        details_str = alert.reason.clone();
                        if alert.blocked {
                            status_str = "KILLED!";
                            color = Color::Magenta;
                        } else {
                            status_str = match alert.risk {
                                crate::detector::RiskLevel::Low => "LOW",
                                crate::detector::RiskLevel::Medium => "MEDIUM",
                                crate::detector::RiskLevel::High => "HIGH",
                                crate::detector::RiskLevel::Critical => "CRITICAL",
                            };
                            color = match alert.risk {
                                crate::detector::RiskLevel::Low => Color::Yellow,
                                crate::detector::RiskLevel::Medium => Color::LightRed,
                                crate::detector::RiskLevel::High => Color::Red,
                                crate::detector::RiskLevel::Critical => Color::Rgb(255, 0, 0),
                            };
                        }
                        break;
                    }
                }

                let target = if e.filename.is_empty() { "-" } else { &e.filename };
                let pid_str = if e.pid == e.tgid { e.pid.to_string() } else { format!("{}:{}", e.pid, e.tgid) };

                let cells = vec![
                    Span::styled(format!("#{}", e.id), Style::default().fg(Color::DarkGray)),
                    Span::raw(pid_str),
                    Span::raw(format!("{}{}", e.pcomm, e.comm)),
                    Span::raw(e.opcode_name.to_string()),
                    Span::raw(target.to_string()),
                    Span::styled(status_str.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                    Span::styled(details_str, Style::default().fg(Color::DarkGray)),
                ];
                
                let bg_color = if i % 2 == 0 { Color::Reset } else { Color::Rgb(25, 25, 25) };
                rows.push(Row::new(cells).style(Style::default().bg(bg_color)).height(1).bottom_margin(0));
            }

            let t = Table::new(rows, [
                Constraint::Length(6),  // ID
                Constraint::Length(12), // PID
                Constraint::Length(15), // PROCESS
                Constraint::Length(15), // OPERATION
                Constraint::Length(25), // TARGET
                Constraint::Length(10), // STATUS
                Constraint::Min(50),    // DETAILS
            ])
            .header(header_table)
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)).title(" Recent io_uring Activity "))
            .row_highlight_style(selected_style);
            f.render_widget(t, middle_chunks[1]);
            
            if total_filtered > 100 {
                let scrollbar = Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(Some("▲"))
                    .end_symbol(Some("▼"));
                
                let mut scrollbar_state = ScrollbarState::default()
                    .content_length(total_filtered)
                    .position(total_filtered.saturating_sub(st.scroll_offset));
                    
                f.render_stateful_widget(
                    scrollbar,
                    middle_chunks[1].inner(ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
                    &mut scrollbar_state,
                );
            }

            let footer = Paragraph::new(Line::from(vec![
                Span::styled(format!(" Alerts: {} ", st.total_alerts), Style::default().fg(if st.total_alerts > 0 { Color::Red } else { Color::White })),
                Span::raw(format!(" | Events: {} | 'p': Toggle Prevention | 'n': Alerts Only | 'c': Clear | 'q': Exit", st.total_events)),
            ]))
            .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(50))? {
            let evt = event::read()?;
            
            let mut st = state.lock().unwrap();
            
            if let CEvent::Key(key) = evt {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('n') => {
                        st.show_normal = !st.show_normal;
                        st.scroll_offset = 0;
                    },
                    KeyCode::Char('f') => {
                        st.show_epoll = !st.show_epoll;
                        st.scroll_offset = 0; 
                    },
                    KeyCode::Char('p') => {
                        st.prevention_mode = !st.prevention_mode;
                    },
                    KeyCode::Up => {
                        st.scroll_offset = st.scroll_offset.saturating_sub(1);
                    },
                    KeyCode::Down => {
                        st.scroll_offset = st.scroll_offset.saturating_add(1);
                    },
                    KeyCode::PageUp => {
                        st.scroll_offset = st.scroll_offset.saturating_sub(20);
                    },
                    KeyCode::PageDown => {
                        st.scroll_offset = st.scroll_offset.saturating_add(20);
                    },
                    KeyCode::Home => {
                        st.scroll_offset = 0;
                    },
                    KeyCode::End => {
                        st.scroll_offset = usize::MAX;
                    },
                    KeyCode::Esc => {
                        st.scroll_offset = 0; 
                    },
                    KeyCode::Char('c') => {
                        st.events.clear();
                        st.alerts.clear();
                        st.total_events = 0;
                        st.total_alerts = 0;
                        st.scroll_offset = 0;
                    }
                    _ => {}
                }
            }
            
            if let CEvent::Mouse(mouse_event) = evt {
                match mouse_event.kind {
                    crossterm::event::MouseEventKind::ScrollUp => {
                        st.scroll_offset = st.scroll_offset.saturating_sub(3);
                    },
                    crossterm::event::MouseEventKind::ScrollDown => {
                        st.scroll_offset = st.scroll_offset.saturating_add(3);
                    },
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
