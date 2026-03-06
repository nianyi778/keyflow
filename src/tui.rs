use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table, TableState, Tabs};
use ratatui::Frame;
use std::time::Duration;

use crate::commands::{get_passphrase, load_config};
use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{KeyStatus, ListFilter, SecretEntry};

// ── Colors (Cyberpunk / HUD) ──────────────────────────
const C_BG: Color = Color::Rgb(10, 14, 23);
const C_SURFACE: Color = Color::Rgb(15, 21, 32);
const C_BORDER: Color = Color::Rgb(30, 41, 59);
const C_BORDER_HI: Color = Color::Rgb(34, 211, 238);
const C_TEXT: Color = Color::Rgb(226, 232, 240);
const C_DIM: Color = Color::Rgb(74, 85, 104);
const C_CYAN: Color = Color::Rgb(34, 211, 238);
const C_GREEN: Color = Color::Rgb(52, 211, 153);
const C_RED: Color = Color::Rgb(248, 113, 113);
const C_YELLOW: Color = Color::Rgb(251, 191, 36);
const C_PURPLE: Color = Color::Rgb(167, 139, 250);
const C_BLUE: Color = Color::Rgb(96, 165, 250);

// ── App State ─────────────────────────────────────────
enum InputMode {
    Normal,
    Search,
}

enum Tab {
    Secrets,
    Health,
    Groups,
}

struct App {
    db: Database,
    secrets: Vec<SecretEntry>,
    filtered: Vec<usize>, // indices into secrets
    table_state: TableState,
    search: String,
    input_mode: InputMode,
    tab: Tab,
    health_expired: Vec<SecretEntry>,
    health_expiring: Vec<SecretEntry>,
    health_unused: Vec<SecretEntry>,
    groups: Vec<(String, Vec<SecretEntry>)>,
    show_detail: bool,
    copied_msg: Option<String>,
    copied_tick: u8,
    quit: bool,
}

impl App {
    fn new(db: Database) -> Self {
        let mut app = App {
            db,
            secrets: Vec::new(),
            filtered: Vec::new(),
            table_state: TableState::default(),
            search: String::new(),
            input_mode: InputMode::Normal,
            tab: Tab::Secrets,
            health_expired: Vec::new(),
            health_expiring: Vec::new(),
            health_unused: Vec::new(),
            groups: Vec::new(),
            show_detail: false,
            copied_msg: None,
            copied_tick: 0,
            quit: false,
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        self.secrets = self
            .db
            .list_secrets(&ListFilter {
                inactive: true,
                ..Default::default()
            })
            .unwrap_or_default();

        let now = chrono::Utc::now();
        self.health_expired = self
            .secrets
            .iter()
            .filter(|e| matches!(e.status(), KeyStatus::Expired))
            .cloned()
            .collect();
        self.health_expiring = self
            .secrets
            .iter()
            .filter(|e| matches!(e.status(), KeyStatus::ExpiringSoon))
            .cloned()
            .collect();
        self.health_unused = self
            .secrets
            .iter()
            .filter(|e| {
                e.is_active && {
                    let last = e.last_used_at.unwrap_or(e.created_at);
                    (now - last).num_days() > 30
                }
            })
            .cloned()
            .collect();

        // groups
        let mut gmap: std::collections::HashMap<String, Vec<SecretEntry>> =
            std::collections::HashMap::new();
        for e in &self.secrets {
            if !e.key_group.is_empty() {
                gmap.entry(e.key_group.clone()).or_default().push(e.clone());
            }
        }
        self.groups = gmap.into_iter().collect();
        self.groups.sort_by(|a, b| a.0.cmp(&b.0));

        self.apply_filter();
    }

    fn apply_filter(&mut self) {
        let q = self.search.to_lowercase();
        self.filtered = self
            .secrets
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if q.is_empty() {
                    return true;
                }
                e.name.to_lowercase().contains(&q)
                    || e.env_var.to_lowercase().contains(&q)
                    || e.provider.to_lowercase().contains(&q)
                    || e.account_name.to_lowercase().contains(&q)
                    || e.source.to_lowercase().contains(&q)
                    || e.key_group.to_lowercase().contains(&q)
                    || e.description.to_lowercase().contains(&q)
                    || e.projects.iter().any(|p| p.to_lowercase().contains(&q))
            })
            .map(|(i, _)| i)
            .collect();

        if !self.filtered.is_empty() {
            let sel = self.table_state.selected().unwrap_or(0);
            if sel >= self.filtered.len() {
                self.table_state.select(Some(0));
            }
            if self.table_state.selected().is_none() {
                self.table_state.select(Some(0));
            }
        } else {
            self.table_state.select(None);
        }
    }

    fn selected_secret(&self) -> Option<&SecretEntry> {
        self.table_state
            .selected()
            .and_then(|i| self.filtered.get(i))
            .and_then(|&idx| self.secrets.get(idx))
    }

    fn next_row(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some((i + 1) % self.filtered.len()));
    }

    fn prev_row(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = self.table_state.selected().unwrap_or(0);
        let prev = if i == 0 {
            self.filtered.len() - 1
        } else {
            i - 1
        };
        self.table_state.select(Some(prev));
    }

    fn copy_selected_value(&mut self) {
        if let Some(entry) = self.selected_secret() {
            let name = entry.name.clone();
            if let Ok(val) = self.db.get_secret_value(&name) {
                // Use pbcopy on macOS, xclip on Linux
                let result = if cfg!(target_os = "macos") {
                    std::process::Command::new("pbcopy")
                        .stdin(std::process::Stdio::piped())
                        .spawn()
                        .and_then(|mut child| {
                            use std::io::Write;
                            child.stdin.as_mut().unwrap().write_all(val.as_bytes())?;
                            child.wait()
                        })
                } else {
                    std::process::Command::new("xclip")
                        .args(["-selection", "clipboard"])
                        .stdin(std::process::Stdio::piped())
                        .spawn()
                        .and_then(|mut child| {
                            use std::io::Write;
                            child.stdin.as_mut().unwrap().write_all(val.as_bytes())?;
                            child.wait()
                        })
                };

                match result {
                    Ok(_) => {
                        self.copied_msg = Some(format!("Copied: {}", name));
                        self.copied_tick = 20; // ~2 seconds
                    }
                    Err(_) => {
                        self.copied_msg = Some("Copy failed".to_string());
                        self.copied_tick = 20;
                    }
                }
            }
        }
    }

    fn handle_event(&mut self) -> bool {
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind != KeyEventKind::Press {
                    return false;
                }

                // Tick down copied message
                if self.copied_tick > 0 {
                    self.copied_tick = self.copied_tick.saturating_sub(1);
                    if self.copied_tick == 0 {
                        self.copied_msg = None;
                    }
                }

                match self.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => {
                            self.quit = true;
                            return true;
                        }
                        KeyCode::Char('c')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            self.quit = true;
                            return true;
                        }
                        KeyCode::Char('/') => {
                            self.input_mode = InputMode::Search;
                        }
                        KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                        KeyCode::Char('k') | KeyCode::Up => self.prev_row(),
                        KeyCode::Char('g') => {
                            if !self.filtered.is_empty() {
                                self.table_state.select(Some(0));
                            }
                        }
                        KeyCode::Char('G') => {
                            if !self.filtered.is_empty() {
                                self.table_state.select(Some(self.filtered.len() - 1));
                            }
                        }
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            self.show_detail = !self.show_detail;
                        }
                        KeyCode::Char('y') => self.copy_selected_value(),
                        KeyCode::Tab | KeyCode::Char('l') => {
                            self.tab = match self.tab {
                                Tab::Secrets => Tab::Health,
                                Tab::Health => Tab::Groups,
                                Tab::Groups => Tab::Secrets,
                            };
                        }
                        KeyCode::BackTab | KeyCode::Char('h') => {
                            self.tab = match self.tab {
                                Tab::Secrets => Tab::Groups,
                                Tab::Health => Tab::Secrets,
                                Tab::Groups => Tab::Health,
                            };
                        }
                        KeyCode::Char('r') => self.reload(),
                        KeyCode::Esc => {
                            if !self.search.is_empty() {
                                self.search.clear();
                                self.apply_filter();
                            }
                            self.show_detail = false;
                        }
                        _ => {}
                    },
                    InputMode::Search => match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Char('c')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            self.quit = true;
                            return true;
                        }
                        KeyCode::Char(c) => {
                            self.search.push(c);
                            self.apply_filter();
                        }
                        KeyCode::Backspace => {
                            self.search.pop();
                            self.apply_filter();
                        }
                        _ => {}
                    },
                }
            }
        } else {
            // Tick down copied message even when no event
            if self.copied_tick > 0 {
                self.copied_tick = self.copied_tick.saturating_sub(1);
                if self.copied_tick == 0 {
                    self.copied_msg = None;
                }
            }
        }
        false
    }
}

// ── Rendering ─────────────────────────────────────────

fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Overall background
    frame.render_widget(Block::default().style(Style::default().bg(C_BG)), area);

    // Layout: header(3) | tabs(3) | content(fill) | footer(1)
    let [header_area, tabs_area, content_area, footer_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(frame, app, header_area);
    render_tabs(frame, app, tabs_area);

    match app.tab {
        Tab::Secrets => render_secrets_tab(frame, app, content_area),
        Tab::Health => render_health_tab(frame, app, content_area),
        Tab::Groups => render_groups_tab(frame, app, content_area),
    }

    render_footer(frame, app, footer_area);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let [logo_area, search_area, status_area] = Layout::horizontal([
        Constraint::Length(22),
        Constraint::Fill(1),
        Constraint::Length(24),
    ])
    .areas(area);

    // Logo
    let logo = Paragraph::new(Line::from(vec![
        Span::styled(
            " Key",
            Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Flow",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ", Style::default()),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_SURFACE)),
    )
    .alignment(Alignment::Center);
    frame.render_widget(logo, logo_area);

    // Search bar
    let search_style = match app.input_mode {
        InputMode::Search => Style::default().fg(C_BORDER_HI),
        InputMode::Normal => Style::default().fg(C_BORDER),
    };
    let search_text = if app.search.is_empty() {
        match app.input_mode {
            InputMode::Search => Line::from(Span::styled(
                "_",
                Style::default()
                    .fg(C_CYAN)
                    .add_modifier(Modifier::SLOW_BLINK),
            )),
            InputMode::Normal => Line::from(Span::styled(
                "  Press / to search...",
                Style::default().fg(C_DIM),
            )),
        }
    } else {
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(&app.search, Style::default().fg(C_CYAN)),
            if matches!(app.input_mode, InputMode::Search) {
                Span::styled(
                    "_",
                    Style::default()
                        .fg(C_CYAN)
                        .add_modifier(Modifier::SLOW_BLINK),
                )
            } else {
                Span::raw("")
            },
        ])
    };

    let search = Paragraph::new(search_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(search_style)
            .title(Span::styled(" Search ", Style::default().fg(C_DIM)))
            .style(Style::default().bg(C_SURFACE)),
    );
    frame.render_widget(search, search_area);

    // Status
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled("●", Style::default().fg(C_GREEN)),
        Span::styled(" VAULT UNLOCKED", Style::default().fg(C_DIM)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_SURFACE)),
    );
    frame.render_widget(status, status_area);
}

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let tab_index = match app.tab {
        Tab::Secrets => 0,
        Tab::Health => 1,
        Tab::Groups => 2,
    };

    let expired_count = app.health_expired.len();
    let expiring_count = app.health_expiring.len();
    let issue_count = expired_count + expiring_count;

    let health_title = if issue_count > 0 {
        format!(" Health [{}] ", issue_count)
    } else {
        " Health ".to_string()
    };

    let tabs = Tabs::new(vec![
        format!(" Secrets [{}] ", app.filtered.len()),
        health_title,
        format!(" Groups [{}] ", app.groups.len()),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_SURFACE)),
    )
    .select(tab_index)
    .style(Style::default().fg(C_DIM))
    .highlight_style(Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))
    .divider(Span::styled(" | ", Style::default().fg(C_BORDER)));

    frame.render_widget(tabs, area);
}

fn render_secrets_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.show_detail {
        // Split: table left, detail right
        let [table_area, detail_area] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(area);
        render_secrets_table(frame, app, table_area);
        render_detail_panel(frame, app, detail_area);
    } else {
        render_secrets_table(frame, app, area);
    }
}

fn render_secrets_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("NAME").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
        Cell::from("ENV VAR").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
        Cell::from("PROVIDER").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
        Cell::from("GROUP").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
        Cell::from("STATUS").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
        Cell::from("EXPIRES").style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD)),
    ])
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|&idx| {
            let e = &app.secrets[idx];
            let status_style = match e.status() {
                KeyStatus::Active => Style::default().fg(C_GREEN),
                KeyStatus::Expired => Style::default().fg(C_RED),
                KeyStatus::ExpiringSoon => Style::default().fg(C_YELLOW),
                KeyStatus::Inactive => Style::default().fg(C_DIM),
                KeyStatus::Unknown => Style::default().fg(C_DIM),
            };
            let provider_color = provider_color(&e.provider);

            Row::new(vec![
                Cell::from(e.name.as_str())
                    .style(Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD)),
                Cell::from(e.env_var.as_str()).style(Style::default().fg(C_YELLOW)),
                Cell::from(e.provider.as_str()).style(Style::default().fg(provider_color)),
                Cell::from(if e.key_group.is_empty() {
                    "-"
                } else {
                    e.key_group.as_str()
                })
                .style(Style::default().fg(if e.key_group.is_empty() {
                    C_DIM
                } else {
                    C_PURPLE
                })),
                Cell::from(format!("{}", e.status())).style(status_style),
                Cell::from(
                    e.expires_at
                        .map(|d| d.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "-".to_string()),
                )
                .style(Style::default().fg(C_DIM)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(22),
        Constraint::Percentage(14),
        Constraint::Percentage(14),
        Constraint::Percentage(14),
        Constraint::Percentage(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    " Secrets ",
                    Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(C_SURFACE))
                .padding(Padding::horizontal(1)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(20, 35, 55))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");

    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_detail_panel(frame: &mut Frame, app: &App, area: Rect) {
    let entry = match app.selected_secret() {
        Some(e) => e,
        None => {
            let empty = Paragraph::new("No secret selected")
                .style(Style::default().fg(C_DIM))
                .block(
                    Block::bordered()
                        .border_style(Style::default().fg(C_BORDER))
                        .title(Span::styled(" Detail ", Style::default().fg(C_CYAN)))
                        .style(Style::default().bg(C_SURFACE)),
                );
            frame.render_widget(empty, area);
            return;
        }
    };

    let status_color = match entry.status() {
        KeyStatus::Active => C_GREEN,
        KeyStatus::Expired => C_RED,
        KeyStatus::ExpiringSoon => C_YELLOW,
        _ => C_DIM,
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Name      ", Style::default().fg(C_DIM)),
            Span::styled(
                &entry.name,
                Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Env Var   ", Style::default().fg(C_DIM)),
            Span::styled(&entry.env_var, Style::default().fg(C_YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("  Provider  ", Style::default().fg(C_DIM)),
            Span::styled(
                &entry.provider,
                Style::default().fg(provider_color(&entry.provider)),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Status    ", Style::default().fg(C_DIM)),
            Span::styled(
                format!("{}", entry.status()),
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Group     ", Style::default().fg(C_DIM)),
            Span::styled(
                if entry.key_group.is_empty() {
                    "-".to_string()
                } else {
                    entry.key_group.clone()
                },
                Style::default().fg(if entry.key_group.is_empty() {
                    C_DIM
                } else {
                    C_PURPLE
                }),
            ),
        ]),
    ];

    if !entry.description.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Desc      ", Style::default().fg(C_DIM)),
            Span::styled(&entry.description, Style::default().fg(C_TEXT)),
        ]));
    }

    if !entry.account_name.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Account   ", Style::default().fg(C_DIM)),
            Span::styled(&entry.account_name, Style::default().fg(C_BLUE)),
        ]));
    }

    if !entry.projects.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Projects  ", Style::default().fg(C_DIM)),
            Span::styled(entry.projects.join(", "), Style::default().fg(C_BLUE)),
        ]));
    }

    if !entry.scopes.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Scopes    ", Style::default().fg(C_DIM)),
            Span::styled(entry.scopes.join(", "), Style::default().fg(C_TEXT)),
        ]));
    }

    let expires = entry
        .expires_at
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "-".to_string());
    lines.push(Line::from(vec![
        Span::styled("  Expires   ", Style::default().fg(C_DIM)),
        Span::styled(
            expires,
            Style::default().fg(if matches!(entry.status(), KeyStatus::Expired) {
                C_RED
            } else if matches!(entry.status(), KeyStatus::ExpiringSoon) {
                C_YELLOW
            } else {
                C_DIM
            }),
        ),
    ]));

    let last_used = entry
        .last_used_at
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "never".to_string());
    lines.push(Line::from(vec![
        Span::styled("  Last Used ", Style::default().fg(C_DIM)),
        Span::styled(last_used, Style::default().fg(C_DIM)),
    ]));

    let last_verified = entry
        .last_verified_at
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string());
    lines.push(Line::from(vec![
        Span::styled("  Verified  ", Style::default().fg(C_DIM)),
        Span::styled(last_verified, Style::default().fg(C_DIM)),
    ]));

    if !entry.apply_url.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  URL       ", Style::default().fg(C_DIM)),
            Span::styled(
                &entry.apply_url,
                Style::default()
                    .fg(C_CYAN)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
    }

    if !entry.source.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("  Source    ", Style::default().fg(C_DIM)),
            Span::styled(&entry.source, Style::default().fg(C_DIM)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [y] Copy Value  [Esc] Close",
        Style::default().fg(C_DIM),
    )));

    // Copied message
    if let Some(ref msg) = app.copied_msg {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", msg),
            Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
        )));
    }

    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER_HI))
            .title(Span::styled(
                " Detail ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(C_SURFACE)),
    );

    frame.render_widget(detail, area);
}

fn render_health_tab(frame: &mut Frame, app: &App, area: Rect) {
    let [expired_area, expiring_area, unused_area] = Layout::vertical([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .areas(area);

    // Expired
    render_health_section(
        frame,
        " Expired Keys ",
        &app.health_expired,
        C_RED,
        expired_area,
    );
    // Expiring
    render_health_section(
        frame,
        " Expiring Soon ",
        &app.health_expiring,
        C_YELLOW,
        expiring_area,
    );
    // Unused
    render_health_section(
        frame,
        " Unused >30 Days ",
        &app.health_unused,
        C_DIM,
        unused_area,
    );
}

fn render_health_section(
    frame: &mut Frame,
    title: &str,
    entries: &[SecretEntry],
    color: Color,
    area: Rect,
) {
    if entries.is_empty() {
        let msg = Paragraph::new(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                "OK",
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" - No issues".to_string(), Style::default().fg(C_DIM)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    format!("{} [0]", title),
                    Style::default().fg(color),
                ))
                .style(Style::default().bg(C_SURFACE)),
        );
        frame.render_widget(msg, area);
        return;
    }

    let rows: Vec<Row> = entries
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(e.name.as_str())
                    .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Cell::from(e.provider.as_str())
                    .style(Style::default().fg(provider_color(&e.provider))),
                Cell::from(
                    e.expires_at
                        .map(|d| d.format("%Y-%m-%d").to_string())
                        .unwrap_or_default(),
                )
                .style(Style::default().fg(C_DIM)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(30),
        Constraint::Percentage(30),
    ];

    let table = Table::new(rows, widths).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!("{} [{}]", title, entries.len()),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(C_SURFACE))
            .padding(Padding::horizontal(1)),
    );

    frame.render_widget(table, area);
}

fn render_groups_tab(frame: &mut Frame, app: &App, area: Rect) {
    if app.groups.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  No groups defined. Use `kf update <name> --group <group>` to create groups.",
            Style::default().fg(C_DIM),
        )))
        .block(
            Block::bordered()
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    " Groups ",
                    Style::default().fg(C_PURPLE).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(C_SURFACE)),
        );
        frame.render_widget(msg, area);
        return;
    }

    // Show groups as sections
    let constraints: Vec<Constraint> = app.groups.iter().map(|_| Constraint::Min(4)).collect();

    let areas = Layout::vertical(constraints).split(area);

    for (i, (group_name, keys)) in app.groups.iter().enumerate() {
        if i >= areas.len() {
            break;
        }

        let rows: Vec<Row> = keys
            .iter()
            .map(|e| {
                let status_color = match e.status() {
                    KeyStatus::Active => C_GREEN,
                    KeyStatus::Expired => C_RED,
                    KeyStatus::ExpiringSoon => C_YELLOW,
                    _ => C_DIM,
                };
                Row::new(vec![
                    Cell::from(e.name.as_str()).style(Style::default().fg(C_TEXT)),
                    Cell::from(e.env_var.as_str()).style(Style::default().fg(C_YELLOW)),
                    Cell::from(format!("{}", e.status())).style(Style::default().fg(status_color)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Percentage(35),
            Constraint::Percentage(40),
            Constraint::Percentage(25),
        ];

        let table = Table::new(rows, widths).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    format!(" {} [{}] ", group_name, keys.len()),
                    Style::default().fg(C_PURPLE).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(C_SURFACE))
                .padding(Padding::horizontal(1)),
        );

        frame.render_widget(table, areas[i]);
    }
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mode_span = match app.input_mode {
        InputMode::Normal => Span::styled(
            " NORMAL ",
            Style::default()
                .fg(C_BG)
                .bg(C_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        InputMode::Search => Span::styled(
            " SEARCH ",
            Style::default()
                .fg(C_BG)
                .bg(C_YELLOW)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let help = match app.input_mode {
        InputMode::Normal => {
            " q:Quit  /:Search  j/k:Nav  Tab:Switch  Enter:Detail  y:Copy  r:Reload "
        }
        InputMode::Search => " Esc/Enter:Done  Type to filter... ",
    };

    // Copied message in footer
    let right_span = if let Some(ref msg) = app.copied_msg {
        Span::styled(
            format!(" {} ", msg),
            Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            format!(" v{} ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(C_DIM),
        )
    };

    let footer = Line::from(vec![
        mode_span,
        Span::styled(help, Style::default().fg(C_DIM)),
        right_span,
    ]);

    frame.render_widget(
        Paragraph::new(footer).style(Style::default().bg(C_BG)),
        area,
    );
}

fn provider_color(provider: &str) -> Color {
    match provider.to_lowercase().as_str() {
        "google" => Color::Rgb(66, 133, 244),
        "github" => Color::Rgb(139, 92, 246),
        "cloudflare" => Color::Rgb(244, 129, 32),
        "aws" => Color::Rgb(255, 153, 0),
        "stripe" => Color::Rgb(99, 91, 255),
        "openai" => Color::Rgb(16, 163, 127),
        "anthropic" => Color::Rgb(212, 165, 116),
        "supabase" => Color::Rgb(62, 207, 142),
        "vercel" => Color::Rgb(200, 200, 200),
        "firebase" => Color::Rgb(255, 202, 40),
        "docker" => Color::Rgb(36, 150, 237),
        "sendgrid" => Color::Rgb(26, 130, 226),
        "resend" => Color::Rgb(0, 204, 153),
        _ => C_CYAN,
    }
}

// ── Public Entry Point ────────────────────────────────

pub fn cmd_tui() -> Result<()> {
    let (data_dir, _config, salt) = load_config()?;
    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    let db = Database::open(db_path.to_str().unwrap(), crypto)?;

    let mut terminal = ratatui::init();
    let mut app = App::new(db);

    loop {
        terminal.draw(|frame| render(frame, &mut app))?;
        if app.handle_event() {
            break;
        }
    }

    ratatui::restore();
    Ok(())
}
