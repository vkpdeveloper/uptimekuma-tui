use chrono::Local;
use futures::FutureExt;
use futures::SinkExt;
use iced::mouse;
use iced::widget::canvas::{self};
use iced::widget::{button, column, container, row, scrollable, text, Column, Space};
use iced::{
    alignment, font, Color, Element, Font, Length, Point, Rectangle, Renderer, Subscription, Task,
    Theme,
};
use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Payload, TransportType};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

// Helper to log Socket.IO events to file with JSON payload
fn log_event(event_type: &str, direction: &str, details: &str, json_data: Option<&Value>) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let mut log_line = format!("[{}] {} {} - {}", timestamp, direction, event_type, details);

    if let Some(data) = json_data {
        // Pretty print JSON for readability
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            log_line.push_str(&format!("\nJSON: {}\n", pretty));
        }
    }

    log_line.push('\n');

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("socketio_events.log")
    {
        let _ = file.write_all(log_line.as_bytes());
    }

    // Also print to stderr for immediate visibility (without JSON to keep it clean)
    eprint!(
        "[{}] {} {} - {}\n",
        timestamp, direction, event_type, details
    );
}
use url::Url;

pub fn main() -> iced::Result {
    dotenvy::dotenv().ok();

    iced::application("Uptime Kuma Desktop", KumaApp::update, KumaApp::view)
        .theme(KumaApp::theme)
        .subscription(KumaApp::subscription)
        .default_font(Font::with_name("JetBrains Mono"))
        .run_with(KumaApp::new)
}

// --- Data Models ---

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct Monitor {
    id: u64,
    name: String,
    url: Option<String>,
    #[serde(rename = "type")]
    type_: Option<String>,
    active: Option<bool>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct Heartbeat {
    #[serde(default)]
    id: Option<u64>,
    #[serde(alias = "monitorID")]
    monitor_id: u64,
    status: u8,
    time: String,
    #[serde(default)]
    end_time: Option<String>,
    ping: Option<f64>,
    msg: Option<String>,
    #[serde(default)]
    retries: Option<u32>,
    #[serde(default)]
    duration: Option<u64>,
}

#[derive(Clone, Debug)]
struct StateChangeEvent {
    monitor_id: u64,
    monitor_name: String,
    from_status: u8,
    to_status: u8,
    timestamp: String,
}

#[derive(Clone, Debug)]
struct StatusStats {
    up: usize,
    down: usize,
    pending: usize,
    maintenance: usize,
    unknown: usize,
    paused: usize,
}

impl Default for StatusStats {
    fn default() -> Self {
        Self {
            up: 0,
            down: 0,
            pending: 0,
            maintenance: 0,
            unknown: 0,
            paused: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct AppState {
    monitors: BTreeMap<u64, Monitor>,
    heartbeats: HashMap<u64, Vec<Heartbeat>>,
    latest_status: HashMap<u64, u8>,
    avg_ping: HashMap<u64, f64>,
    uptime: HashMap<u64, f64>,                     // Ratio 0.0 - 1.0
    monitor_status_history: HashMap<u64, Vec<u8>>, // Last 50 status codes for visualization
    stats: StatusStats,
    selected_id: Option<u64>,
    connected: bool,
    error: Option<String>,
    search_text: String,
    filter_status: Option<u8>, // None = All, Some(status) = filter by status
    recent_events: Vec<StateChangeEvent>,
}

struct KumaApp {
    state: AppState,
}

#[derive(Debug, Clone)]
enum Message {
    Connected,
    Disconnected,
    MonitorListReceived(HashMap<String, Monitor>),
    HeartbeatReceived(Heartbeat),
    HeartbeatListReceived(HashMap<String, Vec<Heartbeat>>),
    AvgPingReceived(u64, f64),
    UptimeReceived(u64, f64),
    SelectMonitor(u64),
    SearchChanged(String),
    FilterChanged(Option<u8>),
    Error(String),
}

// --- Application Logic ---

impl KumaApp {
    fn new() -> (Self, Task<Message>) {
        (
            KumaApp {
                state: AppState {
                    monitors: BTreeMap::new(),
                    heartbeats: HashMap::new(),
                    latest_status: HashMap::new(),
                    avg_ping: HashMap::new(),
                    uptime: HashMap::new(),
                    monitor_status_history: HashMap::new(),
                    stats: StatusStats::default(),
                    selected_id: None,
                    connected: false,
                    error: None,
                    search_text: String::new(),
                    filter_status: None,
                    recent_events: Vec::new(),
                },
            },
            Task::none(),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Connected => {
                self.state.connected = true;
                self.state.error = None;
            }
            Message::Disconnected => {
                self.state.connected = false;
            }
            Message::Error(e) => {
                self.state.error = Some(e);
            }
            Message::MonitorListReceived(monitors) => {
                for (id_str, monitor) in monitors {
                    if let Ok(id) = id_str.parse::<u64>() {
                        self.state.monitors.insert(id, monitor);
                    }
                }
            }
            Message::HeartbeatReceived(hb) => {
                // Track state changes for Recent Events
                let previous_status = self.state.latest_status.get(&hb.monitor_id).copied();
                if let Some(prev_status) = previous_status {
                    if prev_status != hb.status {
                        if let Some(monitor) = self.state.monitors.get(&hb.monitor_id) {
                            let event = StateChangeEvent {
                                monitor_id: hb.monitor_id,
                                monitor_name: monitor.name.clone(),
                                from_status: prev_status,
                                to_status: hb.status,
                                timestamp: hb.time.clone(),
                            };
                            self.state.recent_events.insert(0, event);
                            if self.state.recent_events.len() > 10 {
                                self.state.recent_events.pop();
                            }
                        }
                    }
                }

                self.state.latest_status.insert(hb.monitor_id, hb.status);

                // Update status history
                let status_history = self
                    .state
                    .monitor_status_history
                    .entry(hb.monitor_id)
                    .or_default();
                status_history.push(hb.status);
                if status_history.len() > 50 {
                    status_history.remove(0);
                }

                let list = self.state.heartbeats.entry(hb.monitor_id).or_default();
                list.push(hb.clone());
                if list.len() > 50 {
                    list.remove(0);
                }

                // Recalculate stats
                self.calculate_stats();
            }
            Message::HeartbeatListReceived(hb_map) => {
                for (id_str, hbs) in hb_map {
                    if let Ok(id) = id_str.parse::<u64>() {
                        if let Some(last) = hbs.last() {
                            self.state.latest_status.insert(id, last.status);
                        }

                        // Extract status history from heartbeats
                        let status_history: Vec<u8> = hbs.iter().map(|h| h.status).collect();
                        let trimmed_history = if status_history.len() > 50 {
                            status_history[status_history.len() - 50..].to_vec()
                        } else {
                            status_history
                        };
                        self.state
                            .monitor_status_history
                            .insert(id, trimmed_history);

                        let list = self.state.heartbeats.entry(id).or_default();
                        *list = hbs;
                        if list.len() > 50 {
                            let split = list.len() - 50;
                            *list = list.split_off(split);
                        }
                    }
                }

                // Recalculate stats after bulk update
                self.calculate_stats();
            }
            Message::AvgPingReceived(id, val) => {
                self.state.avg_ping.insert(id, val);
            }
            Message::UptimeReceived(id, val) => {
                self.state.uptime.insert(id, val);
            }
            Message::SelectMonitor(id) => {
                self.state.selected_id = Some(id);
            }
            Message::SearchChanged(text) => {
                self.state.search_text = text;
            }
            Message::FilterChanged(status) => {
                self.state.filter_status = status;
            }
        }
        Task::none()
    }

    fn calculate_stats(&mut self) {
        let mut stats = StatusStats::default();

        for monitor in self.state.monitors.values() {
            // Check if monitor is paused (inactive)
            if let Some(false) = monitor.active {
                stats.paused += 1;
                continue;
            }

            // Get latest status or mark as unknown
            let status = self
                .state
                .latest_status
                .get(&monitor.id)
                .copied()
                .unwrap_or(2);
            match status {
                0 => stats.down += 1,
                1 => stats.up += 1,
                2 => stats.pending += 1,
                3 => stats.maintenance += 1,
                _ => stats.unknown += 1,
            }
        }

        self.state.stats = stats;
    }

    fn subscription(&self) -> Subscription<Message> {
        struct Connect;
        Subscription::run_with_id(std::any::TypeId::of::<Connect>(), socket_worker())
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }

    fn view(&self) -> Element<Message> {
        let sidebar = container(scrollable(
            Column::with_children(self.state.monitors.values().map(|m| {
                // Show all monitors - use UNKNOWN (4) as fallback status
                let status = self.state.latest_status.get(&m.id).copied().unwrap_or(4);
                let is_selected = Some(m.id) == self.state.selected_id;
                let status_history = self.state.monitor_status_history.get(&m.id);

                monitor_list_item(m, status, is_selected, status_history)
            }))
            .spacing(4),
        ))
        .width(Length::Fixed(280.0))
        .height(Length::Fill)
        .style(|_t: &Theme| {
            container::Style::default()
                .background(Color::from_rgb8(30, 30, 30))
                .border(iced::border::color(Color::from_rgb8(50, 50, 50)).width(1.0))
        });

        let content = if let Some(selected_id) = self.state.selected_id {
            if let Some(monitor) = self.state.monitors.get(&selected_id) {
                let heartbeats = self.state.heartbeats.get(&selected_id);
                let current_status = self
                    .state
                    .latest_status
                    .get(&selected_id)
                    .copied()
                    .unwrap_or(4); // Unknown - should rarely happen since we filter monitors
                let avg_ping = self
                    .state
                    .avg_ping
                    .get(&selected_id)
                    .copied()
                    .unwrap_or(0.0);
                let uptime = self.state.uptime.get(&selected_id).copied().unwrap_or(0.0);
                monitor_detail_view(monitor, current_status, heartbeats, avg_ping, uptime)
            } else {
                container(
                    text("Monitor not found")
                        .size(20)
                        .color(Color::from_rgb(0.5, 0.5, 0.5)),
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        } else {
            // Quick Stats Dashboard
            quick_stats_view(
                &self.state.stats,
                &self.state.monitor_status_history,
                self.state.connected,
                &self.state.error,
            )
        };

        row![sidebar, content].height(Length::Fill).into()
    }
}

// --- Socket Worker ---

fn socket_worker() -> impl futures::Stream<Item = Message> {
    iced::stream::channel(100, |mut output| async move {
        let raw_url = env::var("UPTIME_KUMA_URL").unwrap_or_default();
        let username = env::var("UPTIME_KUMA_USERNAME").unwrap_or_default();
        let password = env::var("UPTIME_KUMA_PASSWORD").unwrap_or_default();

        if raw_url.is_empty() {
            let _ = output
                .send(Message::Error("UPTIME_KUMA_URL not set".to_string()))
                .await;
            return;
        }

        // Sanitize URL: Extract only base origin
        let base_url = match Url::parse(&raw_url) {
            Ok(u) => {
                let host = u.host_str().unwrap_or("localhost");
                let port = u.port().map(|p| format!(":{}", p)).unwrap_or_default();
                let scheme = if u.scheme() == "ws" {
                    "http"
                } else if u.scheme() == "wss" {
                    "https"
                } else {
                    u.scheme()
                };
                format!("{}://{}{}", scheme, host, port)
            }
            Err(_) => raw_url.clone(),
        };

        use rust_socketio::{
            asynchronous::{Client, ClientBuilder},
            Payload, TransportType,
        };

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let tx = Arc::new(tx);

        let tx_error = tx.clone();
        let tx_disconnect = tx.clone();
        let tx_monitor_list = tx.clone();
        let tx_heartbeat = tx.clone();
        let tx_heartbeat_list = tx.clone();
        let tx_avg_ping = tx.clone();
        let tx_uptime = tx.clone();

        // Helper function to perform login
        async fn do_login(
            client: Client,
            username: String,
            password: String,
            tx: Arc<tokio::sync::mpsc::UnboundedSender<Message>>,
        ) {
            let login_data = serde_json::json!({
                "username": username,
                "password": password,
                "token": ""
            });

            log_event("login", "EMIT", "Sending credentials", Some(&login_data));
            let tx_ack = tx.clone();
            match client
                .emit_with_ack(
                    "login",
                    login_data,
                    std::time::Duration::from_secs(30),
                    move |payload, client_ack| {
                        let tx_inner = tx_ack.clone();
                        async move {
                            if let Payload::Text(values) = &payload {
                                if let Some(val) = values.first() {
                                    log_event(
                                        "login",
                                        "RECV",
                                        "Login response received",
                                        Some(val),
                                    );
                                    if let Some(ok) = val.get("ok").and_then(|v| v.as_bool()) {
                                        if ok {
                                            log_event(
                                                "login",
                                                "SUCCESS",
                                                "Login successful, requesting monitor list",
                                                None,
                                            );
                                            log_event(
                                                "getMonitorList",
                                                "EMIT",
                                                "Requesting monitor list",
                                                Some(&serde_json::json!([])),
                                            );
                                            // Login successful! Request monitor list
                                            let _ = client_ack
                                                .emit("getMonitorList", serde_json::json!([]))
                                                .await;
                                        } else {
                                            let msg = val
                                                .get("msg")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Login failed");
                                            let _ = tx_inner.send(Message::Error(format!(
                                                "Auth failed: {}",
                                                msg
                                            )));
                                        }
                                    }
                                }
                            }
                        }
                        .boxed()
                    },
                )
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.send(Message::Error(format!("Login failed: {:?}", e)));
                }
            }
        }

        let tx_info = tx.clone();
        let username_info = username.clone();
        let password_info = password.clone();
        let logged_in = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let logged_in_info = logged_in.clone();

        let socket_build =
            ClientBuilder::new(base_url)
                .transport_type(TransportType::Any)
                .on("disconnect", move |_, _| {
                    let tx = tx_disconnect.clone();
                    async move {
                        log_event("disconnect", "RECV", "Disconnected from server", None);
                        let _ = tx.send(Message::Disconnected);
                    }
                    .boxed()
                })
                .on("error", move |err, _| {
                    let tx = tx_error.clone();
                    let msg = format!("Socket Error: {:?}", err);
                    async move {
                        let _ = tx.send(Message::Error(msg));
                    }
                    .boxed()
                })
                .on("info", move |_payload, client| {
                    let tx = tx_info.clone();
                    let u = username_info.clone();
                    let p = password_info.clone();
                    let logged_in = logged_in_info.clone();
                    async move {
                        log_event("info", "RECV", "Server info received", None);
                        // Mark as connected when we receive info
                        let _ = tx.send(Message::Connected);
                        // Perform login only once
                        if !logged_in.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            do_login(client.clone(), u, p, tx.clone()).await;
                        }
                    }
                    .boxed()
                })
                .on("monitorList", move |payload, client| {
                    let tx = tx_monitor_list.clone();
                    async move {
                        if let rust_socketio::Payload::Text(values) = &payload {
                            if let Some(val) = values.first() {
                                log_event(
                                    "monitorList",
                                    "RECV",
                                    "Monitor list event received",
                                    Some(val),
                                );
                                if let Ok(monitors) =
                                    serde_json::from_value::<HashMap<String, Monitor>>(val.clone())
                                {
                                    log_event(
                                        "monitorList",
                                        "PARSE",
                                        &format!("Parsed {} monitors", monitors.len()),
                                        Some(val),
                                    );
                                    // Send monitor list to app
                                    let _ = tx.send(Message::MonitorListReceived(monitors.clone()));

                                    // Request historical heartbeat data for each monitor (24 hours)
                                    for (id_str, _) in monitors {
                                        if let Ok(id) = id_str.parse::<u64>() {
                                            let request = serde_json::json!({
                                                "monitorID": id,
                                                "period": 24
                                            });
                                            log_event(
                                                "getMonitorBeats",
                                                "EMIT",
                                                &format!("Requesting beats for monitor {}", id),
                                                Some(&request),
                                            );

                                            // Emit getMonitorBeats for each monitor
                                            let _ = client.emit("getMonitorBeats", request).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    .boxed()
                })
                .on("heartbeat", move |payload, _| {
                    let tx = tx_heartbeat.clone();
                    log_event("heartbeat", "RECV", "Heartbeat event received", None);
                    handle_payload(payload, tx, |v| {
                        serde_json::from_value::<Heartbeat>(v)
                            .map(Message::HeartbeatReceived)
                            .ok()
                    })
                    .boxed()
                })
                .on("heartbeatList", move |payload, _| {
                    let tx = tx_heartbeat_list.clone();
                    log_event(
                        "heartbeatList",
                        "RECV",
                        "HeartbeatList event received",
                        None,
                    );

                    // heartbeatList format from server: [monitorID (string), heartbeats_array, boolean]
                    // values[0] = monitor ID (string), values[1] = heartbeats array, values[2] = boolean
                    if let rust_socketio::Payload::Text(values) = &payload {
                        log_event(
                            "heartbeatList",
                            "INFO",
                            &format!("Received {} parameters", values.len()),
                            None,
                        );

                        if values.len() >= 2 {
                            // Parameter 0: monitor ID (as string)
                            // Parameter 1: heartbeats array
                            if let Some(monitor_id_val) = values.get(0) {
                                log_event(
                                    "heartbeatList",
                                    "DEBUG",
                                    &format!(
                                        "Parameter 0 (monitor ID) type: {}",
                                        if monitor_id_val.is_string() {
                                            "string"
                                        } else if monitor_id_val.is_number() {
                                            "number"
                                        } else {
                                            "other"
                                        }
                                    ),
                                    Some(monitor_id_val),
                                );

                                if let Some(heartbeats_val) = values.get(1) {
                                    log_event(
                                        "heartbeatList",
                                        "DEBUG",
                                        &format!(
                                            "Parameter 1 (heartbeats) is array: {}",
                                            heartbeats_val.is_array()
                                        ),
                                        None,
                                    );

                                    // Parse monitor ID - can be string or number
                                    let monitor_id_opt =
                                        if let Some(id_num) = monitor_id_val.as_u64() {
                                            Some(id_num)
                                        } else if let Some(id_str) = monitor_id_val.as_str() {
                                            id_str.parse::<u64>().ok()
                                        } else {
                                            None
                                        };

                                    if let Some(monitor_id) = monitor_id_opt {
                                        log_event(
                                            "heartbeatList",
                                            "PARSE",
                                            &format!("Parsing beats for monitor {}", monitor_id),
                                            None,
                                        );

                                        if let Ok(heartbeats) =
                                            serde_json::from_value::<Vec<Heartbeat>>(
                                                heartbeats_val.clone(),
                                            )
                                        {
                                            log_event(
                                                "heartbeatList",
                                                "SUCCESS",
                                                &format!(
                                                    "Parsed {} beats for monitor {}",
                                                    heartbeats.len(),
                                                    monitor_id
                                                ),
                                                None,
                                            );
                                            let mut map = HashMap::new();
                                            map.insert(monitor_id.to_string(), heartbeats);
                                            let _ = tx.send(Message::HeartbeatListReceived(map));
                                        } else {
                                            log_event(
                                                "heartbeatList",
                                                "ERROR",
                                                &format!(
                                                    "Failed to parse beats array for monitor {}",
                                                    monitor_id
                                                ),
                                                Some(heartbeats_val),
                                            );
                                        }
                                    } else {
                                        log_event(
                                            "heartbeatList",
                                            "ERROR",
                                            "Failed to parse monitor ID from parameter 0",
                                            Some(monitor_id_val),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    async {}.boxed()
                })
                .on("avgPing", move |payload, _| {
                    let tx = tx_avg_ping.clone();
                    async move {
                        if let Payload::Text(args) = payload {
                            if args.len() >= 2 {
                                let id = args[0].as_u64();
                                let val = args[1].as_f64();
                                if let (Some(id), Some(val)) = (id, val) {
                                    let _ = tx.send(Message::AvgPingReceived(id, val));
                                }
                            }
                        }
                    }
                    .boxed()
                })
                .on("uptime", move |payload, _| {
                    let tx = tx_uptime.clone();
                    async move {
                        if let Payload::Text(args) = payload {
                            // Payload: ["uptime", monitorID, period, uptimeRatio]
                            // args = [monitorID, period, uptimeRatio] (event name stripped)
                            if args.len() >= 3 {
                                let id = args[0].as_u64();
                                let val = args[2].as_f64();
                                if let (Some(id), Some(val)) = (id, val) {
                                    let _ = tx.send(Message::UptimeReceived(id, val));
                                }
                            }
                        }
                    }
                    .boxed()
                })
                .connect()
                .await;

        match socket_build {
            Ok(client) => {
                // Keep the client alive by holding a reference
                let _client = client;
                while let Some(msg) = rx.recv().await {
                    let _ = output.send(msg).await;
                }
            }
            Err(e) => {
                let _ = output
                    .send(Message::Error(format!("Connection failed: {}", e)))
                    .await;
            }
        }
    })
}

async fn handle_payload<F>(
    payload: rust_socketio::Payload,
    tx: Arc<tokio::sync::mpsc::UnboundedSender<Message>>,
    mapper: F,
) where
    F: Fn(Value) -> Option<Message>,
{
    match payload {
        rust_socketio::Payload::Text(values) => {
            eprintln!("[handle_payload] Received {} values", values.len());
            if let Some(val) = values.first() {
                eprintln!(
                    "[handle_payload] Value type: {}",
                    if val.is_object() {
                        "object"
                    } else if val.is_array() {
                        "array"
                    } else {
                        "other"
                    }
                );

                match mapper(val.clone()) {
                    Some(msg) => {
                        eprintln!("[handle_payload] Successfully parsed message");
                        let _ = tx.send(msg);
                    }
                    None => {
                        eprintln!(
                            "[handle_payload] Failed to parse! Value: {:?}",
                            serde_json::to_string(val)
                                .unwrap_or_else(|_| "unprintable".to_string())
                        );
                    }
                }
            }
        }
        #[allow(deprecated)]
        rust_socketio::Payload::String(s) => {
            eprintln!("[handle_payload] Received string payload");
            if let Ok(val) = serde_json::from_str::<Value>(&s) {
                if let Some(msg) = mapper(val) {
                    let _ = tx.send(msg);
                }
            }
        }
        _ => {
            eprintln!("[handle_payload] Received other payload type");
        }
    }
}

// --- UI Components ---

fn monitor_list_item<'a>(
    monitor: &'a Monitor,
    status: u8,
    is_selected: bool,
    status_history: Option<&'a Vec<u8>>,
) -> Element<'a, Message> {
    let (color, _status_icon) = status_color(status);

    // Create status bar if history exists - make boxes prominent like web UI
    let status_bar: Element<'a, Message> = if let Some(history) = status_history {
        if !history.is_empty() {
            container(
                canvas::Canvas::<StatusBar, Message>::new(StatusBar {
                    statuses: history.clone(),
                })
                .width(Length::Fill)
                .height(Length::Fixed(14.0)), // Increased for prominent boxes
            )
            .width(Length::Fill)
            .into()
        } else {
            Space::with_height(14).into()
        }
    } else {
        Space::with_height(14).into()
    };

    button(
        column![
            row![
                container(Space::new(10, 10)).style(move |_| container::Style::default()
                    .background(color)
                    .border(iced::border::rounded(5))),
                Space::with_width(10),
                column![
                    text(monitor.name.clone()).size(14).color(Color::WHITE),
                    text(monitor.url.clone().unwrap_or_default())
                        .size(10)
                        .color(Color::from_rgb(0.6, 0.6, 0.6))
                ]
            ]
            .align_y(alignment::Vertical::Center),
            status_bar
        ]
        .padding(10)
        .spacing(4),
    )
    .on_press(Message::SelectMonitor(monitor.id))
    .width(Length::Fill)
    .style(move |_t: &Theme, s| {
        let active = is_selected || s == iced::widget::button::Status::Hovered;
        let bg = if active {
            Color::from_rgb8(50, 50, 50)
        } else {
            Color::TRANSPARENT
        };
        button::Style {
            background: Some(bg.into()),
            text_color: Color::WHITE,
            border: iced::border::rounded(6),
            ..button::Style::default()
        }
    })
    .into()
}

fn quick_stats_view<'a>(
    stats: &'a StatusStats,
    monitor_status_history: &'a HashMap<u64, Vec<u8>>,
    connected: bool,
    error: &'a Option<String>,
) -> Element<'a, Message> {
    if !connected {
        return container(
            column![
                text("Connecting to Uptime Kuma...")
                    .size(20)
                    .color(Color::from_rgb(0.7, 0.7, 0.7)),
                if let Some(err) = error {
                    text(err).color(Color::from_rgb(0.9, 0.4, 0.4))
                } else {
                    text(" ")
                }
            ]
            .spacing(10)
            .align_x(alignment::Horizontal::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into();
    }

    let total_monitors =
        stats.up + stats.down + stats.pending + stats.maintenance + stats.unknown + stats.paused;

    // Create overall status history from all monitors
    let overall_statuses: Vec<u8> = monitor_status_history
        .values()
        .flat_map(|v| v.iter().copied())
        .collect();

    let overall_status_bar = if !overall_statuses.is_empty() {
        container(
            canvas::Canvas::<StatusBar, Message>::new(StatusBar {
                statuses: overall_statuses,
            })
            .width(Length::Fill)
            .height(Length::Fixed(20.0)),
        )
        .padding(10)
        .width(Length::Fill)
        .style(|_| {
            container::Style::default()
                .background(Color::from_rgb8(25, 25, 25))
                .border(iced::border::rounded(8))
        })
    } else {
        container(
            text("No status data available yet")
                .size(12)
                .color(Color::from_rgb(0.5, 0.5, 0.5)),
        )
        .padding(15)
        .style(|_| {
            container::Style::default()
                .background(Color::from_rgb8(25, 25, 25))
                .border(iced::border::rounded(8))
        })
    };

    container(
        column![
            text("Quick Stats").size(28).color(Color::WHITE),
            text(format!("Total Monitors: {}", total_monitors))
                .size(14)
                .color(Color::from_rgb(0.7, 0.7, 0.7)),
            Space::with_height(20),
            // First row of stats
            row![
                stat_card_with_color(
                    "🟢 Up",
                    &stats.up.to_string(),
                    Color::from_rgb8(67, 208, 138)
                ),
                stat_card_with_color(
                    "🔴 Down",
                    &stats.down.to_string(),
                    Color::from_rgb8(224, 82, 82)
                ),
                stat_card_with_color(
                    "🟠 Pending",
                    &stats.pending.to_string(),
                    Color::from_rgb8(240, 173, 78)
                ),
            ]
            .spacing(10),
            Space::with_height(10),
            // Second row of stats
            row![
                stat_card_with_color(
                    "🔵 Maintenance",
                    &stats.maintenance.to_string(),
                    Color::from_rgb8(78, 154, 230)
                ),
                stat_card_with_color(
                    "⚫ Unknown",
                    &stats.unknown.to_string(),
                    Color::from_rgb8(100, 100, 100)
                ),
                stat_card_with_color(
                    "⏸️ Paused",
                    &stats.paused.to_string(),
                    Color::from_rgb8(150, 150, 150)
                ),
            ]
            .spacing(10),
            Space::with_height(20),
            text("Overall Status History").size(16).color(Color::WHITE),
            overall_status_bar,
            Space::with_height(20),
            text("← Select a monitor to view details")
                .size(14)
                .color(Color::from_rgb(0.6, 0.6, 0.6)),
        ]
        .padding(30)
        .spacing(10),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn stat_card_with_color(
    label: &str,
    value: &str,
    accent_color: Color,
) -> Element<'static, Message> {
    container(column![
        text(label.to_string())
            .size(12)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
        text(value.to_string()).size(24).color(accent_color)
    ])
    .padding(15)
    .width(Length::Fill)
    .style(move |_| {
        container::Style::default()
            .background(Color::from_rgb8(40, 40, 40))
            .border(iced::border::color(accent_color).width(2.0).rounded(8))
    })
    .into()
}

fn monitor_detail_view<'a>(
    monitor: &'a Monitor,
    status: u8,
    heartbeats: Option<&'a Vec<Heartbeat>>,
    avg_ping: f64,
    uptime: f64,
) -> Element<'a, Message> {
    let (color, status_text) = status_color(status);
    let current_ping = heartbeats
        .and_then(|h| h.last())
        .and_then(|h| h.ping)
        .unwrap_or(0.0);

    let chart = if let Some(history) = heartbeats {
        container(
            canvas::Canvas::new(PingChart {
                heartbeats: history.clone(),
                color,
            })
            .width(Length::Fill)
            .height(Length::Fixed(100.0)),
        )
        .padding(10)
        .style(|_| {
            container::Style::default()
                .background(Color::from_rgb8(25, 25, 25))
                .border(iced::border::rounded(8))
        })
    } else {
        container(text("No data")).into()
    };

    column![
        row![
            container(Space::new(16, 16)).style(move |_| container::Style::default()
                .background(color)
                .border(iced::border::rounded(8))),
            text(monitor.name.clone())
                .size(24)
                .font(iced::Font::DEFAULT)
                .color(Color::WHITE),
            text(status_text).size(16).color(color)
        ]
        .spacing(10)
        .align_y(alignment::Vertical::Center),
        Space::with_height(20),
        row![
            stat_card("Current Ping", &format!("{:.0} ms", current_ping)),
            stat_card("Avg Ping (24h)", &format!("{:.0} ms", avg_ping)),
            stat_card("Uptime (24h)", &format!("{:.2}%", uptime * 100.0)),
        ]
        .spacing(10),
        Space::with_height(20),
        text("Response Time History").size(16).color(Color::WHITE),
        chart,
    ]
    .padding(30)
    .spacing(10)
    .into()
}

fn stat_card(label: &str, value: &str) -> Element<'static, Message> {
    container(column![
        text(label.to_string())
            .size(12)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
        text(value.to_string()).size(18).color(Color::WHITE)
    ])
    .padding(15)
    .width(Length::Fill)
    .style(|_| {
        container::Style::default()
            .background(Color::from_rgb8(40, 40, 40))
            .border(iced::border::rounded(8))
    })
    .into()
}

fn status_color(status: u8) -> (Color, &'static str) {
    match status {
        0 => (Color::from_rgb8(224, 82, 82), "DOWN"),
        1 => (Color::from_rgb8(67, 208, 138), "UP"),
        2 => (Color::from_rgb8(240, 173, 78), "PENDING"),
        3 => (Color::from_rgb8(78, 154, 230), "MAINTENANCE"),
        _ => (Color::from_rgb8(100, 100, 100), "UNKNOWN"),
    }
}

struct PingChart {
    heartbeats: Vec<Heartbeat>,
    color: Color,
}
impl<Message> canvas::Program<Message> for PingChart {
    type State = ();
    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        if self.heartbeats.len() < 2 {
            return vec![frame.into_geometry()];
        }
        let max_ping = self
            .heartbeats
            .iter()
            .filter_map(|h| h.ping)
            .fold(0.0, f64::max)
            .max(10.0);
        let width_step = bounds.width / (self.heartbeats.len() as f32 - 1.0);
        let points: Vec<Point> = self
            .heartbeats
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let p = h.ping.unwrap_or(0.0) as f32;
                Point::new(
                    i as f32 * width_step,
                    bounds.height - (p / max_ping as f32 * bounds.height),
                )
            })
            .collect();
        let path = canvas::Path::new(|b| {
            if let Some(first) = points.first() {
                b.move_to(*first);
                for p in points.iter().skip(1) {
                    b.line_to(*p);
                }
            }
        });
        frame.stroke(
            &path,
            canvas::Stroke::default()
                .with_color(self.color)
                .with_width(2.0),
        );
        let area = canvas::Path::new(|b| {
            if let Some(first) = points.first() {
                b.move_to(Point::new(first.x, bounds.height));
                b.line_to(*first);
                for p in points.iter().skip(1) {
                    b.line_to(*p);
                }
                if let Some(last) = points.last() {
                    b.line_to(Point::new(last.x, bounds.height));
                }
                b.close();
            }
        });
        frame.fill(
            &area,
            Color {
                a: 0.1,
                ..self.color
            },
        );
        vec![frame.into_geometry()]
    }
}

// StatusBar canvas component for rendering status history
struct StatusBar {
    statuses: Vec<u8>,
}

impl<Message> canvas::Program<Message> for StatusBar {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());

        if self.statuses.is_empty() {
            return vec![frame.into_geometry()];
        }

        // Calculate gaps: 1px between each item
        let gap = 1.0;
        let count = self.statuses.len() as f32;
        let total_gap_width = if count > 1.0 {
            (count - 1.0) * gap
        } else {
            0.0
        };
        let available_width = (bounds.width - total_gap_width).max(0.0);
        let segment_width = available_width / count;

        let mut x_offset = 0.0;

        for (i, status) in self.statuses.iter().enumerate() {
            // Add gap before item (except the first one)
            if i > 0 {
                x_offset += gap;
            }

            let (color, _) = status_color(*status);

            let rect = canvas::Path::rectangle(
                Point::new(x_offset, 0.0),
                iced::Size::new(segment_width, bounds.height),
            );

            frame.fill(&rect, color);

            x_offset += segment_width;
        }

        vec![frame.into_geometry()]
    }
}
