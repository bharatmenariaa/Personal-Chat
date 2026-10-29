use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef, State as SocketState},
    SocketIo,
};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

// ── tunables ──────────────────────────────────────────────────────────────────

/// Max base64 packet size accepted (~64 KB plaintext)
const MAX_PACKET_BYTES: usize = 90_000;

/// Rooms idle longer than this are swept from memory
const ROOM_TTL: Duration = Duration::from_secs(3 * 60 * 60); // 3 hours

/// Wrong pair-code attempts before a room is soft-locked
const MAX_FAIL_ATTEMPTS: u32 = 5;

// ── state ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    rooms: Arc<DashMap<String, Room>>,
}

struct Room {
    salt: String,
    pair_hash: String,
    owner: String,
    members: HashSet<String>,
    locked: bool,
    last_active: Instant,
    fail_attempts: u32,
}

// ── wire types ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JoinPayload {
    key: String,
    #[serde(rename = "pairCode")]
    pair_code: String,
    role: Option<String>,
}

#[derive(Deserialize)]
struct CipherPayload {
    key: String,
    packet: String,
}

#[derive(Deserialize)]
struct LockPayload {
    key: String,
    locked: bool,
}

#[derive(Serialize)]
struct GenKeyResponse {
    key: String,
}

#[derive(Serialize, Clone, Debug)]
struct RoomInfoResponse {
    #[serde(rename = "roomKey")]
    room_key: String,
    salt: String,
    members: usize,
    owner: bool,
    locked: bool,
}

#[derive(Serialize, Clone)]
struct PeerSyncResponse {
    members: usize,
}

#[derive(Serialize, Clone)]
struct LockSyncResponse {
    locked: bool,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

async fn genkey_handler() -> Json<GenKeyResponse> {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();
    Json(GenKeyResponse { key })
}

// ── TTL sweeper ───────────────────────────────────────────────────────────────

async fn room_sweeper(rooms: Arc<DashMap<String, Room>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
    loop {
        interval.tick().await;
        let before = rooms.len();
        rooms.retain(|_, room| room.last_active.elapsed() < ROOM_TTL);
        let removed = before - rooms.len();
        if removed > 0 {
            println!(
                "🧹 Swept {} stale room(s). Active: {}",
                removed,
                rooms.len()
            );
        }
    }
}

// ── socket handlers ───────────────────────────────────────────────────────────

async fn on_connect(socket: SocketRef, io: SocketIo) {
    println!("🟢 Connected: {}", socket.id);

    socket.on(
        "join",
        |socket: SocketRef,
         Data(payload): Data<JoinPayload>,
         state: SocketState<AppState>| async move {
            let room_key = payload.key.trim().to_string();
            let socket_id = socket.id.to_string();
            let pair_code = payload.pair_code.trim().to_string();

            println!(
                "📥 Join: key={}, role={:?}, socket={}",
                room_key, payload.role, socket_id
            );

            if room_key.len() != 12 || pair_code.len() != 6 {
                socket
                    .emit("error-msg", "Invalid format (key: 12 chars, code: 6 digits).")
                    .ok();
                return;
            }

            let mut is_owner = false;
            let room_salt: String;
            let member_count: usize;
            let locked: bool;

            if state.rooms.contains_key(&room_key) {
                if payload.role.as_deref() == Some("owner") {
                    socket
                        .emit("error-msg", "Room already exists. Click Connect to join.")
                        .ok();
                    return;
                }

                let (hash, is_locked, attempts) = {
                    let room = state.rooms.get(&room_key).unwrap();
                    (room.pair_hash.clone(), room.locked, room.fail_attempts)
                };

                if is_locked {
                    socket.emit("error-msg", "Room is locked.").ok();
                    return;
                }

                if attempts >= MAX_FAIL_ATTEMPTS {
                    socket
                        .emit("error-msg", "Too many failed attempts. Room is protected.")
                        .ok();
                    return;
                }

                let valid = bcrypt::verify(&pair_code, &hash).unwrap_or(false);
                if !valid {
                    if let Some(mut room) = state.rooms.get_mut(&room_key) {
                        room.fail_attempts += 1;
                    }
                    socket.emit("error-msg", "Invalid Pair Code.").ok();
                    return;
                }

                {
                    let mut room = state.rooms.get_mut(&room_key).unwrap();
                    room.members.insert(socket_id.clone());
                    room.last_active = Instant::now();
                    room.fail_attempts = 0;
                    room_salt = room.salt.clone();
                    member_count = room.members.len();
                    locked = room.locked;
                }
            } else {
                if payload.role.as_deref() != Some("owner") {
                    socket
                        .emit("error-msg", "Room not found. Click Initialize Room first.")
                        .ok();
                    return;
                }

                let salt_bytes: [u8; 16] = rand::thread_rng().gen();
                room_salt = BASE64.encode(salt_bytes);
                let pair_hash = bcrypt::hash(&pair_code, bcrypt::DEFAULT_COST).unwrap();

                let mut members = HashSet::new();
                members.insert(socket_id.clone());

                state.rooms.insert(
                    room_key.clone(),
                    Room {
                        salt: room_salt.clone(),
                        pair_hash,
                        owner: socket_id.clone(),
                        members,
                        locked: false,
                        last_active: Instant::now(),
                        fail_attempts: 0,
                    },
                );

                is_owner = true;
                member_count = 1;
                locked = false;

                println!("🏠 Room created: {}", room_key);
            }

            socket.join(room_key.clone());
            socket.extensions.insert(room_key.clone());

            // emit room-info first (sync, no await)
            let room_info = RoomInfoResponse {
                room_key: room_key.clone(),
                salt: room_salt.clone(),
                members: member_count,
                owner: is_owner,
                locked,
            };

            println!("📤 Emitting room-info to {}: {:?}", socket.id, room_info);
            socket.emit("room-info", &room_info).ok();

            // notify existing peers (socket.to excludes sender, needs .await)
            if member_count > 1 {
            socket
                .to(room_key.clone())
                .emit("peer-joined", &PeerSyncResponse { members: member_count })
                .ok();
                println!("📢 peer-joined broadcast (excluding joiner)");
            }
        },
    );

    socket.on("ciphertext", {
        move |socket: SocketRef, Data(payload): Data<CipherPayload>| async move {
            if payload.packet.len() > MAX_PACKET_BYTES {
                println!(
                    "⚠️ Oversized packet from {} ({} bytes) — dropped",
                    socket.id,
                    payload.packet.len()
                );
                return;
            }
            println!("✉️ Message in room {}", payload.key);
            // socket.to() excludes sender (no echo-back) and needs .await
            socket
                .to(payload.key.clone())
                .emit("ciphertext", &payload.packet)
                .ok();
        }
    });

    socket.on("typing", {
        let io = io.clone();
        move |_socket: SocketRef, Data(payload): Data<CipherPayload>| async move {
            io.to(payload.key.clone()).emit("typing", &()).ok();
        }
    });

    socket.on(
        "lock-room",
        {
            let io = io.clone();
            move |socket: SocketRef,
                  Data(payload): Data<LockPayload>,
                  state: SocketState<AppState>| async move {
                if let Some(mut room) = state.rooms.get_mut(&payload.key) {
                    if room.owner == socket.id.to_string() {
                        room.locked = payload.locked;
                        room.last_active = Instant::now();
                        io.to(payload.key.clone())
                            .emit("room-locked", &LockSyncResponse { locked: room.locked })
                            .ok();
                    }
                }
            }
        },
    );

    socket.on("close-room", {
        let io = io.clone();
        move |socket: SocketRef, state: SocketState<AppState>| async move {
            if let Some(key) = socket.extensions.get::<String>() {
                if let Some(room) = state.rooms.get(&key) {
                    if room.owner == socket.id.to_string() {
                        io.to(key.clone()).emit("room-closed", &()).ok();
                        drop(room);
                        state.rooms.remove(&key);
                        println!("💥 Room closed: {}", key);
                    }
                }
            }
        }
    });

    socket.on("leave-room", {
        let io = io.clone();
        move |socket: SocketRef, state: SocketState<AppState>| async move {
            if let Some(key) = socket.extensions.get::<String>() {
                let mut remove_room = false;

                if let Some(mut room) = state.rooms.get_mut(&key) {
                    room.members.remove(&socket.id.to_string());
                    let members = room.members.len();

                    if room.owner == socket.id.to_string() || members == 0 {
                        io.to(key.clone()).emit("room-closed", &()).ok();
                        remove_room = true;
                    } else {
                        io.to(key.clone())
                            .emit("peer-left", &PeerSyncResponse { members })
                            .ok();
                    }
                }

                if remove_room {
                    state.rooms.remove(&key);
                }

                socket.leave(key.clone());
                socket.emit("left", &()).ok();
            }
        }
    });

    socket.on_disconnect({
        let io = io.clone();
        move |socket: SocketRef, state: SocketState<AppState>| async move {
            println!("🔴 Disconnected: {}", socket.id);

            if let Some(key) = socket.extensions.get::<String>() {
                let mut remove_room = false;

                if let Some(mut room) = state.rooms.get_mut(&key) {
                    room.members.remove(&socket.id.to_string());
                    let members = room.members.len();

                    if room.owner == socket.id.to_string() || members == 0 {
                        io.to(key.clone()).emit("room-closed", &()).ok();
                        remove_room = true;
                    } else {
                        io.to(key.clone())
                            .emit("peer-left", &PeerSyncResponse { members })
                            .ok();
                    }
                }

                if remove_room {
                    state.rooms.remove(&key);
                }
            }
        }
    });
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        rooms: Arc::new(DashMap::new()),
    };

    tokio::spawn(room_sweeper(Arc::clone(&state.rooms)));

    let (layer, io) = SocketIo::builder()
        .ping_interval(Duration::from_secs(20))
        .ping_timeout(Duration::from_secs(10))
        .with_state(state.clone())
        .build_layer();

    let io_clone = io.clone();

    io.ns("/", move |socket| {
        let io = io_clone.clone();
        async move {
            on_connect(socket, io).await;
        }
    });

    let app = Router::new()
        .route("/api/genkey", get(genkey_handler))
        .fallback_service(ServeDir::new("public"))
        .layer(layer)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    println!("🚀 Server running on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.unwrap();
}
