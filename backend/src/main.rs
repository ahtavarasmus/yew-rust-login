use dotenvy::dotenv;
use axum::{
    routing::{get, post},
    Router,
};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::{TraceLayer, DefaultMakeSpan, DefaultOnResponse};
use tracing::Level;
use std::sync::Arc;

mod handlers {
    pub mod auth_handlers;
    pub mod auth_models;
}
mod models {
    pub mod user_models;
}
mod repositories {
    pub mod user_repository;
}
mod schema;

use handlers::auth_handlers::{register, login, get_users};

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;


#[tokio::main]
async fn main() {
    dotenv().ok();
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();
    // Set up database connection pool
    let manager = ConnectionManager::<SqliteConnection>::new("database.db");
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    let _conn = &mut pool.get().expect("Failed to get DB connection");
    // Create router with CORS
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/register", post(register))
        .route("/api/admin/users", get(get_users))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS])
                .allow_headers(Any)
                .expose_headers([axum::http::header::CONTENT_TYPE])
        )
        .with_state(Arc::new(pool));

    // Start server
    axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

