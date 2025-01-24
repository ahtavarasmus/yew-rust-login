use axum::{
    routing::{get, post},
    Router,
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    extract::State,
};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use jsonwebtoken::{encode, Header, EncodingKey};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::{TraceLayer, DefaultMakeSpan, DefaultOnResponse};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;
use std::sync::Arc;
use chrono::{Duration, Utc};  // Add this for timestamp
use serde_json::json;         // Add this for the json! macro

// Import our models
mod models;  // First declare the module
use models::{User, NewUser, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse};  // Then import the types

// Import our schema
mod schema;
use schema::users;  // This fixes the users::table not found error


type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;


#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();
    // Set up database connection pool
    let manager = ConnectionManager::<SqliteConnection>::new("database.db");
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    let conn = &mut pool.get().expect("Failed to get DB connection");
    // Create router with CORS
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/register", post(register))
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

async fn login(
    State(pool): State<Arc<DbPool>>,
    Json(login_req): Json<LoginRequest>,
) -> Json<LoginResponse> {
    let conn = &mut pool.get().unwrap();
    
    // Find user and verify password (simplified for example)
    let user = users::table
        .filter(users::username.eq(&login_req.username))
        .select(User::as_select())
        .first::<User>(conn)
        .optional()
        .unwrap();

    match user {
        Some(user) if bcrypt::verify(&login_req.password, &user.password_hash).unwrap() => {
            // Generate JWT token (simplified)
            let token = encode(
                &Header::default(),
                &json!({ "sub": user.id, "exp": (Utc::now() + Duration::hours(24)).timestamp() }),
                &EncodingKey::from_secret("your-secret-key".as_ref()),
            ).unwrap();
           
            Json(LoginResponse { token })
        },
        _ => panic!("Invalid credentials"), // In real app, handle this properly
    }
}


async fn register(
    State(pool): State<Arc<DbPool>>,
    Json(reg_req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<serde_json::Value>)> {
    let conn = &mut pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Database connection error: {}", e) })),
        )
    })?;
    
    // Check if username exists
    let existing_user = users::table
        .filter(users::username.eq(&reg_req.username))
        .select(User::as_select())
        .first::<User>(conn)
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Database error: {}", e) })),
            )
        })?;

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({ "error": "Username already exists" })),
        ));
    }

    // Hash password
    let password_hash = bcrypt::hash(&reg_req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Password hashing failed: {}", e) })),
            )
        })?;

    // Create and insert user
    let new_user = NewUser {
        username: reg_req.username,
        email: reg_req.email,
        password_hash,
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(conn)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("User creation failed: {}", e) })),
            )
        })?;

    Ok(Json(RegisterResponse {
        message: "User registered successfully".to_string(),
    }))
}
