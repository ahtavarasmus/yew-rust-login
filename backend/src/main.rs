use dotenvy::dotenv;
use axum::{
    routing::{get, post},
    Router,
    Json,
    http::{StatusCode, HeaderMap},
    response::Response,
    extract::State,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use jsonwebtoken::{encode, Header, EncodingKey};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::{TraceLayer, DefaultMakeSpan, DefaultOnResponse};
use tracing::Level;
use std::sync::Arc;
use chrono::{Duration, Utc};  // Add this for timestamp
use serde_json::json;         // Add this for the json! macro

// Import our models
mod models;  // First declare the module
use models::{User, NewUser, LoginRequest, RegisterRequest, RegisterResponse};  // Then import the types

// Import our schema
mod schema;
use schema::users;  // This fixes the users::table not found error


type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

#[derive(Debug, Serialize)]
struct UserResponse {
    id: i32,
    username: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: i32,
    exp: i64,
}

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


async fn get_users(
    State(pool): State<Arc<DbPool>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, Json<serde_json::Value>)> {
    // Extract token from Authorization header
    let auth_header = headers.get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(token) => token,
        None => return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "No authorization token provided"}))
        )),
    };

    // Decode and validate JWT token
    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(std::env::var("JWT_SECRET_KEY")
                    .expect("JWT_SECRET_KEY must be set in environment")
                    .as_bytes()),
        &Validation::new(Algorithm::HS256)
    ) {
        Ok(token_data) => token_data.claims,
        Err(_) => return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid token"}))
        )),
    };

    let conn = &mut pool.get().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Database connection error: {}", e)}))
    ))?;

    // Check if the user is admin (username is 'rasmus')
    let user = users::table
        .find(claims.sub)
        .first::<User>(conn)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Database error: {}", e)}))
        ))?;

    if user.username != "rasmus" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only admin can access this endpoint"}))
        ));
    }

    // Get all users
    let users_list = users::table
        .select((users::id, users::username, users::email))
        .load::<(i32, String, String)>(conn)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Database error: {}", e)}))
        ))?;

    let users_response: Vec<UserResponse> = users_list
        .into_iter()
        .map(|(id, username, email)| UserResponse { id, username, email })
        .collect();

    Ok(Json(users_response))
}


async fn login(
    State(pool): State<Arc<DbPool>>,
    Json(login_req): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let conn = &mut pool.get().map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Database connection error"}))
    ))?;
    
    let user = users::table
            .filter(users::username.eq(&login_req.username))
            .select(User::as_select())
            .first::<User>(conn)
            .optional()
            .map_err(|_| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"}))
            ))?;

    match user {
        Some(user) => {
            if let Ok(valid) = bcrypt::verify(&login_req.password, &user.password_hash) {
                if valid {
                    // Generate access token (short-lived)
                    let access_token = encode(
                        &Header::default(),
                        &json!({
                            "sub": user.id,
                            "exp": (Utc::now() + Duration::minutes(15)).timestamp(),
                            "type": "access"
                        }),
                        &EncodingKey::from_secret(std::env::var("JWT_SECRET_KEY")
                            .expect("JWT_SECRET_KEY must be set in environment")
                            .as_bytes()),
                    ).map_err(|_| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Token generation failed"}))
                    ))?;
    
                    // Generate refresh token (long-lived)
                    let refresh_token = encode(
                        &Header::default(),
                        &json!({
                            "sub": user.id,
                            "exp": (Utc::now() + Duration::days(7)).timestamp(),
                            "type": "refresh"
                        }),
                        &EncodingKey::from_secret(std::env::var("JWT_REFRESH_KEY")
                            .expect("JWT_REFRESH_KEY must be set in environment")
                            .as_bytes()),
                    ).map_err(|_| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Token generation failed"}))
                    ))?;
                    // Create response with HttpOnly cookies
                    let mut response = Response::new(
                        axum::body::boxed(axum::body::Full::from(
                            Json(json!({"message": "Login successful", "token": access_token})).to_string()
                        ))
                    );
                    
                    let cookie_options = "; HttpOnly; Secure; SameSite=Strict; Path=/";
                    response.headers_mut().insert(
                        "Set-Cookie",
                        format!("access_token={}{}; Max-Age=900", access_token, cookie_options)
                            .parse()
                            .unwrap(),
                    );
                    response.headers_mut().insert(
                        "Set-Cookie",
                        format!("refresh_token={}{}; Max-Age=604800", refresh_token, cookie_options)
                            .parse()
                            .unwrap(),
                    );
                    
                    // Set content type header
                    response.headers_mut().insert(
                        "Content-Type",
                        "application/json".parse().unwrap()
                    );
    
                    Ok(response)
                } else {
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "Invalid credentials"}))
                    ))
                }
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid credentials"}))
                ))
            }
        },
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"}))
        )),
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
