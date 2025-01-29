use std::sync::Arc;
use axum::{
    Json,
    extract::State,
    response::Response,
    http::{StatusCode, HeaderMap}
};
use serde_json::json;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::{Duration, Utc};
use diesel::prelude::*;



use crate::{
    models::user_models::{User, NewUser},
    handlers::auth_models::{LoginRequest, RegisterRequest, RegisterResponse, UserResponse, Claims},
    schema::users,
    DbPool
};



pub async fn get_users(
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


pub async fn login(
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


pub async fn register(
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
