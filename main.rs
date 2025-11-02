use actix_web::{//
    cookie::{Cookie, SameSite},
    get, web, App, HttpResponse, HttpServer,
};//
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;//
use std::time::{SystemTime, UNIX_EPOCH};
use tera::{Context, Tera};
use tracing::{info, error};
use uuid::Uuid;
use validator::Validate;
//
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
struct User {
    id: Uuid,
    email: String,
    username: String,
    password_hash: Option<String>,
    name: Option<String>,
    oauth_provider: Option<String>,
    oauth_id: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Validate)]
struct NewUser {
    #[validate(email)]
    email: String,
    #[validate(length(min = 3, max = 30))]
    username: String,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 1))]
    name: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct LoginRequest {
    #[validate(email)]
    email: String,
    #[validate(length(min = 1))]
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SignupRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 3, max = 30))]
    pub username: String,
    #[validate(length(min = 8))]
    pub password: String,
    #[validate(length(min = 1))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UsernameSetupRequest {
    #[validate(length(min = 3, max = 30))]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    email: String,
    exp: usize,
}

#[derive(Clone)]
struct OAuthConfig {
    google_client_id: String,
    google_client_secret: String,
    github_client_id: String,
    github_client_secret: String,
    redirect_base_url: String,
}

struct AppState {
    tera: Tera,
    jwt_secret: String,
    oauth_config: OAuthConfig,
    db_pool: PgPool,
    http_client: reqwest::Client,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    id_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: String,
    name: String,
    picture: Option<String>,
    sub: String,
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
}

#[derive(Deserialize)]
struct GitHubUserInfo {
    email: Option<String>,
    name: Option<String>,
    login: String,
    id: u64,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUserEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Debug)]
struct AppError {
    message: String,
    status: actix_web::http::StatusCode,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl actix_web::error::ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status).body(self.message.clone())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        error!("Database error: {}", err);
        AppError {
            message: "Database operation failed".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

async fn index(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "index.html", "JRep")
}

async fn home(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "home.html", "Home")
}

async fn about(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "about.html", "About")
}

async fn installations(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "installation.html", "Installations")
}

async fn features(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "features.html", "Features")
}

async fn contact(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "contact.html", "Contact")
}

async fn api_reference(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "apireference.html", "API Reference")
}

async fn blog(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "blog.html", "Blog")
}

async fn careers(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "careers.html", "Careers")
}

async fn community(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "community.html", "Community")
}

async fn documentation(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "documentation.html", "Documentation")
}

async fn getting_started(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "gettingstarted.html", "Getting Started")
}

async fn pricing(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "pricing.html", "Pricing")
}

async fn releases(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "releases.html", "Releases")
}

async fn tutorials(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "tutorials.html", "Tutorials")
}

async fn support(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "support.html", "Support")
}

async fn dashboard(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "dashboard.html", "Dashboard")
}

async fn droom(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "droom.html", "Droom")
}

// Helper function for template rendering
fn render_template(tera: &Tera, template: &str, title: &str) -> Result<HttpResponse, AppError> {
    let mut ctx = Context::new();
    ctx.insert("title", title);
    
    let rendered = tera.render(template, &ctx)
        .map_err(|e| {
            error!("Template rendering error: {}", e);
            AppError {
                message: "Template rendering failed".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;
    
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// Auth pages
async fn signup_page(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "signup.html", "Sign Up")
}

async fn login_page(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "login.html", "Log In")
}

async fn username_setup_page(data: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    render_template(&data.tera, "username_setup.html", "Choose Username")
}

// Auth handlers
async fn signup(
    data: web::Data<AppState>,
    form: web::Form<SignupRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate the form data
    if let Err(validation_errors) = form.validate() {
        return Ok(HttpResponse::BadRequest().body(format!("Validation errors: {:?}", validation_errors)));
    }

    // Check if email already exists (from any source - manual signup or OAuth)
    let existing_email = sqlx::query!(
        "SELECT id, oauth_provider FROM users WHERE email = $1", 
        form.email
    )
    .fetch_optional(&data.db_pool)
    .await?;

    if let Some(user) = existing_email {
        if let Some(provider) = user.oauth_provider {
            return Ok(HttpResponse::BadRequest().body(
                format!("This email is already linked with a {} account. Please log in using {}.", provider, provider)
            ));    
        } else {
            return Ok(HttpResponse::BadRequest().body("User with this email already exists"));
        }  
    }

    // Check if username already exists
    let existing_username = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        form.username
    )
    .fetch_optional(&data.db_pool)
    .await?;

    if existing_username.is_some() {
        return Ok(HttpResponse::BadRequest().body("Username is already taken. Please choose a different username."));
    }

    let password_hash = hash(&form.password, DEFAULT_COST)
        .map_err(|e| {
            error!("Password hashing error: {}", e);
            AppError {
                message: "Failed to process password".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;
    
    let user_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, email, username, password_hash, name, oauth_provider, oauth_id)
         VALUES ($1, $2, $3, $4, $5, NULL, NULL)",
        user_id,
        form.email,
        form.username,
        password_hash,
        form.name
    )
    .execute(&data.db_pool)
    .await?;

    info!("New user registered: {} (username: {})", form.email, form.username);
    let token = create_jwt_token(&data.jwt_secret, user_id, &form.email)?;

    Ok(HttpResponse::SeeOther()
        .cookie(create_auth_cookie(&token))
        .append_header(("Location", "/dashboard"))
        .finish())
}

async fn login(
    data: web::Data<AppState>,
    form: web::Form<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    if let Err(validation_errors) = form.validate() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {:?}", validation_errors)
        })));
    }

    // Fetch user
    let user_result = sqlx::query!(
        "SELECT id, email, username, password_hash, name, oauth_provider, oauth_id, created_at
         FROM users WHERE email = $1",
        form.email
    )
    .fetch_optional(&data.db_pool)
    .await?;

    let user = match user_result {
        Some(u) => u,
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "Invalid email or password."
            })));
        }
    };

    // Check if this is an OAuth user trying to login with password
    if let Some(provider) = &user.oauth_provider {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("This account is registered with {}. Please use the 'Continue with {}' button instead.", provider, provider)
        })));
    }

    // For local accounts, verify password
    let password_hash = user.password_hash.as_deref().ok_or_else(|| AppError {
        message: "Invalid user account".to_string(),
        status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
    })?;

    let password_valid = verify(&form.password, password_hash)
        .map_err(|e| AppError {
            message: format!("Password verification error: {}", e),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "error": "Invalid email or password."
        })));
    }

    // Create JWT token
    let token = create_jwt_token(&data.jwt_secret, user.id, &user.email)?;

    Ok(HttpResponse::Ok()
        .cookie(create_auth_cookie(&token))
        .json(serde_json::json!({
            "success": true,
            "redirect": "/dashboard"
        })))
}

async fn logout() -> HttpResponse {
    HttpResponse::SeeOther()
        .cookie(create_logout_cookie())
        .append_header(("Location", "/"))
        .finish()
}

// OAuth handlers
async fn google_auth_start(data: web::Data<AppState>) -> HttpResponse {
    let redirect_uri = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
         client_id={}&\
         redirect_uri={}/auth/google/callback&\
         response_type=code&\
         scope=email%20profile&\
         access_type=offline",
        data.oauth_config.google_client_id,
        data.oauth_config.redirect_base_url
    );
    
    HttpResponse::SeeOther()
        .append_header(("Location", redirect_uri))
        .finish()
}

async fn github_auth_start(data: web::Data<AppState>) -> HttpResponse {
    let redirect_uri = format!(
        "https://github.com/login/oauth/authorize?\
         client_id={}&\
         redirect_uri={}/auth/github/callback&\
         scope=user:email",
        data.oauth_config.github_client_id,
        data.oauth_config.redirect_base_url
    );
    
    HttpResponse::SeeOther()
        .append_header(("Location", redirect_uri))
        .finish()
}

#[get("/auth/google/callback")]
async fn google_callback(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    // Log all headers for debugging
    for (key, value) in req.headers() {
        info!("Header: {}: {:?}", key, value);
    }
    
    let code = get_query_param(&req, "code")?;
    info!("Received Google OAuth code (length: {}): {}", code.len(), code);

    // Check if code looks valid
    if code.is_empty() || code.len() < 10 {
        error!("Invalid code received: '{}'", code);
        return Err(AppError {
            message: "Invalid authorization code received from Google".to_string(),
            status: actix_web::http::StatusCode::BAD_REQUEST,
        });
    }

    // Check for errors in the callback
    if let Ok(error_param) = get_query_param(&req, "error") {
        let error_description = get_query_param(&req, "error_description").unwrap_or_default();
        error!("Google OAuth error: {} - {}", error_param, error_description);
        return Err(AppError {
            message: format!("OAuth error: {} - {}", error_param, error_description),
            status: actix_web::http::StatusCode::BAD_REQUEST,
        });
    }

    // Exchange code for tokens
    let token_data = match exchange_google_code(&data, &code).await {
        Ok(token) => {
            info!("Successfully exchanged code for tokens");
            token
        }
        Err(e) => {
            error!("Failed to exchange code for tokens: {}", e);
            return Err(e);
        }
    };

    // Get user info
    let user_info = match get_google_user_info(&token_data.access_token).await {
        Ok(info) => {
            info!("Successfully fetched user info: {}", info.email);
            info
        }
        Err(e) => {
            error!("Failed to get user info: {}", e);
            return Err(e);
        }
    };

    // Check if email already exists (prevents reusing Google emails)
    let existing_user = sqlx::query!(
        "SELECT id, username, oauth_provider FROM users WHERE email = $1",
        user_info.email
    )
    .fetch_optional(&data.db_pool)
    .await?;

    let user_id = match existing_user {
        Some(user) => {
            // Email exists - check if it's a local account or OAuth
            if user.oauth_provider.is_none() {
                // Local user trying to login with OAuth - BLOCK THIS
                return Ok(HttpResponse::BadRequest().body(
                    "This email is already registered with a password. Please log in using your email and password instead."
                ));
            }
            // OAuth user - allow login
            info!("Existing OAuth user logging in: {}", user_info.email);
            user.id
        }
        None => {
            // New user - create temporary auth and redirect to username setup
            let temp_user_id = Uuid::new_v4();
            let temp_token = create_temp_oauth_token(&data.jwt_secret, temp_user_id, &user_info.email, &user_info.name, &user_info.sub, "google")?;
            
            return Ok(HttpResponse::SeeOther()
                .cookie(create_temp_auth_cookie(&temp_token))
                .append_header(("Location", "/username-setup"))
                .finish());
        }
    };

    // Create JWT token for existing user
    let token = create_jwt_token(&data.jwt_secret, user_id, &user_info.email)?;
    info!("OAuth login successful for: {}", user_info.email);

    Ok(HttpResponse::SeeOther()
        .cookie(create_auth_cookie(&token))
        .append_header(("Location", "/dashboard"))
        .finish())
}

async fn github_callback(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let code = get_query_param(&req, "code")?;

    // Exchange code for access token
    let access_token = exchange_github_code(&data, &code).await?;

    // Get user info
    let (user_info, primary_email) = get_github_user_info(&access_token).await?;
    let email = primary_email.unwrap_or_else(|| format!("{}@users.noreply.github.com", user_info.login));

    // Check if email already exists (prevents reusing GitHub emails)
    let existing_user = sqlx::query!(
        "SELECT id, username, oauth_provider FROM users WHERE email = $1",
        email
    )
    .fetch_optional(&data.db_pool)
    .await?;

    let user_id = match existing_user {
        Some(user) => {
            // Email exists - check if it's a local account or OAuth
            if user.oauth_provider.is_none() {
                // Local user trying to login with OAuth - BLOCK THIS
                return Ok(HttpResponse::BadRequest().body(
                    "This email is already registered with a password. Please log in using your email and password instead."
                ));
            }
            // OAuth user - allow login
            info!("Existing OAuth user logging in: {}", email);
            user.id
        }
        None => {
            // New user - create temporary auth and redirect to username setup
            let temp_user_id = Uuid::new_v4();
            let name = user_info.name.clone().unwrap_or_else(|| user_info.login.clone());
            let temp_token = create_temp_oauth_token(&data.jwt_secret, temp_user_id, &email, &name, &user_info.id.to_string(), "github")?;
            
            return Ok(HttpResponse::SeeOther()
                .cookie(create_temp_auth_cookie(&temp_token))
                .append_header(("Location", "/username-setup"))
                .finish());
        }
    };

    // Create JWT token for existing user
    let token = create_jwt_token(&data.jwt_secret, user_id, &email)?;
    info!("GitHub OAuth login successful for: {}", email);

    Ok(HttpResponse::SeeOther()
        .cookie(create_auth_cookie(&token))
        .append_header(("Location", "/dashboard"))
        .finish())
}

// Username setup handler for OAuth users
async fn setup_username(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
    form: web::Form<UsernameSetupRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate username
    if let Err(validation_errors) = form.validate() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("Validation failed: {:?}", validation_errors)
        })));
    }

    // Get temporary OAuth token from cookie
    let temp_token = match req.cookie("temp_auth") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "No temporary authentication found. Please try logging in again."
            })));
        }
    };

    // Decode temp token to get OAuth info
    let temp_claims = match decode_temp_oauth_token(&data.jwt_secret, &temp_token) {
        Ok(claims) => claims,
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "Invalid or expired session. Please try logging in again."
            })));
        }
    };

    // Check if username is already taken
    let existing_username = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        form.username
    )
    .fetch_optional(&data.db_pool)
    .await?;

    if existing_username.is_some() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Username is already taken. Please choose a different username."
        })));
    }

    // Double-check email hasn't been registered in the meantime
    let existing_email = sqlx::query!(
        "SELECT id FROM users WHERE email = $1",
        temp_claims.email
    )
    .fetch_optional(&data.db_pool)
    .await?;

    if existing_email.is_some() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "This email has already been registered."
        })));
    }

    // Create the user account with duplicate guard at DB layer
    let user_id = Uuid::new_v4();
    let insert_result = sqlx::query!(
        "INSERT INTO users (id, email, username, name, oauth_provider, oauth_id, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        user_id,
        temp_claims.email,
        form.username,
        temp_claims.name,
        temp_claims.oauth_provider,
        temp_claims.oauth_id
    )
    .execute(&data.db_pool)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) => {
            // Postgres unique violation code
            if db_err.code().as_deref() == Some("23505") {
                let detail = db_err.message();
                let is_username = detail.to_lowercase().contains("username");
                let is_email = detail.to_lowercase().contains("email");
                let msg = if is_username {
                    "Username is already taken. Please choose a different username."
                } else if is_email {
                    "This email has already been registered."
                } else {
                    "This account already exists."
                };
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": msg
                })));
            }
            // Other DB errors
            return Err(sqlx::Error::Database(db_err).into());
        }
        Err(e) => return Err(e.into()),
    }

    info!("New OAuth user registered: {} (username: {}, provider: {})", 
          temp_claims.email, form.username, temp_claims.oauth_provider);

    // Create permanent JWT token
    let token = create_jwt_token(&data.jwt_secret, user_id, &temp_claims.email)?;

    // Remove temp cookie and set permanent auth cookie
    Ok(HttpResponse::Ok()
        .cookie(create_temp_auth_removal_cookie())
        .cookie(create_auth_cookie(&token))
        .json(serde_json::json!({
            "success": true,
            "redirect": "/dashboard"
        })))
}

// Helper functions
fn create_jwt_token(secret: &str, user_id: Uuid, email: &str) -> Result<String, AppError> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 24 * 60 * 60; // 24 hours

    let claims = Claims {
        sub: user_id,
        email: email.to_string(),
        exp: expiration as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|e| {
        error!("JWT encoding error: {}", e);
        AppError {
            message: "Token creation failed".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct TempOAuthClaims {
    sub: Uuid,
    email: String,
    name: String,
    oauth_id: String,
    oauth_provider: String,
    exp: usize,
}

fn create_temp_oauth_token(
    secret: &str,
    temp_id: Uuid,
    email: &str,
    name: &str,
    oauth_id: &str,
    oauth_provider: &str,
) -> Result<String, AppError> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 600; // 10 minutes

    let claims = TempOAuthClaims {
        sub: temp_id,
        email: email.to_string(),
        name: name.to_string(),
        oauth_id: oauth_id.to_string(),
        oauth_provider: oauth_provider.to_string(),
        exp: expiration as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|e| {
        error!("Temp JWT encoding error: {}", e);
        AppError {
            message: "Token creation failed".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })
}

fn decode_temp_oauth_token(secret: &str, token: &str) -> Result<TempOAuthClaims, AppError> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    
    let token_data = decode::<TempOAuthClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ).map_err(|e| {
        error!("JWT decoding error: {}", e);
        AppError {
            message: "Invalid or expired token".to_string(),
            status: actix_web::http::StatusCode::UNAUTHORIZED,
        }
    })?;

    Ok(token_data.claims)
}

fn create_auth_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("auth_token", token.to_string())
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish()
}

fn create_temp_auth_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("temp_auth", token.to_string())
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::minutes(10))
        .finish()
}

fn create_logout_cookie() -> Cookie<'static> {
    Cookie::build("auth_token", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .http_only(true)
        .finish()
}

fn create_temp_auth_removal_cookie() -> Cookie<'static> {
    Cookie::build("temp_auth", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .http_only(true)
        .finish()
}

fn get_query_param(req: &actix_web::HttpRequest, param: &str) -> Result<String, AppError> {
    let query = req.query_string();
    info!("Full query string: {}", query);
    
    // Parse query string properly
    let params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    
    info!("Parsed query parameters: {:?}", params);
    
    params.get(param)
        .cloned()
        .ok_or_else(|| AppError {
            message: format!("Missing '{}' parameter in callback. Available params: {:?}", param, params.keys()),
            status: actix_web::http::StatusCode::BAD_REQUEST,
        })
}

async fn exchange_google_code(data: &AppState, code: &str) -> Result<GoogleTokenResponse, AppError> {
    let redirect_uri = format!("{}/auth/google/callback", data.oauth_config.redirect_base_url);

    let params = [
        ("code", code),
        ("client_id", data.oauth_config.google_client_id.as_str()),
        ("client_secret", data.oauth_config.google_client_secret.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];

    info!("Exchanging code (length: {})", code.len());
    
    let response = data.http_client
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            error!("Google token exchange request failed: {}", e);
            AppError {
                message: format!("OAuth authentication failed: {}", e),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    let status = response.status();
    let response_text = response.text().await.map_err(|e| {
        error!("Failed to read response text: {}", e);
        AppError {
            message: "Failed to read OAuth response".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    info!("Google OAuth response status: {}", status);

    if !status.is_success() {
        error!("Google OAuth error: {} - {}", status, response_text);
        return Err(AppError {
            message: format!("OAuth authentication failed: {} - {}", status, response_text),
            status: actix_web::http::StatusCode::BAD_REQUEST,
        });
    }

    serde_json::from_str(&response_text).map_err(|e| {
        error!("Failed to parse token response: {}", e);
        AppError {
            message: "Failed to parse OAuth response".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })
}

async fn get_google_user_info(access_token: &str) -> Result<GoogleUserInfo, AppError> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!("Google user info fetch error: {}", e);
            AppError {
                message: "Failed to fetch user information".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    response.json::<GoogleUserInfo>().await.map_err(|e| {
        error!("Google user info parsing error: {}", e);
        AppError {
            message: "Failed to parse user information".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })
}

async fn exchange_github_code(data: &AppState, code: &str) -> Result<String, AppError> {
    let params = [
        ("code", code),
        ("client_id", &data.oauth_config.github_client_id),
        ("client_secret", &data.oauth_config.github_client_secret),
    ];

    let response = data.http_client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            error!("GitHub token exchange error: {}", e);
            AppError {
                message: "OAuth authentication failed".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    let token_data: GitHubTokenResponse = response.json::<GitHubTokenResponse>().await.map_err(|e| {
        error!("GitHub token response parsing error: {}", e);
        AppError {
            message: "OAuth authentication failed".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    Ok(token_data.access_token)
}

async fn get_github_user_info(access_token: &str) -> Result<(GitHubUserInfo, Option<String>), AppError> {
    let client = reqwest::Client::new();
    
    // Get user profile
    let user_response = client
        .get("https://api.github.com/user")
        .header("User-Agent", "JRep-App")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!("GitHub user info fetch error: {}", e);
            AppError {
                message: "Failed to fetch user information".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    let user_info: GitHubUserInfo = user_response.json::<GitHubUserInfo>().await.map_err(|e| {
        error!("GitHub user info parsing error: {}", e);
        AppError {
            message: "Failed to parse user information".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    // Get user emails to find primary email
    let emails_response = client
        .get("https://api.github.com/user/emails")
        .header("User-Agent", "JRep-App")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!("GitHub emails fetch error: {}", e);
            AppError {
                message: "Failed to fetch user emails".to_string(),
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    let emails: Vec<GitHubUserEmail> = emails_response.json::<Vec<GitHubUserEmail>>().await.map_err(|e| {
        error!("GitHub emails parsing error: {}", e);
        AppError {
            message: "Failed to parse user emails".to_string(),
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    let primary_email = emails
        .into_iter()
        .find(|email| email.primary && email.verified)
        .map(|email| email.email);

    Ok((user_info, primary_email))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    dotenvy::dotenv().ok();
    
    info!("Starting JRep server...");

    let tera = Tera::new("templates/**/*")
        .map_err(|e| {
            error!("Failed to load templates: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "Template loading failed")
        })?;

    let jwt_secret = env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set in environment");
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in environment");

    let redirect_base_url = env::var("REDIRECT_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());

    let oauth_config = OAuthConfig {
        google_client_id: env::var("GOOGLE_CLIENT_ID")
            .expect("GOOGLE_CLIENT_ID must be set in environment"),
        google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
            .expect("GOOGLE_CLIENT_SECRET must be set in environment"),
        github_client_id: env::var("GITHUB_CLIENT_ID")
            .expect("GITHUB_CLIENT_ID must be set in environment"),
        github_client_secret: env::var("GITHUB_CLIENT_SECRET")
            .expect("GITHUB_CLIENT_SECRET must be set in environment"),
        redirect_base_url,
    };

    let db_pool = PgPool::connect(&database_url)
        .await
        .map_err(|e| {
            error!("Database connection error: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "Database connection failed")
        })?;

    info!("Successfully connected to PostgreSQL database");

    let app_state = web::Data::new(AppState {
        tera,
        jwt_secret,
        oauth_config,
        db_pool,
        http_client: reqwest::Client::new(),
    });

    info!("Server running at http://127.0.0.1:8080/");

    // Start server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            // Page routes
            .route("/", web::get().to(home))
            .route("/index", web::get().to(index))
            .route("/about", web::get().to(about))
            .route("/installations", web::get().to(installations))
            .route("/features", web::get().to(features))
            .route("/contact", web::get().to(contact))
            .route("/apireference", web::get().to(api_reference))
            .route("/blog", web::get().to(blog))
            .route("/careers", web::get().to(careers))
            .route("/community", web::get().to(community))
            .route("/documentation", web::get().to(documentation))
            .route("/gettingstarted", web::get().to(getting_started))
            .route("/pricing", web::get().to(pricing))
            .route("/releases", web::get().to(releases))
            .route("/support", web::get().to(support))
            .route("/tutorials", web::get().to(tutorials))
            .route("/dashboard", web::get().to(dashboard))
            .route("/droom", web::get().to(droom))
            // Auth routes
            .route("/signup", web::get().to(signup_page))
            .route("/signup", web::post().to(signup))
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login))
            .route("/logout", web::get().to(logout))
            // Username setup for OAuth users
            .route("/username-setup", web::get().to(username_setup_page))
            .route("/username-setup", web::post().to(setup_username))
            // OAuth routes
            .route("/auth/google", web::get().to(google_auth_start))
            .service(google_callback)
            .route("/auth/github", web::get().to(github_auth_start))
            .route("/auth/github/callback", web::get().to(github_callback))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
