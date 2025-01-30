pub mod home {
    use yew::prelude::*;
    use yew_router::prelude::*;
    use crate::Route;
    use web_sys::window;

    fn is_logged_in() -> bool {
        if let Some(window) = window() {
            if let Ok(Some(storage)) = window.local_storage() {
                if let Ok(Some(_token)) = storage.get_item("token") {
                    return true;
                }
            }
        }
        false
    }

    #[function_component]
    pub fn Home() -> Html {
        let logged_in = is_logged_in();

        let handle_logout = {
            Callback::from(move |_| {
                if let Some(window) = window() {
                    if let Ok(Some(storage)) = window.local_storage() {
                        let _ = storage.remove_item("token");
                        // Reload the page to reflect the logged out state
                        let _ = window.location().reload();
                    }
                }
            })
        };

        html! {
            <div class="home-container">
                <h1>{"Welcome to Our App"}</h1>
                {
                    if logged_in {
                        html! {
                            <div class="user-panel">
                                <p>{"You are logged in!"}</p>
                                <button onclick={handle_logout}>{"Logout"}</button>
                            </div>
                        }
                    } else {
                        html! {
                            <div class="auth-links">
                                <Link<Route> to={Route::Login}>
                                    {"Login"}
                                </Link<Route>>
                                {" or "}
                                <Link<Route> to={Route::Register}>
                                    {"Register"}
                                </Link<Route>>
                            </div>
                        }
                    }
                }
            </div>
        }
    }
}

pub mod login {
    use yew::prelude::*;
    use web_sys::HtmlInputElement;
    use gloo_net::http::Request;
    use serde::{Deserialize, Serialize};
    use yew_router::prelude::*;
    use crate::Route;
    #[derive(Serialize)]
    pub struct LoginRequest {
        username: String,
        password: String,
    }
    #[derive(Deserialize)]
    pub struct LoginResponse {
        token: String,
    }
    #[derive(Deserialize)]
    struct ErrorResponse {
        error: String,
    }

    #[function_component]
    pub fn Login() -> Html {
        let username = use_state(String::new);
        let password = use_state(String::new);
        let error = use_state(|| None::<String>);
        let success = use_state(|| None::<String>);

        let onsubmit = {
            let username = username.clone();
            let password = password.clone();
            let error_setter = error.clone();
            let success_setter = success.clone();
            
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                let username = (*username).clone();
                let password = (*password).clone();
                let error_setter = error_setter.clone();
                let success_setter = success_setter.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    match Request::post("http://localhost:3000/api/login")
                        .json(&LoginRequest { username, password })
                        .unwrap()
                        .send()
                        .await 
                    {
                        Ok(response) => {
                            if response.ok() {
                                match response.json::<LoginResponse>().await {
                                    Ok(resp) => {
                                        let window = web_sys::window().unwrap();
                                        if let Ok(Some(storage)) = window.local_storage() {
                                            if storage.set_item("token", &resp.token).is_ok() {
                                                error_setter.set(None);
                                                success_setter.set(Some("Login successful! Redirecting...".to_string()));
                                                
                                                // Redirect after a short delay to show the success message
                                                let window_clone = window.clone();
                                                wasm_bindgen_futures::spawn_local(async move {
                                                    gloo_timers::future::TimeoutFuture::new(1_000).await;
                                                    let _ = window_clone.location().set_href("/");
                                                });
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        error_setter.set(Some("Failed to parse server response".to_string()));
                                    }
                                }
                            } else {
                                match response.json::<ErrorResponse>().await {
                                    Ok(error_response) => {
                                        error_setter.set(Some(error_response.error));
                                    }
                                    Err(_) => {
                                        error_setter.set(Some("Login failed".to_string()));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error_setter.set(Some(format!("Request failed: {}", e)));
                        }
                    }
                });
            })
        };

        html! {
            <div class="login-container">
                <h1>{"Login"}</h1>
                {
                    if let Some(error_message) = (*error).as_ref() {
                        html! {
                            <div class="error-message" style="color: red; margin-bottom: 10px;">
                                {error_message}
                            </div>
                        }
                    } else if let Some(success_message) = (*success).as_ref() {
                        html! {
                            <div class="success-message" style="color: green; margin-bottom: 10px;">
                                {success_message}
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                <form onsubmit={onsubmit}>
                    <input
                        type="text"
                        placeholder="Username"
                        onchange={let username = username.clone(); move |e: Event| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            username.set(input.value());
                        }}
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        onchange={let password = password.clone(); move |e: Event| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            password.set(input.value());
                        }}
                    />
                    <button type="submit">{"Login"}</button>
                </form>
                <div class="auth-redirect">
                    {"Don't have an account? "}
                    <Link<Route> to={Route::Register}>
                        {"Register here"}
                    </Link<Route>>
                </div>
            </div>
        }
    }
}



pub mod register {
    use yew::prelude::*;
    use web_sys::HtmlInputElement;
    use gloo_net::http::Request;
    use serde::{Deserialize, Serialize};
    use yew_router::prelude::*;
    use crate::Route;

    #[derive(Serialize)]
    pub struct RegisterRequest {
        username: String,
        password: String,
        email: String,
    }

    #[derive(Deserialize)]
    pub struct RegisterResponse {
        message: String,
    }

    #[derive(Deserialize)]
    pub struct ErrorResponse {
        error: String,
    }

    #[function_component]
    pub fn Register() -> Html {
        let username = use_state(String::new);
        let password = use_state(String::new);
        let email = use_state(String::new);
        let error = use_state(|| None::<String>);
        let success = use_state(|| None::<String>);

        let onsubmit = {
            let username = username.clone();
            let password = password.clone();
            let email = email.clone();
            let error_setter = error.clone();
            let success_setter = success.clone();
            
            Callback::from(move |e: SubmitEvent| {
                e.prevent_default();
                let username = (*username).clone();
                let password = (*password).clone();
                let email = (*email).clone();
                let error_setter = error_setter.clone();
                let success_setter = success_setter.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    match Request::post("http://localhost:3000/api/register")
                        .json(&RegisterRequest { 
                            username, 
                            password,
                            email,
                        })
                        .unwrap()
                        .send()
                        .await 
                    {
                        Ok(resp) => {
                            if resp.ok() {
                                match resp.json::<RegisterResponse>().await {
                                    Ok(success_response) => {
                                        error_setter.set(None);
                                        success_setter.set(Some(success_response.message));
                                        
                                        let window = web_sys::window().unwrap();
                                        let window_clone = window.clone();
                                        wasm_bindgen_futures::spawn_local(async move {
                                            gloo_timers::future::TimeoutFuture::new(2_000).await;
                                            let _ = window_clone.location().set_href("/login");
                                        });
                                    }
                                    Err(_) => {
                                        error_setter.set(Some("Failed to parse server response".to_string()));
                                    }
                                }
                            } else {
                                match resp.json::<ErrorResponse>().await {
                                    Ok(error_response) => {
                                        error_setter.set(Some(error_response.error));
                                    }
                                    Err(_) => {
                                        error_setter.set(Some("An unknown error occurred".to_string()));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error_setter.set(Some(format!("Request failed: {}", e)));
                        }
                    }
                });
            })
        };

        html! {
            <div class="register-container">
                <h1>{"Register"}</h1>
                {
                    if let Some(error_message) = (*error).as_ref() {
                        html! {
                            <div class="error-message" style="color: red; margin-bottom: 10px;">
                                {error_message}
                            </div>
                        }
                    } else if let Some(success_message) = (*success).as_ref() {
                        html! {
                            <div class="success-message" style="color: green; margin-bottom: 10px;">
                                {success_message}
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                <form onsubmit={onsubmit}>
                    <input
                        type="text"
                        placeholder="Username"
                        onchange={let username = username.clone(); move |e: Event| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            username.set(input.value());
                        }}
                    />
                    <input
                        type="email"
                        placeholder="Email"
                        onchange={let email = email.clone(); move |e: Event| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            email.set(input.value());
                        }}
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        onchange={let password = password.clone(); move |e: Event| {
                            let input: HtmlInputElement = e.target_unchecked_into();
                            password.set(input.value());
                        }}
                    />
                    <button type="submit">{"Register"}</button>
                </form>
                <div class="auth-redirect">
                    {"Already have an account? "}
                    <Link<Route> to={Route::Login}>
                        {"Login here"}
                    </Link<Route>>
                </div>
            </div>
        }
    }
}

pub mod admin {
    use yew::prelude::*;
    use web_sys::window;
    use gloo_net::http::Request;
    use serde::Deserialize;

    #[derive(Deserialize, Clone, Debug)]
    struct UserInfo {
        id: i32,
        username: String,
        email: String,
    }

    #[function_component]
    pub fn Admin() -> Html {
        let users = use_state(|| Vec::new());
        let error = use_state(|| None::<String>);

        // Clone state handles for the effect
        let users_effect = users.clone();
        let error_effect = error.clone();

        use_effect_with_deps(move |_| {
            let users = users_effect;
            let error = error_effect;
            wasm_bindgen_futures::spawn_local(async move {
                // Get token from localStorage
                let token = window()
                    .and_then(|w| w.local_storage().ok())
                    .flatten()
                    .and_then(|storage| storage.get_item("token").ok())
                    .flatten();

                if let Some(token) = token {
                    match Request::get("http://localhost:3000/api/admin/users")
                        .header("Authorization", &format!("Bearer {}", token))
                        .send()
                        .await
                    {
                        Ok(response) => {
                            if response.ok() {
                                match response.json::<Vec<UserInfo>>().await {
                                    Ok(data) => {
                                        users.set(data);
                                    }
                                    Err(_) => {
                                        error.set(Some("Failed to parse users data".to_string()));
                                    }
                                }
                            } else {
                                error.set(Some("Not authorized to view this page".to_string()));
                            }
                        }
                        Err(_) => {
                            error.set(Some("Failed to fetch users".to_string()));
                        }
                    }
                }
            });
            || ()
        }, ());

        html! {
            <div class="admin-container">
                <h1>{"Admin Dashboard"}</h1>
                {
                    if let Some(error_msg) = (*error).as_ref().clone() {
                        html! {
                            <div class="error-message">
                                {error_msg}
                            </div>
                        }
                    } else {
                        html! {
                            <div class="users-list">
                                <h2>{"Users List"}</h2>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>{"ID"}</th>
                                            <th>{"Username"}</th>
                                            <th>{"Email"}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {
                                            users.iter().map(|user| {
                                                html! {
                                                    <tr key={user.id}>
                                                        <td>{user.id}</td>
                                                        <td>{&user.username}</td>
                                                        <td>{&user.email}</td>
                                                    </tr>
                                                }
                                            }).collect::<Html>()
                                        }
                                    </tbody>
                                </table>
                            </div>
                        }
                    }
                }
            </div>
        }
    }
}
