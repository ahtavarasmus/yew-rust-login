use yew::prelude::*;
use yew_router::prelude::*;
use tracing::info;

mod pages;
use pages::{
    home::Home,
    login::Login,
    register::Register,
    admin::Admin,
};

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/login")]
    Login,
    #[at("/register")]
    Register,
    #[at("/admin")]
    Admin,
}


fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => {
            info!("Rendering Home page");
            html! { <Home /> }
        },
        Route::Login => {
            info!("Rendering Login page");
            html! { <Login /> }
        },
        Route::Register => {
            info!("Rendering Register page");
            html! { <Register /> }
        },
        Route::Admin => {
            info!("Rendering Admin page");
            html! { <Admin /> }
        },
    }
}
#[function_component]
fn App() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={switch} />
        </BrowserRouter>
        }
}

fn main() {
    // Initialize console error panic hook for better error messages
    console_error_panic_hook::set_once();
    
    // Initialize tracing for logging
    tracing_wasm::set_as_global_default();
    
    info!("Starting application");
    yew::Renderer::<App>::new().render();
}

        
