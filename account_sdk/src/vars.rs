#[cfg(target_arch = "wasm32")]
use {js_sys, web_sys};

pub fn get_cartridge_api_url() -> String {
    get_env("CARTRIDGE_API_URL", "http://localhost:8000")
}

pub fn get_env(key: &str, default: &str) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        if let Ok(window) = web_sys::window().ok_or("no window") {
            if let Ok(env_obj) = js_sys::Reflect::get(&window, &"__WASM_ENV__".into()) {
                if !env_obj.is_undefined() {
                    if let Ok(value) = js_sys::Reflect::get(&env_obj, &key.into()) {
                        if let Some(str_value) = value.as_string() {
                            return str_value;
                        }
                    }
                }
            }
        }
        default.to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        match std::env::var(key) {
            Ok(val) => val,
            Err(_e) => default.to_string(),
        }
    }
}
