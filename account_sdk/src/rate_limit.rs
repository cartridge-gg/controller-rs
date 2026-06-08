use std::future::Future;
use std::time::Duration;

use starknet::providers::ProviderError;

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let multiplier = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        let delay = self.base_delay.saturating_mul(multiplier);
        delay.min(self.max_delay)
    }
}

pub async fn retry_with_policy<T, E, F, Fut, I>(
    policy: RetryPolicy,
    mut operation: F,
    is_rate_limited: I,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    I: Fn(&E) -> bool,
{
    let mut attempt = 0;

    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) if is_rate_limited(&error) && attempt + 1 < policy.max_attempts => {
                sleep(policy.delay_for_attempt(attempt)).await;
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

pub async fn sleep(delay: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::sleep(delay).await;
    }

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        use web_sys::WorkerGlobalScope;

        let mut cb = |resolve: js_sys::Function, _reject: js_sys::Function| {
            if let Ok(worker_scope) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
                worker_scope
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        &resolve,
                        delay.as_millis() as i32,
                    )
                    .expect("should register `setTimeout`");
            } else {
                web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        &resolve,
                        delay.as_millis() as i32,
                    )
                    .expect("should register `setTimeout`");
            }
        };
        let promise = js_sys::Promise::new(&mut cb);
        wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
    }
}

pub fn is_provider_rate_limited(error: &ProviderError) -> bool {
    match error {
        ProviderError::RateLimited => true,
        ProviderError::Other(other) => {
            let message = other.to_string().to_ascii_lowercase();
            message.contains("rate limit")
                || message.contains("too many requests")
                || message.contains("429")
        }
        ProviderError::StarknetError(starknet_error) => {
            let message = starknet_error.to_string().to_ascii_lowercase();
            message.contains("rate limit") || message.contains("too many requests")
        }
        ProviderError::ArrayLengthMismatch => false,
    }
}

pub fn is_reqwest_rate_limited(error: &reqwest::Error) -> bool {
    error.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS)
        || error
            .to_string()
            .to_ascii_lowercase()
            .contains("rate limit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_exponential_and_capped() {
        let policy = RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(2),
        };

        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(500));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(2));
    }

    #[test]
    fn detects_provider_rate_limit_errors() {
        assert!(is_provider_rate_limited(&ProviderError::RateLimited));
        assert!(!is_provider_rate_limited(
            &ProviderError::ArrayLengthMismatch
        ));
    }
}
