use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<WindowState>>,
    maximum_requests: u32,
    window: Duration,
}

struct WindowState {
    started_at: Instant,
    request_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitConfigError {
    MaximumRequestsMustBePositive,
    WindowMustBePositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    Exceeded { retry_after_seconds: u64 },
    Unavailable,
}

impl RateLimiter {
    pub fn new(maximum_requests: u32, window: Duration) -> Result<Self, RateLimitConfigError> {
        if maximum_requests == 0 {
            return Err(RateLimitConfigError::MaximumRequestsMustBePositive);
        }

        if window.is_zero() {
            return Err(RateLimitConfigError::WindowMustBePositive);
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(WindowState {
                started_at: Instant::now(),
                request_count: 0,
            })),
            maximum_requests,
            window,
        })
    }

    pub fn check(&self) -> Result<(), RateLimitError> {
        self.check_at(Instant::now())
    }

    fn check_at(&self, now: Instant) -> Result<(), RateLimitError> {
        let mut state = self.inner.lock().map_err(|_| RateLimitError::Unavailable)?;

        let elapsed = now.saturating_duration_since(state.started_at);

        if elapsed >= self.window {
            state.started_at = now;
            state.request_count = 0;
        }

        if state.request_count >= self.maximum_requests {
            let remaining = self.window.saturating_sub(elapsed);

            return Err(RateLimitError::Exceeded {
                retry_after_seconds: remaining.as_secs().max(1),
            });
        }

        state.request_count += 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{RateLimitConfigError, RateLimitError, RateLimiter};

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60)).expect("test limit is valid");

        assert_eq!(limiter.check(), Ok(()));
        assert_eq!(limiter.check(), Ok(()));
    }

    #[test]
    fn rejects_request_above_limit() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60)).expect("test limit is valid");

        assert_eq!(limiter.check(), Ok(()));

        assert!(matches!(
            limiter.check(),
            Err(RateLimitError::Exceeded { .. })
        ));
    }

    #[test]
    fn resets_after_window() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60)).expect("test limit is valid");

        let now = Instant::now();

        assert_eq!(limiter.check_at(now), Ok(()));

        assert!(matches!(
            limiter.check_at(now + Duration::from_secs(30)),
            Err(RateLimitError::Exceeded { .. })
        ));

        assert_eq!(limiter.check_at(now + Duration::from_secs(61)), Ok(()));
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert!(matches!(
            RateLimiter::new(0, Duration::from_secs(60)),
            Err(RateLimitConfigError::MaximumRequestsMustBePositive)
        ));

        assert!(matches!(
            RateLimiter::new(10, Duration::ZERO),
            Err(RateLimitConfigError::WindowMustBePositive)
        ));
    }
}
