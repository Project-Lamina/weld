use std::time::Instant;

pub struct PhaseTimer(Option<Instant>);

impl PhaseTimer {
    pub fn new() -> Self {
        Self(std::env::var_os("WELD_TIMINGS").map(|_| Instant::now()))
    }

    pub fn mark(&mut self, phase: &str) {
        if let Some(last) = &mut self.0 {
            let now = Instant::now();
            log::debug!(
                "{phase}: {:.3} ms",
                now.duration_since(*last).as_secs_f64() * 1000.0
            );
            *last = now;
        }
    }
}
