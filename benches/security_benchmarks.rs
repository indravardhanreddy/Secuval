use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secureapis::{
    config::{RateLimitConfig, ValidationConfig},
    rate_limit::RateLimiter,
    validation::InputValidator,
};
use std::time::Duration;

fn benchmark_rate_limiter(c: &mut Criterion) {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_window: 1000,
        window_duration: Duration::from_secs(1),
        burst_size: 100,
        per_ip: true,
        per_user: false,
        adaptive: false,
    };

    let limiter = RateLimiter::new(config);
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("rate_limiter_check", |b| {
        b.iter(|| {
            runtime.block_on(async {
                limiter.check(black_box("test-ip")).await.ok();
            })
        })
    });
}

fn benchmark_input_validation(c: &mut Criterion) {
    let config = ValidationConfig::default();
    let validator = InputValidator::new(config);

    c.bench_function("sql_injection_check", |b| {
        b.iter(|| {
            validator.validate_string(
                black_box("SELECT * FROM users WHERE id = 1"),
                "query",
                &mut secureapis::core::SecurityContext::new(
                    "test".to_string(),
                    "127.0.0.1".to_string(),
                ),
            )
        })
    });

    c.bench_function("xss_check", |b| {
        b.iter(|| {
            validator.validate_string(
                black_box("<div>Normal HTML content</div>"),
                "content",
                &mut secureapis::core::SecurityContext::new(
                    "test".to_string(),
                    "127.0.0.1".to_string(),
                ),
            )
        })
    });

    c.bench_function("sanitization", |b| {
        b.iter(|| {
            validator.sanitize(black_box("<script>alert('test')</script>"))
        })
    });
}

criterion_group!(benches, benchmark_rate_limiter, benchmark_input_validation);
criterion_main!(benches);
