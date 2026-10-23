use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use identity_service::{config::Config, create_router, AppState};
use tower::ServiceExt;
#[tokio::test]
#[ignore = "requires TEST_EMPTY_DATABASE_URL pointing at a separate disposable PostgreSQL database without identity migrations"]
async fn live_process_without_schema_is_not_ready() {
    let mut config = Config::from_env().unwrap();
    config.database_url =
        std::env::var("TEST_EMPTY_DATABASE_URL").expect("separate empty database required");
    let state = AppState::connect(config).await.unwrap();
    let router = create_router(state);
    let live = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    let ready = router
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
}
