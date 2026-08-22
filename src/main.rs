use axum::{
    Json, Router,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct AnalyzePromptRequest {
    prompt: String,
}

#[derive(Serialize)]
struct AnalyzePromptResponse {
    verdict: &'static str,
    risk_score: u8,
    findings: Vec<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}
fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/analyze-prompt", post(analyze_prompt))
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = app();

    let listener = TcpListener::bind("127.0.0.1:3000").await?;

    println!("Zyguor AI Security Lab running at http://127.0.0.1:3000");

    axum::serve(listener, app).await
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
async fn analyze_prompt(Json(request): Json<AnalyzePromptRequest>) -> Json<AnalyzePromptResponse> {
    let prompt_length = request.prompt.chars().count();

    Json(AnalyzePromptResponse {
        verdict: "not_analyzed",
        risk_score: 0,
        findings: vec![format!(
            "Prompt accepted for analysis: {prompt_length} characters"
        )],
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::app;

    #[tokio::test]
    async fn health_endpoint_returns_success() -> Result<(), Box<dyn std::error::Error>> {
        let request = Request::get("/health").body(Body::empty())?;

        let response = app().oneshot(request).await?;

        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }
}
