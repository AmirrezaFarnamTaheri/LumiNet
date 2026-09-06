use axum::{routing::post, Router, Json, http::StatusCode};
use axum::extract::State;
use ring::hmac;
use serde_json::Value;

pub struct WebhookState {
    pub hmac_key: hmac::Key,
}

/// Webhook Subscriptions (webhooks.md): Allows dynamic HTTP POST endpoints 
/// to wake up the agent based on payload evaluation (using templated filters and HMAC signatures).
pub fn webhook_router(state: WebhookState) -> Router {
    Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(std::sync::Arc::new(state))
}

async fn handle_webhook(
    State(state): State<std::sync::Arc<WebhookState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Result<StatusCode, StatusCode> {
    let signature = headers.get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let expected_sig = hmac::sign(&state.hmac_key, &payload_bytes);
    let expected_hex = hex::encode(expected_sig.as_ref());
    
    let sig_value = signature.strip_prefix("sha256=").unwrap_or(signature);
    if sig_value != expected_hex {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // Evaluate payload based on templated filters and wake up agent
    if let Some(action) = payload.get("action") {
        if action == "wake_agent" {
            // Wake agent logic
        }
    }
    
    Ok(StatusCode::OK)
}
