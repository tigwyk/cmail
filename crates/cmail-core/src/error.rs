#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("identity not found: {0} (run: cmail init --name {0})")]
    IdentityNotFound(String),
    #[error("recipient has no identity: {0}")]
    UnknownRecipient(String),
    #[error("invalid name: {0} (allowed: lowercase alphanumerics and hyphens, max 64)")]
    InvalidName(String),
    #[error("invalid envelope: {reason}")]
    InvalidEnvelope { reason: String },
    #[error("message not found: {0}")]
    MessageNotFound(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
