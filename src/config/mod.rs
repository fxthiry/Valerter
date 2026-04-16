//! Configuration loading and validation for valerter.
//!
//! This module handles loading the YAML configuration file,
//! validation, and managing environment variables for secrets.

mod env;
mod notifiers;
mod runtime;
mod secret;
mod types;
mod validation;

// Re-exports publics
pub use env::{resolve_body_template, resolve_env_vars};
pub use notifiers::{
    EmailNotifierConfig, MattermostNotifierConfig, NotifierConfig, NotifiersConfig, SmtpConfig,
    TelegramNotifierConfig, TlsMode, WebhookNotifierConfig,
};
pub use runtime::{
    CompiledParser, CompiledRule, CompiledTemplate, CompiledThrottle, RuntimeConfig,
};
pub use secret::SecretString;
pub use types::{
    BasicAuthConfig, Config, DEFAULT_CONFIG_PATH, DEFAULT_MAX_STREAMS, DefaultsConfig,
    JsonParserConfig, MetricsConfig, NotifyConfig, ParserConfig, RuleConfig, TemplateConfig,
    ThrottleConfig, TlsConfig, VlSourceConfig,
};
pub use validation::validate_template_render;

#[cfg(test)]
mod tests;
