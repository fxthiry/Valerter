//! Notifier-level (layer 2) templates: `body_template` (webhook, Telegram,
//! email) and `subject_template` (email).
//!
//! Each template is compiled once, when its notifier is built, in an
//! environment holding valerter's filters; sending an alert only renders it.

use crate::template::filters;
use minijinja::{AutoEscape, Environment, Value};

/// Variables of every layer 2 template context. The email notifier adds
/// `accent_color`.
pub(crate) const CONTEXT_VARIABLES: [&str; 7] = [
    "title",
    "body",
    "rule_name",
    "vl_source",
    "log_timestamp",
    "log_timestamp_formatted",
    "log",
];

/// Name of the single template held by a [`NotifierTemplate`] environment.
const TEMPLATE_NAME: &str = "template";

/// A layer 2 template compiled in its own environment.
pub(crate) struct NotifierTemplate {
    env: Environment<'static>,
}

impl NotifierTemplate {
    /// Compiles `source`, with HTML auto-escaping when `html` is set (email
    /// body). Unknown variables render as empty strings (lenient, the
    /// minijinja default).
    pub(crate) fn compile(source: String, html: bool) -> Result<Self, minijinja::Error> {
        let mut env = Environment::new();
        if html {
            env.set_auto_escape_callback(|_| AutoEscape::Html);
        }
        filters::register(&mut env);
        env.add_template_owned(TEMPLATE_NAME, source)?;
        Ok(Self { env })
    }

    /// Renders the template with `ctx`.
    pub(crate) fn render(&self, ctx: Value) -> Result<String, minijinja::Error> {
        self.env.get_template(TEMPLATE_NAME)?.render(ctx)
    }

    /// Top-level variables read by the template that are neither in `known`
    /// nor globals of the environment (`range`, `dict`, `namespace`…), sorted.
    /// Loop and `set` variables are declared by the template itself.
    pub(crate) fn unknown_variables(&self, known: &[&str]) -> Vec<String> {
        let Ok(template) = self.env.get_template(TEMPLATE_NAME) else {
            return Vec::new();
        };
        let mut unknown: Vec<String> = template
            .undeclared_variables(false)
            .into_iter()
            .filter(|name| !known.contains(&name.as_str()))
            .filter(|name| !self.env.globals().any(|(global, _)| global == name))
            .collect();
        unknown.sort();
        unknown
    }

    /// Logs a warning for each [unknown variable](Self::unknown_variables):
    /// at layer 2 it renders empty, most likely a log field written
    /// `{{ host }}` instead of `{{ log.host }}`. Never an error, so existing
    /// configurations keep loading.
    pub(crate) fn warn_unknown_variables(&self, notifier: &str, field: &str, known: &[&str]) {
        for variable in self.unknown_variables(known) {
            tracing::warn!(
                notifier = %notifier,
                field = %field,
                variable = %variable,
                "Notifier template references unknown variable"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::context;

    fn unknown(source: &str) -> Vec<String> {
        NotifierTemplate::compile(source.to_string(), false)
            .unwrap()
            .unknown_variables(&CONTEXT_VARIABLES)
    }

    #[test]
    fn log_field_read_without_log_is_unknown() {
        assert_eq!(unknown(r#"{"host": {{ host | tojson }}}"#), vec!["host"]);
    }

    #[test]
    fn known_loop_set_and_global_variables_are_not_unknown() {
        let source = "{{ title }} {{ body }} {{ rule_name }} {{ vl_source }} \
            {{ log_timestamp }} {{ log_timestamp_formatted }} {{ log.host }} \
            {% for k, v in log | items %}{{ k }}={{ v }}{{ loop.index }}{% endfor %}\
            {% set n = 3 %}{% for i in range(n) %}{{ i }}{% endfor %}\
            {% set ns = namespace(c=0) %}{{ ns.c }}{{ dict(a=1).a }}";
        assert_eq!(unknown(source), Vec::<String>::new());
    }

    /// Warnings logged on the current thread while `f` runs.
    fn warnings_during(f: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn webhook_body_template_reading_a_field_without_log_warns() {
        let logs = warnings_during(|| {
            let config = crate::config::WebhookNotifierConfig {
                url: crate::config::SecretString::new("https://example.com/hook".to_string()),
                method: "POST".to_string(),
                headers: Default::default(),
                body_template: Some(r#"{"host": {{ host | tojson }}}"#.to_string()),
                format: None,
            };
            crate::notify::WebhookNotifier::from_config("hook", &config, reqwest::Client::new())
                .expect("a warning never fails the notifier");
        });

        assert!(
            logs.contains("Notifier template references unknown variable"),
            "{logs}"
        );
        assert!(logs.contains("notifier=hook"), "{logs}");
        assert!(logs.contains("field=body_template"), "{logs}");
        assert!(logs.contains("variable=host"), "{logs}");
    }

    #[test]
    fn known_variables_log_no_warning() {
        let logs = warnings_during(|| {
            NotifierTemplate::compile("{{ title }} {{ log.host }}".to_string(), false)
                .unwrap()
                .warn_unknown_variables("n", "body_template", &CONTEXT_VARIABLES);
        });
        assert_eq!(logs, "");
    }

    #[test]
    fn render_uses_valerter_filters_and_html_escaping() {
        let tmpl =
            NotifierTemplate::compile("<td>{{ v | md_escape }}</td>".to_string(), true).unwrap();
        assert_eq!(
            tmpl.render(context! { v => "<b>_x" }).unwrap(),
            r"<td>&lt;b\&gt;\_x</td>"
        );
    }

    #[test]
    fn compile_reports_syntax_errors() {
        assert!(NotifierTemplate::compile("{% broken %}".to_string(), false).is_err());
    }
}
