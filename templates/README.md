# Email body templates

This directory holds the built-in HTML body of the email notifier, [default-email.html.j2](default-email.html.j2). This page covers what is specific to email body templates. For templates in general (rule templates and notifier templates, the variables, the valerter filters, Markdown bodies), see the [template guide](../docs/templates.md). For the email notifier settings, see [Email (SMTP)](../docs/notifiers.md#email-smtp).

An email body template is a notifier template written with [minijinja](https://github.com/mitsuhiko/minijinja), a Jinja2 implementation. The body is sent as HTML (`Content-Type: text/html`).

## Default template

Without `body_template` or `body_template_file`, emails use [default-email.html.j2](default-email.html.j2), embedded in the binary: a responsive layout with the alert title in the header (in the template's `accent_color` when it has one), the body, and a footer with the rule name and the log time. The `.deb` package also installs a copy in `/etc/valerter/templates/`, to start a custom template from.

## Custom templates

| Option | Description |
|--------|-------------|
| `body_template` | Inline template string |
| `body_template_file` | Path to a template file, absolute or relative to the directory of the configuration file (at most 1 MB, UTF-8) |

**Priority:** `body_template_file` > `body_template` > default template. When both are set, valerter logs a warning and uses `body_template_file`.

We recommend the `.html.j2` extension (for example `my-alert.html.j2`), but any extension works.

## Available variables

An email body template sees the notifier template variables, plus `accent_color`. The event fields are under `log` (see [Rule templates and notifier templates](../docs/templates.md#rule-templates-and-notifier-templates)).

| Variable | Type | Description |
|----------|------|-------------|
| `title` | string | Rendered `title` of the rule template |
| `body` | HTML | The body of the alert, already HTML: see [The `body` variable](#the-body-variable) |
| `rule_name` | string | Name of the rule that triggered |
| `vl_source` | string | Name of the VictoriaLogs source the event came from |
| `accent_color` | string or none | `accent_color` of the rule template (for example `#ff0000`), none when it has none |
| `log_timestamp` | string | Original log timestamp in ISO 8601 format (for VictoriaLogs search) |
| `log_timestamp_formatted` | string | Human-readable timestamp (follows the `timestamp_timezone` setting) |
| `log` | object | Every field of the event: `{{ log.host }}`, `{{ log["k8s.pod"] }}` (see [Fields with special characters](../docs/templates.md#fields-with-special-characters)) |

`subject_template` sees the same variables, but it is plain text: it is not HTML-escaped, and its `body` is the plain-text rendering of the body.

### The `body` variable

In the body template, `body` is, by priority:

1. the rendered `email_body_html` of the rule template, when it defines one;
2. otherwise, for a rule template with `body_format: markdown`, the HTML rendering of its Markdown `body`;
3. otherwise, the plain `body` (in practice the fallback message sent when the rule template fails to render), HTML-escaped.

The first two are already HTML and are inserted unescaped: write `{{ body }}` alone, not `<p>{{ body }}</p>` and not `{{ body | safe }}`.

A rule template sent to an email notifier must define `email_body_html`, unless its body is Markdown (`body_format: markdown`): its HTML rendering is then the email body. `--validate` reports a rule template that breaks this rule (see [The `email_body_html` requirement](../docs/templates.md#email-body-html-requirement) and [Markdown bodies](../docs/templates.md#markdown-bodies-body_format)). The `format` key of an email notifier accepts only `html`, its default.

### `accent_color`

`accent_color` is none, not undefined, when the rule template has no accent color. `{{ accent_color | default('#ff0000') }}` would therefore render `None`: pass `true` as the second argument of `default`, which also replaces none and empty values, or test the value like the default template does.

```jinja2
{{ accent_color | default('#ff0000', true) }}

{% if accent_color %}{{ accent_color }}{% else %}#111827{% endif %}
```

## Examples

### Default template

```yaml
notifiers:
  email-ops:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "[{{ rule_name }}] {{ title }}"
```

### Custom template file

```yaml
notifiers:
  email-custom:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "[{{ rule_name | upper }}] {{ title }}"
    body_template_file: "templates/my-alert.html.j2"
```

The file must exist when the configuration is loaded: `--validate` fails otherwise.

### Inline template

```yaml
notifiers:
  email-inline:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "Alert: {{ title }}"
    body_template: |
      <html>
        <body>
          <h1 style="color: {{ accent_color | default('#cc0000', true) }}">{{ title }}</h1>
          {{ body }}
          <hr>
          <small>Rule: {{ rule_name }} (source: {{ vl_source }})</small>
        </body>
      </html>
```

## Writing templates

### Basic structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }}</title>
</head>
<body>
    <div style="padding: 20px; border-left: 4px solid {{ accent_color | default('#ff0000', true) }};">
        <h1>{{ title }}</h1>
        {{ body }}
        <small>
            Rule: <code>{{ rule_name }}</code><br>
            Host: {{ log.host }}<br>
            Log time: {{ log_timestamp_formatted }}
        </small>
    </div>
</body>
</html>
```

### Tips

1. **Use inline CSS** - Many email clients don't support `<style>` blocks well
2. **Use tables for layout** - Flexbox/Grid support is limited in email clients
3. **Test across clients** - Gmail, Outlook, Apple Mail render differently
4. **Keep it simple** - Complex layouts often break

## Security

The body template is rendered with HTML auto-escaping: `title`, `rule_name`, `vl_source`, `accent_color`, the timestamps and every `log` field are escaped, so log data cannot inject markup into the email.

For example, `<script>alert('xss')</script>` in a log field becomes:

```html
&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2f;script&gt;
```

`body` is the exception: when it comes from `email_body_html` or from a Markdown body, it is inserted unescaped, because it is already HTML. The values it contains were escaped when it was rendered: `email_body_html` is itself rendered with HTML auto-escaping, so only the markup written in the rule template stays HTML, and the HTML rendering of a Markdown body escapes all its text, HTML tags written in the Markdown included.
