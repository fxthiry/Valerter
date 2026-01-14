# Email Body Templates

Valerter email notifications use [Jinja2](https://jinja.palletsprojects.com/) templates (via [minijinja](https://github.com/mitsuhiko/minijinja)) to customize the email body content.

## Default Behavior

By default, emails use a built-in template ([default-email.html.j2](default-email.html.j2)) that provides a clean, responsive design with color-coded headers and professional styling.

## Custom Templates

You can provide your own template via:

| Option | Description |
|--------|-------------|
| `body_template` | Inline Jinja2 template string |
| `body_template_file` | Path to template file (relative to config dir or absolute) |

**Priority:** `body_template_file` > `body_template` > default template

## Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `title` | string | Alert title (from message template) |
| `body` | string | Alert body (from message template) |
| `rule_name` | string | Name of the rule that triggered |
| `accent_color` | string \| null | Accent color from template (e.g., `#ff0000`) |

## Jinja2 Syntax

Common patterns:

```jinja2
{# Variable output #}
{{ title }}

{# With default value #}
{{ accent_color | default('#ff0000') }}

{# Filters #}
{{ rule_name | upper }}
{{ title | lower }}

{# Conditionals #}
{% if accent_color %}<span style="color: {{ accent_color }}">●</span>{% endif %}

{# Comments (not rendered) #}
{# This is a comment #}
```

## Examples

### Minimal Config (uses default template)

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

### Custom Template File

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

### Inline Template

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
          <h1 style="color: {{ accent_color | default('#cc0000') }}">{{ title }}</h1>
          <p>{{ body }}</p>
          <hr>
          <small>Rule: {{ rule_name }}</small>
        </body>
      </html>
```

## Writing Templates

### Basic Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }}</title>
</head>
<body>
    <div style="padding: 20px; border-left: 4px solid {{ accent_color | default('#ff0000') }};">
        <h1>{{ title }}</h1>
        <p>{{ body }}</p>
        <small>Rule: <code>{{ rule_name }}</code></small>
    </div>
</body>
</html>
```

### Tips

1. **Use inline CSS** - Many email clients don't support `<style>` blocks well
2. **Use tables for layout** - Flexbox/Grid support is limited in email clients
3. **Test across clients** - Gmail, Outlook, Apple Mail render differently
4. **Keep it simple** - Complex layouts often break

### File Naming

We recommend `.html.j2` extension (e.g., `my-alert.html.j2`), but any extension works.

## Security

**HTML auto-escaping is enabled** - All variables are automatically escaped to prevent XSS attacks from malicious log data.

For example, `<script>alert('xss')</script>` in a log becomes:
```html
&lt;script&gt;alert('xss')&lt;/script&gt;
```
