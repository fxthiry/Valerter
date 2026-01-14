# Email Templates

Valerter email notifications support customizable HTML templates using [Jinja2](https://jinja.palletsprojects.com/) syntax (via [minijinja](https://github.com/mitsuhiko/minijinja)).

## Quick Start

1. Set `body_format: html` in your email notifier config
2. Either use the default template, or provide your own via `body_template` (inline) or `body_template_file` (file path)

## Configuration Options

| Option | Description |
|--------|-------------|
| `body_format` | `text` (default) or `html` |
| `body_template` | Inline Jinja2 template string |
| `body_template_file` | Path to template file (relative to config dir or absolute) |

**Priority:** `body_template_file` > `body_template` > default template

**Note:** `body_template` and `body_template_file` require `body_format: html`. They cannot be used with `body_format: text`.

## Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `title` | string | Alert title (from message template) |
| `body` | string | Alert body (from message template) |
| `rule_name` | string | Name of the rule that triggered |
| `color` | string \| null | Color from template (e.g., `#ff0000`) |
| `icon` | string \| null | Icon from template |

## Jinja2 Syntax

Templates use Jinja2 syntax. Common patterns:

```jinja2
{# Variable output #}
{{ title }}

{# With default value #}
{{ color | default('#ff0000') }}

{# Filters #}
{{ rule_name | upper }}
{{ title | lower }}

{# Conditionals #}
{% if icon %}<span>{{ icon }}</span>{% endif %}

{# Comments (not rendered) #}
{# This is a comment #}
```

## Examples

### Using the Default Template

Simply set `body_format: html` without specifying a template:

```yaml
notifiers:
  email-default:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "[{{ rule_name }}] {{ title }}"
    body_format: html
    # Uses built-in default-email.html.j2 template
```

### Using a Custom Template File

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
    body_format: html
    body_template_file: "templates/my-alert.html.j2"  # Relative to config file
```

### Using an Inline Template

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
    body_format: html
    body_template: |
      <html>
        <body>
          <h1 style="color: {{ color | default('#cc0000') }}">{{ title }}</h1>
          <p>{{ body }}</p>
          <hr>
          <small>Rule: {{ rule_name }}</small>
        </body>
      </html>
```

### Plain Text (No Template)

```yaml
notifiers:
  email-text:
    type: email
    smtp:
      host: smtp.example.com
      port: 587
    from: "valerter@example.com"
    to:
      - "ops@example.com"
    subject_template: "[{{ rule_name }}] {{ title }}"
    body_format: text  # Default - sends alert body as plain text
```

## Creating Custom Templates

### Basic Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }}</title>
    <style>
        /* Inline CSS for email compatibility */
        body { font-family: sans-serif; }
        .alert { padding: 20px; border-left: 4px solid {{ color | default('#ff0000') }}; }
    </style>
</head>
<body>
    <div class="alert">
        {% if icon %}<span class="icon">{{ icon }}</span>{% endif %}
        <h1>{{ title }}</h1>
        <p>{{ body }}</p>
        <footer>
            <small>Rule: <code>{{ rule_name }}</code></small>
        </footer>
    </div>
</body>
</html>
```

### Tips for Email HTML

1. **Use inline CSS** - Many email clients don't support `<style>` blocks well
2. **Use tables for layout** - Flexbox/Grid support is limited in email clients
3. **Test across clients** - Gmail, Outlook, Apple Mail render differently
4. **Keep it simple** - Complex layouts often break

### File Naming Convention

We recommend using `.html.j2` extension for template files:
- `.html` - indicates HTML content
- `.j2` - indicates Jinja2 templating

The extension doesn't affect functionality - Valerter reads the file content regardless of extension.

## Security

**HTML auto-escaping is enabled** - All variables are automatically HTML-escaped to prevent XSS attacks from malicious log data.

For example, if a log contains `<script>alert('xss')</script>`, it will be rendered as:
```html
&lt;script&gt;alert('xss')&lt;/script&gt;
```

## Default Template

The default template (`default-email.html.j2`) provides a clean, responsive design with:
- Color-coded header based on `color` variable
- Icon display (if provided)
- Professional styling
- Valerter branding in footer

See [default-email.html.j2](default-email.html.j2) for the full source.
