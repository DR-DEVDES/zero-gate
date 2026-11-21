# ZERO GATE

A lightweight PHP page-protection script with a minimal, dark access screen.

ZERO GATE protects PHP pages using PHP sessions and `password_hash()` /
`password_verify()`. It supports password-only access or multiple named users.

## Requirements

- PHP 8.1 or newer
- A web server configured to execute PHP
- HTTPS recommended for production

## Features

- Password verification with PHP's `PASSWORD_DEFAULT`
- Optional username + password authentication
- PHP session-based authentication
- Configurable inactivity timeout
- Logout and session cleanup
- CSRF token on the login form
- Basic session-level throttling after failed attempts
- Responsive dark login interface
- No database or external PHP dependencies

## Installation

1. Copy `zero-gate.php` into your project.
2. Generate a password hash:

   ```bash
   php -r "echo password_hash('YOUR_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
   ```

3. Configure `$ACCESS_USERS` in `zero-gate.php`.
4. Include `zero-gate.php` at the very top of every protected PHP page.
5. Do not output whitespace, HTML, or a UTF-8 BOM before the include.

### Password-only mode

Keep:

```php
const USE_USERNAME = false;
```

Then add one or more hashes as values:

```php
$ACCESS_USERS = [
    'PASTE_HASH_FOR_PASSWORD_1',
    'PASTE_HASH_FOR_PASSWORD_2',
];
```

### Username + password mode

Set:

```php
const USE_USERNAME = true;
```

Then use usernames as array keys:

```php
$ACCESS_USERS = [
    'admin'  => 'PASTE_ADMIN_PASSWORD_HASH',
    'editor' => 'PASTE_EDITOR_PASSWORD_HASH',
];
```

Each value must be generated with `password_hash()`.

## Protect a page

Place this at the absolute beginning of the PHP file:

```php
<?php
require_once __DIR__ . '/zero-gate.php';
?>
```

If the protected page is in a different directory, adjust the path. See
[`examples/protected.php`](examples/protected.php).

## Configuration

The settings are near the top of `zero-gate.php`:

| Setting | Purpose |
| --- | --- |
| `USE_USERNAME` | `false` for password-only; `true` for username + password |
| `SESSION_TIMEOUT` | Inactivity timeout in minutes; `0` disables it |
| `LOGIN_TITLE` | Heading shown on the login screen |
| `BRAND_NAME` | Brand label shown on the login screen |
| `LOGOUT_URL` | Destination after logout |

## Logout

Add a link on a protected page:

```html
<a href="?logout=1">Logout</a>
```

The current script redirects to the configured `LOGOUT_URL`.

## Security notes

- Never store plain-text passwords in the configuration.
- Never commit real password hashes or credentials to a public repository.
- Use HTTPS in production.
- The included failed-login throttle is session-based. It is not a substitute
  for server-side or IP-based rate limiting.
- For public-facing or sensitive applications, consider persistent rate
  limiting, audit logging, and an independent security review.
- `PASSWORD_DEFAULT` lets PHP choose its current default password-hashing
  algorithm. Verify passwords with `password_verify()`; do not compare hashes
  directly because password hashes use salts.

## Repository contents

```text
zero-gate-project/
├── zero-gate.php
├── examples/
│   └── protected.php
├── .gitignore
├── README.md
├── CHANGELOG.md
└── SECURITY.md
```

## License

MIT License

Copyright (c) 2026 Dominique Ratzmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
