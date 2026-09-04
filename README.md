# CMS ADMINS Security Check Report

Performs a comprehensive series of security tests on your WordPress installation and provides an overall risk evaluation with weighted A-F grading.

- WordPress.org: https://wordpress.org/plugins/security-check-report/
- Author: [CMS ADMINS](https://www.cms-admins.de/)

## Features

- 45 security tests across four impact categories (Critical, High, Medium, Low)
- Weighted A-F risk grading
- Real-time progress with live percentage updates
- Searchable test documentation
- Dark mode support, WCAG 2.1 AA accessible
- One-click report export

## Requirements

- WordPress 6.4+
- PHP 8.2+

## Development

```
composer install
composer phplint     # syntax check
composer lint        # PHPCS (WordPress Coding Standards)
composer analyse     # PHPStan
```

Releases are tagged `X.Y.Z` on `main`; a tag push deploys to the WordPress.org plugin directory via GitHub Actions.

## License

GPLv2 or later. See [LICENSE](LICENSE).
