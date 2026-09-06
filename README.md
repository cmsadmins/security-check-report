# CMS ADMINS Security Check Report

Read-only security audit for WordPress: 60 checks, a weighted A to F grade, and a short list of what to fix first.

- WordPress.org: https://wordpress.org/plugins/security-check-report/
- Author: [CMS ADMINS](https://www.cms-admins.de/), WordPress maintenance, hosting and security from Munich
- Security services: https://www.cms-admins.de/wordpress-sicherheit/
- Documentation: https://www.cms-admins.de/docs/

## What it does

- 60 checks across core and extensions, configuration, files and permissions, accounts, and network and transport
- Weighted grading where one failing critical check cannot be hidden by passing minor ones
- A priority list of at most five items, derived deterministically from urgency and score
- A comparison with the previous run: newly failing, resolved, changed
- Muting with a content fingerprint, so an accepted finding returns as soon as it changes
- `inconclusive` as a real outcome, so a blocked request never becomes a finding
- Exports as text, JSON and CSV, plus `wp security-check run`

It changes nothing. The only write is a temporary file in the uploads folder for the PHP execution check, removed in the same request.

## Requirements

- WordPress 7.0 or newer
- PHP 7.4 through 8.5

## Architecture

`security-check-report.php` is a bootstrap. Everything else lives in `includes/`:

| File | Responsibility |
|---|---|
| `class-cascr-registry.php` | The single source of truth for a check: id, label, category, severity, weight, callback |
| `class-cascr-result.php` | The four possible outcomes; checks never build the array themselves |
| `class-cascr-scoring.php` | Weighting, grade, deterministic prioritisation |
| `class-cascr-store.php` | Stored runs, diff, muting, drift baselines |
| `class-cascr-http.php` | Cached outbound requests, one fetch per URL per run |
| `class-cascr-runner.php` | Executes a check and applies the filters |
| `class-cascr-rest.php` | REST routes under `cascr/v1` |
| `class-cascr-admin.php` | Menu, assets, markup |
| `class-cascr-cli.php` | `wp security-check run` |
| `checks/class-cascr-checks-*.php` | The checks, grouped by topic |

Documentation lives in `config/docs.php`, keyed by the same identifier as the registry. A test enforces that both sides match.

### Adding a check

1. Add a method to the matching `CASCR_Checks_*` class that returns a `CASCR_Result`.
2. Register it in `CASCR_Registry`.
3. Add its documentation to `config/docs.php` under the same key.
4. Add a behaviour test that sets a state and asserts the verdict.

Third parties can use the `cascr_registry` and `cascr_test_result` filters instead.

## Development

```
composer install
composer phplint     # syntax check
composer lint        # PHPCS, WordPress Coding Standards
composer analyse     # PHPStan level 5
composer test        # PHPUnit
```

The test suite runs against single site and multisite. Multisite resolves registration and administrator rights through network options, so it gets its own CI job:

```
WP_MULTISITE=1 vendor/bin/phpunit
```

CI runs phplint on PHP 7.4 through 8.5, PHPUnit on four combinations, PHPCS, PHPStan and the WordPress.org Plugin Check. All of them block a release.

Releases are tagged `X.Y.Z` on `main`; a tag push deploys to the WordPress.org plugin directory via GitHub Actions.

## License

GPLv2 or later. See [LICENSE](LICENSE).
