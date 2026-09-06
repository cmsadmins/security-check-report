=== CMS ADMINS Security Check Report ===
Contributors: contexlabs
Donate link: https://www.cms-admins.de/
Tags: security, audit, hardening, scanner, site-health
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.3.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only security audit for WordPress: 60 checks, an A to F grade, and a short list of what to fix first.

== Description ==

Security Check Report looks at 60 aspects of a WordPress installation and turns the findings into a graded report. It changes nothing. Every check reads state, and the only thing ever written is one temporary file in the uploads folder that is deleted again in the same request.

The report opens with the five things worth doing first, not with a table of 60 rows. Every finding says what was found, why it matters and what to do about it. From the second run onwards the report also says what changed since the last one, which is usually the part worth reading.

= What you get =

* A weighted grade from A to F, where one failing critical check cannot be hidden by fifty passing minor ones
* A priority list of at most five items, derived from urgency and score rather than from guesswork
* A comparison with the previous run: newly failing, resolved, changed
* Muting that remembers what a finding said, so an accepted finding comes back the moment it actually changes
* "Not determined" as a real outcome, so a blocked request is never reported as a problem and never moves the grade
* Exports as plain text, JSON and CSV
* A WP-CLI command that produces the same grade as the screen
* An explanation of every check, searchable, right on the page

= What it checks =

**Core, plugins and themes.** WordPress version, PHP version against the published end-of-life dates, automatic core updates, core file integrity against the official checksums, files in the core directories that are not part of WordPress, pending plugin and theme updates, unused plugins and themes, plugins that look abandoned, plugins whose listing was closed, plugins whose author changed, must-use plugins and drop-ins, other installations sharing the account.

**Configuration.** Debug mode, debug log exposure, the theme and plugin editor, installing code from the dashboard, authentication keys and salts, table prefix, database user privileges, whether the scheduler actually runs, autoloaded options size, injected content in the options table, backups, login protection, password policy.

**Files and permissions.** Permissions on wp-config.php, the uploads folder and the core directories, world-writable paths, executable files among the media, whether the server runs PHP from the uploads folder, configuration and backup files that the server hands out, readable .git, .svn and .hg folders, database dumps in the web root, leftovers from interrupted updates, directory listing.

**Accounts and access.** Guessable passwords, predictable administrator names, how many accounts hold administrator rights and which have gone dormant, roles below administrator holding capabilities they should not have, open registration and the role it hands out, two-factor coverage per administrator, the application password inventory including when each was last used and from where.

**Network and transport.** HTTPS and the redirect from http, TLS certificate expiry and negotiated protocol, the security headers and their quality rather than their mere presence, cookie attributes, CORS, exposed software versions, legacy discovery tags, XML-RPC, user enumeration, REST routes that accept writes without checking permissions, and whether the client address can be faked through forwarded headers.

= What it is not =

* Not a firewall. It blocks nothing and intercepts no requests.
* Not a malware scanner. It compares core files against the official checksums and looks for injected content in the options table, but it does not hunt for signatures in plugin or theme code, and it removes nothing.
* Not a vulnerability database. It reports that a plugin is outdated, abandoned or delisted; it does not look up individual CVEs.
* Not an auto-fixer. Every finding comes with instructions, and you carry them out.

= Data and connections =

The plugin talks to `api.wordpress.org` and to your own site. Nothing else, and there is no telemetry. See the questions below for exactly which endpoints and what is stored locally.

= Who builds it =

[CMS ADMINS](https://www.cms-admins.de/) maintains, hosts and secures WordPress and Drupal sites from Munich. This plugin is the checklist we run ourselves, packaged up. It is free, it stays free, and it works the same whether or not you ever talk to us.

* [What we do about WordPress security](https://www.cms-admins.de/wordpress-sicherheit/)
* [Documentation and guides](https://www.cms-admins.de/docs/)
* [Source code and issues on GitHub](https://github.com/cmsadmins/security-check-report)

== Installation ==

1. Install the plugin from the WordPress plugin directory, or upload the folder to `/wp-content/plugins/security-check-report`.
2. Activate it on the Plugins screen.
3. Open "Security Check" in the admin menu and start a run.

The plugin needs PHP 7.4 or newer and WordPress 7.0 or newer. Running the checks requires the `manage_options` capability, so on a normal site that means an administrator.

== Frequently Asked Questions ==

= Does the plugin change anything on my site? =

No. Every check reads state and reports on it.

There is one exception, and it is deliberate. To find out whether your server would execute a PHP file dropped into the uploads folder, the plugin has to try. It writes one file with a random name, requests it once over HTTP and deletes it in the same request. A shutdown handler removes the file even if PHP dies in between, and anything left behind by an earlier interrupted run is cleaned up before the next one starts.

= Does it send data anywhere? =

Only to `api.wordpress.org`, and only through the WordPress functions that already talk to it for update checks:

* `https://api.wordpress.org/core/version-check/1.7/` to learn the current WordPress version
* `https://api.wordpress.org/plugins/update-check/1.1/` and `https://api.wordpress.org/themes/update-check/1.1/` for pending updates
* `https://api.wordpress.org/plugins/info/1.2/` to see whether a plugin listing is still open and when it was last released
* `https://api.wordpress.org/core/checksums/1.0/` for the official core file hashes

WordPress.org [privacy policy](https://wordpress.org/about/privacy/) and [terms of service](https://wordpress.org/about/terms-of-service/).

The remaining requests go to your own site, because several checks can only be answered from the outside: whether a file is served, whether a header is sent, whether a directory is listed. There is no telemetry and no reporting back to the plugin author.

= What does the plugin store? =

Four options in your database, all removed when you delete the plugin:

* the last run and the one before it, so the report can show what changed
* which findings you have muted, together with a fingerprint of what they said
* a baseline recorded on the first run, holding plugin authors, role definitions and the list of must-use plugins and drop-ins, so later runs can spot changes

It also records a login timestamp for each account, in user meta, because WordPress keeps no login history of its own and the administrator check would otherwise have nothing to say about dormant accounts. That is deleted on uninstall too.

= Is this a malware scanner or a firewall? =

Neither. It finds configuration weaknesses and exposure, which is what most WordPress sites are actually taken over through. It does not block traffic and it does not clean an infected site.

It will notice several things that point at a compromise: core files that differ from the official release, executable files in the uploads folder, must-use plugins or drop-ins that appeared out of nowhere, roles that gained administrator capabilities, injected scripts in the options table. If any of those turn up, treat it as a starting point for an investigation, not as a verdict.

= What do the grades mean? =

* **A**, excellent: nothing of substance outstanding
* **B**, good: minor improvements available
* **C**, moderate: several things worth addressing
* **D**, poor: significant weaknesses, act soon
* **F**, critical: act now

= How is the grade calculated? =

Every check carries an urgency, and the urgency sets how much a finding weighs:

* **Critical**, weight 3.0: authentication, code execution, exposed secrets
* **High**, weight 2.0: updates, transport security, important configuration
* **Medium**, weight 1.5: headers, permissions, policies
* **Low**, weight 1.0: fingerprinting and good practice

The score is the weighted risk as a percentage of the worst possible outcome. Checks that could not be determined are left out of both sides of that calculation, so a blocked outbound request never moves the grade in either direction. A failing critical check pulls the result down to at least a D, which is what stops one serious problem from being averaged away. A few checks are informational and carry no weight at all.

= Why does a check say "Not determined"? =

Because it could not get an answer, usually a blocked outbound request or a file it is not allowed to read. That is deliberately not treated as a finding. An unreachable endpoint says nothing about your site, and reporting it as a problem would teach you to ignore the report.

= A finding does not apply to my setup. What now? =

Mute it. The plugin hides the finding and stores a fingerprint of what it was reporting. As soon as the content changes, for instance one more affected file, it comes back on its own.

That is the difference between accepting a known state and going blind to it, and it is why muting is offered instead of a permanent dismissal by default.

= How often should I run it? =

Monthly is a reasonable baseline, plus a run after any larger change: a migration, a new plugin, a server move. From the second run onwards the report opens with what changed since the previous one.

= Can I run it from the command line? =

Yes, and it produces the same grade as the screen because the scoring happens in PHP either way.

`wp security-check run` for a table, `wp security-check run --format=json` for the full result, `wp security-check run --failed-only` for just what needs attention.

= Does it work on multisite? =

Yes. It runs per site: anyone with `manage_options` on a site can run it there and sees that site's accounts, plugins, themes and options.

Several things work differently on a network, and the checks account for it. Registration is a network setting, so the sign-up check reads that instead of the per-site option. Network administrators hold every capability regardless of their role on the current site, so the account, password and two-factor checks include them. The table prefix check looks at the base prefix rather than the per-site one.

The checks that look at files, permissions and server configuration necessarily report the same thing on every site in the network, because they describe one installation. There is no network-wide overview screen.

= Can I add my own checks? =

Yes. `cascr_registry` filters the list of checks, so you can add, remove or reweight one. `cascr_test_result` filters an individual result before it is scored. A check is a callable that returns one of the four outcomes built by `CASCR_Result`.

= Which WordPress and PHP versions are supported? =

WordPress 7.0 and newer, PHP 7.4 through 8.5. Every release is tested against WordPress 7.0 and the current version, on single site and on multisite, and linted on all seven PHP branches in between.

= Who is behind this plugin, and where do I report a problem? =

It is built and maintained by [CMS ADMINS](https://www.cms-admins.de/), a Munich agency that has been looking after WordPress and Drupal installations since 2012.

* Bugs and feature requests: [GitHub issues](https://github.com/cmsadmins/security-check-report/issues)
* Questions about a finding: the [WordPress.org support forum](https://wordpress.org/support/plugin/security-check-report/)
* Background reading: our [documentation](https://www.cms-admins.de/docs/) and [what we do about WordPress security](https://www.cms-admins.de/wordpress-sicherheit/)

If a check reports something you believe is wrong, a GitHub issue with the finding text is the fastest way to get it fixed. False positives are treated as bugs.

== Screenshots ==

1. The report: grade, risk score and the five things to do first
2. All checks, grouped by area and filterable by outcome, with one finding expanded
3. The built-in documentation for every check, with a search

== Changelog ==

Releases before 2.2.0 are listed in changelog.txt.

= 2.3.1 =

* The screen is now laid out as three steps: start the check, read the result, go through everything else. Steps two and three say what they will contain before the first run, so the page explains itself.
* The start button says what it does and how long it takes, and the note about the temporary file sits directly above it.
* The result opens with a plain sentence, not just a letter: how many findings need attention now, how many are worth improving, and how many checks could not be completed.
* The page scrolls to the result when a run finishes, instead of leaving it below the fold.
* The priority list is now called what it is, a to-do list, and says to work through it in order.
* A finding can carry a link to further help. The two-factor finding uses it to point at the Two Factor plugin from the WordPress core team and at ReportedIP Hive, which we build ourselves and name as ours.
* Removed three interface strings and two stylesheet rules left behind by the rebuild.

= 2.3.0 =

**Rebuilt**

* One registry is now the single source of truth for a check: identifier, label, grouping, urgency, weight, callback and documentation used to live in four separate places that nothing kept in sync. A test now enforces that they match.
* Grading moved out of the browser and into PHP, which makes the result reproducible, testable and available outside the dashboard.
* The admin-ajax endpoint was replaced by REST routes under `cascr/v1`, running three checks at a time instead of strictly one after another.
* Results are stored, so the report can compare a run with the one before it.

**Added**

* Twenty-five checks, among them publicly readable configuration files and repository folders, database dumps in the web root, must-use plugins and drop-ins, role and capability changes, the application password inventory with last use, two-factor coverage per administrator, unauthenticated REST write routes, TLS certificate expiry, HSTS and CSP quality, cookie attributes, client address spoofing and plugin ownership changes.
* `wp security-check run` as a WP-CLI command.
* A priority list of the five things worth doing first, at the top of the report.
* A comparison with the previous run: newly failing, resolved, changed.
* Muting with a content fingerprint, so an accepted finding reappears as soon as it actually changes.
* "Not determined" as its own outcome, so a blocked request is no longer a finding and no longer affects the grade.
* Exports as plain text, JSON and CSV.
* The filters `cascr_registry` and `cascr_test_result`.

**Fixed**

* Multisite reported "registration is closed" on a network that let anyone sign up, because the check read the per-site option that multisite ignores. It now reads the network setting.
* Network administrators were missing from the password, administrator, two-factor and application password checks. They hold every capability regardless of their role on a site, so a role query alone did not find them.
* The table prefix check compared the per-site prefix on multisite, so every subsite looked like it had a custom one.
* A stored cross-site scripting path: findings carrying site data such as plugin names or user names were written into the summary with innerHTML.
* Permission checks compared against exactly 0755 and therefore reported 0750 and the widespread setgid 2755 as insecure.
* `WP_AUTO_UPDATE_CORE` set to true was reported as a risk, although it enables more updates than the recommended setting.
* "Not modified in six months" was treated as "outdated", which flagged well maintained plugins. Replaced by release date, tested-up-to version and directory status.
* The malware signature scan searched wp-admin and wp-includes for strings such as `eval(` and `$_GET[`, and needed a hand-maintained list of 180 core files to stay quiet. Replaced by a comparison against the official WordPress file list.
* Security headers were all or nothing. They are now scored per header, with the cross-origin isolation headers treated as optional.
* The interface followed the operating system colour scheme and painted dark cards onto the light dashboard. It now follows the WordPress admin.

**Changed**

* One request to the homepage per run instead of four, and one update lookup instead of one request per installed plugin.
* Duplicate checks merged (PHP version support, XML-RPC methods, login attempt limiting) and two dropped that could never fail (jQuery version, table storage engine).
* Every string in the interface is translatable. The report was previously hardcoded English with a German date format.
* Counts in the report use proper plural forms instead of assuming plural.
* The JavaScript alert was replaced by an admin notice and a screen reader announcement.
* The test suite now runs against multisite as well, as a blocking step before every release.

= 2.2.2 =

* Broadened PHP compatibility: the plugin runs on PHP 7.4 through 8.5
* Requires WordPress 7.0 or newer
* Added an automated test suite covering every check and the permission and nonce gates
* Continuous integration lints on seven PHP versions and runs the tests against WordPress 7.0 and the current release
* Fixed a PHP warning in the theme and plugin update checks when a path no longer exists
* Removed unused legacy code paths and reached full WordPress Coding Standards compliance

= 2.2.1 =

* First release on the WordPress.org plugin directory
* Renamed plugin folder, main file and text domain to security-check-report
* Removed the Spamhaus IP blacklist test, which sent the server address to a third party without asking
* Removed unused legacy code and files
* Fixed translation loading on WordPress 6.7 and newer
* Enabled certificate verification for the PHP execution test request

= 2.2.0 =

* Redesigned interface with a native details and summary accordion
* Added a live search across the check documentation
* Rewrote every check description into a consistent format: what it checks, why it matters, what to do
* Unified the colour scheme and fixed several layout issues

== Upgrade Notice ==

= 2.3.1 =
The screen now walks you through three steps and the result is stated in plain language, not just as a letter grade.

= 2.3.0 =
Fixes a cross-site scripting path in the report and several checks that reported healthy sites as insecure. Adds 25 checks, a priority list, a comparison with the previous run and a WP-CLI command.

= 2.2.2 =
Broader PHP support, from 7.4 through 8.5, plus an automated test suite behind every release.

= 2.2.1 =
First release on WordPress.org. The Spamhaus test is gone; nothing is sent anywhere except the WordPress.org API.
