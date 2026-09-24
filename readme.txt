=== CMS ADMINS Security Check Report ===
Contributors: contexlabs
Donate link: https://www.cms-admins.de/
Tags: security, audit, hardening, scanner, site-health
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only security audit for WordPress: 61 checks, an A to F grade, and a checklist that records what you have fixed.

== Description ==

Security Check Report looks at 61 aspects of a WordPress installation and turns the findings into a graded report. It changes nothing. Every check reads state, and the only thing ever written is one temporary file in the uploads folder that is deleted again in the same request.

The report opens with the five things worth doing first, not with a table of 61 rows. Every finding says what was found, why it matters and what to do about it.

From the second run onwards the page no longer opens on the start button but on an overview: the grade, a line saying where the site stood on the first run and where it stands today, one bar per recorded run, five tasks to work through, what is still open, and what has been resolved and when.

Each task has a button that runs that one check again and answers within seconds, so a fix is confirmed while you are still on the screen instead of at the next full pass. A single re-check writes no point into the history, and the page says as much, because a grade pieced together from several passes is not a grade measured in one.

= What you get =

* A weighted grade from A to F, where one failing critical check cannot be hidden by fifty passing minor ones
* A checklist of five tasks at a time, derived from urgency and score rather than from guesswork, with the next one moving up when you finish one
* A button per task that re-runs that single check, so you see the result of a fix in seconds
* A history of the last 24 runs, with the very first one kept for good, so the starting point stays visible
* A comparison with the previous run: newly failing, resolved, changed
* Muting that remembers what a finding said, so an accepted finding comes back the moment it actually changes
* "Not determined" as a real outcome, so a blocked request is never reported as a problem and never moves the grade
* A count on the menu entry, a widget on the dashboard home and a reminder once the last run is more than 30 days old
* Exports as plain text, JSON and CSV
* A WP-CLI command that produces the same grade as the screen
* An explanation of every check, searchable, right on the page

= What it checks =

**Core, plugins and themes.** WordPress version, PHP version against the published end-of-life dates, automatic core updates, core file integrity against the official checksums, files in the core directories that are not part of WordPress, pending plugin and theme updates, unused plugins and themes, plugins that look abandoned, plugins whose listing was closed, plugins whose author changed, must-use plugins and drop-ins, other installations sharing the account.

**Configuration.** Debug mode, debug log exposure, the theme and plugin editor, installing code from the dashboard, authentication keys and salts, table prefix, database user privileges, whether the scheduler actually runs, autoloaded options size, injected content in the options table, backups, login protection, password policy.

**Files and permissions.** Permissions on wp-config.php, the uploads folder and the core directories, world-writable paths, executable files among the media, whether the server runs PHP from the uploads folder, configuration and backup files that the server hands out, readable .git, .svn and .hg folders, database dumps in the web root, leftovers from interrupted updates, directory listing.

**Accounts and access.** Guessable passwords, predictable administrator names, how many accounts hold administrator rights and which have gone dormant, roles below administrator holding capabilities they should not have, open registration and the role it hands out, two-factor coverage per administrator, the application password inventory including when each was last used and from where.

**Network and transport.** HTTPS and the redirect from http, TLS certificate expiry and negotiated protocol, the security headers and their quality rather than their mere presence, cookie attributes, CORS, exposed software versions, legacy discovery tags, XML-RPC, user enumeration, REST routes that accept writes without checking permissions, and whether the client address can be faked through forwarded headers.

**Transparency and disclosure.** Whether AI-generated content carries a machine-readable label and whether visitors are told when they are talking to an AI system, which Article 50 of the EU AI Act has asked for since 2 August 2026. The disclosure plugins in the directory are recognised by their folder and by the settings they write, so a plugin that was installed and never set up is not mistaken for an answer. A site that publishes no AI output has nothing to label, so this one only ever warns and barely moves the grade.

= What it is not =

* Not a firewall. It blocks nothing and intercepts no requests.
* Not a malware scanner. It compares core files against the official checksums and looks for injected content in the options table, but it does not hunt for signatures in plugin or theme code, and it removes nothing.
* Not a vulnerability database. It reports that a plugin is outdated, abandoned or delisted; it does not look up individual CVEs.
* Not an auto-fixer. Every finding comes with instructions, and you carry them out.
* Not a monitor. Nothing runs in the background, nothing is scheduled, no mail is sent. A check runs when you start it.

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

A handful of options in your database, all removed when you delete the plugin:

* the last run and the one before it, so the report can show what changed
* the history of the last 24 runs, each one holding the date, the grade, the risk score and a single character per check, which is what the progress display reads
* which findings you have muted, together with a fingerprint of what they said
* a baseline recorded on the first run, holding plugin authors, role definitions and the list of must-use plugins and drop-ins, so later runs can spot changes
* the number of failing checks from the last run, so the count on the menu entry does not have to load a whole run on every admin page
* the moment you agreed to the run, so you are not asked again on every visit

Two entries go into user meta. One is a login timestamp per account, because WordPress keeps no login history of its own and the administrator check would otherwise have nothing to say about dormant accounts. The other records that somebody switched off the reminder notice, which is a decision per person rather than per site. Both are deleted on uninstall.

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

Monthly is a reasonable baseline, plus a run after any larger change: a migration, a new plugin, a server move. Once the last full run is more than 30 days old, a notice in the dashboard says so. You can switch that notice off for good, and it is the only reminder the plugin sends anywhere.

= What happens when I re-check a single task? =

That one check runs again, its result replaces the old one in the stored run, and the grade is recalculated from what is then stored. It takes a few seconds, so you can fix something and see the result without sitting through 61 checks.

The history is left alone, because one check is not a run. As long as the stored run carries results from more than one pass, the page says how many checks were re-checked on their own and when the last full pass was, so the grade is never presented as something it is not.

= How much history is kept? =

The last 24 runs. When a 25th arrives, the second oldest point is dropped instead of the oldest, so the first run stays and the line about where the site started remains true. One point holds the date, the grade, the risk score and one character per check, which comes to a few kilobytes for the whole history.

If you already used an earlier version, the two runs it had stored become the first two points, so the display is not empty after the update.

= Can I run it from the command line? =

Yes, and it produces the same grade as the screen because the scoring happens in PHP either way.

`wp security-check run` for a table, `wp security-check run --format=json` for the full result, `wp security-check run --failed-only` for just what needs attention.

A command line run reports and stores nothing. The history, the checklist and the count on the menu entry follow the runs you start on the screen.

= Does it work on multisite? =

Yes. It runs per site: anyone with `manage_options` on a site can run it there and sees that site's accounts, plugins, themes and options.

Several things work differently on a network, and the checks account for it. Registration is a network setting, so the sign-up check reads that instead of the per-site option. Network administrators hold every capability regardless of their role on the current site, so the account, password and two-factor checks include them. The table prefix check looks at the base prefix rather than the per-site one.

The checks that look at files, permissions and server configuration necessarily report the same thing on every site in the network, because they describe one installation. There is no network-wide overview screen.

The history, the checklist and the reminder belong to a single site as well. Every site in the network keeps its own.

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

1. The overview from the second run onwards: grade, the way from the first run to today and the next five tasks
2. All checks, grouped by area and filterable by outcome, with one finding expanded
3. The built-in documentation for every check, with a search

== Changelog ==

Releases before 2.2.0 are listed in changelog.txt.

= 2.4.0 =

**Added**

* A checklist instead of a one-off verdict. From the second run onwards the page opens on an overview: the grade, where the site started and where it stands today, a bar for every run, the five things to work through, what is still open, and what has been resolved and when. The guided three-step walkthrough stays for the first run.
* Every task carries a button that re-runs that one check and answers within seconds. A fix is confirmed while you are still at the screen, and the next task moves up, instead of waiting for the next full pass.
* A history of the last 24 runs. The very first one is kept for good, so the opening line can always name where the site started. An installation upgrading from an earlier version finds its two stored runs as the first two points.
* Progress per category, so it is visible which part of the site has been dealt with and which has not.
* A sixth area, transparency and disclosure, with one check in it: whether AI-generated content on the site is labelled. Article 50 of the EU AI Act has asked for a machine-readable label and a notice for AI chatbots since 2 August 2026. The disclosure plugins from the directory are recognised by their folder and by the settings they write, and the check only ever warns, because a site with no AI content has nothing to label.
* A count on the menu entry, a widget on the dashboard, and a reminder once the last full run is older than thirty days. The reminder can be switched off for good, per user.

**Changed**

* The report is built on the server now. It used to be assembled in the browser, which meant the overview could not exist before a run had finished, and the same markup would have had to be written twice.
* A single re-check never writes a point into the history, and the page says plainly that the grade then rests partly on older measurements. A partial pass is not a run.
* A run stores what each check reported, so the report can be rebuilt without running everything again.

**Fixed**

* Reading a run stored by an earlier version could raise a PHP warning, because those runs carry neither the recommendation nor the link nor the findings that the new report reads. Both readers now fill in what is missing.

= 2.3.2 =

**Fixed**

* The check for executable files in the uploads directory reported the empty index.php that WordPress and most plugins drop into every upload folder to stop directory listing. Those files are the opposite of a finding, and because the check counts as critical, a single one of them pulled an otherwise healthy site down to grade D. Across twenty sites the grade was identical for that reason alone. The check now reads such a file instead of judging it by name: an index.php passes only when it stays small and reads no request data, includes no other file, calls none of the functions a dropped shell needs and prints nothing of its own. Everything else is still reported, index.php included.
* Every reported file now carries its size and, where an index.php did not pass, the reason it was reported. A guard file runs to a few hundred bytes, so the number alone usually settles what a file is.
* Two-factor coverage could not tell an account that never finished the setup from one it simply could not read, and called both inconclusive. Each supported plugin is now listed together with the user meta it writes, so an installed plugin nobody uses is reported as the exposure it is, naming the accounts without a second factor.
* Two-factor detection now covers ReportedIP Hive, Solid Security, Kadence Security, WP Defender and Google Authenticator. iThemes Security has been renamed twice and ships under three folder names, all of which are recognised.

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

= 2.4.0 =
The report becomes a checklist you can come back to. It keeps a history, shows what you have resolved since your first run, and confirms a fix on the spot instead of at the next full pass.

= 2.3.1 =
The screen now walks you through three steps and the result is stated in plain language, not just as a letter grade.

= 2.3.0 =
Fixes a cross-site scripting path in the report and several checks that reported healthy sites as insecure. Adds 25 checks, a priority list, a comparison with the previous run and a WP-CLI command.

= 2.2.2 =
Broader PHP support, from 7.4 through 8.5, plus an automated test suite behind every release.

= 2.2.1 =
First release on WordPress.org. The Spamhaus test is gone; nothing is sent anywhere except the WordPress.org API.
