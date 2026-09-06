<?php
/**
 * Documentation for every check, keyed by the identifier used in the registry.
 *
 * Keying by identifier instead of by translated title is what keeps a check and
 * its description from drifting apart.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$cascr_what = '<p><strong>' . esc_html__( 'What it checks', 'security-check-report' ) . ':</strong> ';
$cascr_why  = '</p><p><strong>' . esc_html__( 'Why it matters', 'security-check-report' ) . ':</strong> ';
$cascr_fix  = '</p><p><strong>' . esc_html__( 'What to do', 'security-check-report' ) . ':</strong> ';
$cascr_end  = '</p>';

/**
 * Assembles one documentation entry.
 *
 * @param string $what What the check looks at.
 * @param string $why  Why the finding matters.
 * @param string $fix  What to do about it.
 * @return string
 */
$cascr_doc = function ( $what, $why, $fix ) use ( $cascr_what, $cascr_why, $cascr_fix, $cascr_end ) {
	return $cascr_what . $what . $cascr_why . $why . $cascr_fix . $fix . $cascr_end;
};

return array(

	// Core, plugins and themes.

	'wordpress_version'              => $cascr_doc(
		__( 'Whether the installed WordPress release is the current one.', 'security-check-report' ),
		__( 'Security releases are published together with a description of what they fix, which tells everyone exactly what to try against sites that have not updated yet.', 'security-check-report' ),
		__( 'Install the update. Leave automatic minor updates switched on so security releases arrive without anyone having to notice them.', 'security-check-report' )
	),
	'php_version'                    => $cascr_doc(
		__( 'Whether the PHP branch this site runs on still receives security fixes, measured against the published end-of-life dates.', 'security-check-report' ),
		__( 'Once a branch is retired, flaws found in it are never fixed. The site keeps working, which is exactly why this goes unnoticed for years.', 'security-check-report' ),
		__( 'Ask the host to move the site to a supported branch. Test on a staging copy first: a PHP jump is the one upgrade that reliably breaks old plugins.', 'security-check-report' )
	),
	'automatic_core_updates'         => $cascr_doc(
		__( 'Whether WordPress installs its own security releases.', 'security-check-report' ),
		__( 'The window between a security release and the first attempts against it is measured in hours. Nobody updates that fast by hand.', 'security-check-report' ),
		__( 'Leave the default in place, or set WP_AUTO_UPDATE_CORE to minor. Setting it to true is fine too and covers more.', 'security-check-report' )
	),
	'core_file_integrity'            => $cascr_doc(
		__( 'Every core file against the checksums WordPress.org publishes for this exact release.', 'security-check-report' ),
		__( 'A modified core file is either a botched update or someone else editing the site. Both are worth knowing about, and the second one is urgent.', 'security-check-report' ),
		__( 'Reinstall WordPress from Dashboard, Updates. If the same files change again afterwards, treat the site as compromised and rebuild it.', 'security-check-report' )
	),
	'unknown_core_files'             => $cascr_doc(
		__( 'Executable files inside wp-admin and wp-includes that are not part of the official release.', 'security-check-report' ),
		__( 'Nothing but WordPress itself belongs in those two directories. A file that is not on the official list was put there by something else.', 'security-check-report' ),
		__( 'Open each file before deleting it. Note that a few hosts do drop their own helper files into these directories.', 'security-check-report' )
	),
	'outdated_plugins'               => $cascr_doc(
		__( 'Whether any active plugin has an update waiting, using the update information WordPress already holds.', 'security-check-report' ),
		__( 'Nine out of ten new vulnerabilities in the WordPress ecosystem are in plugins, and the fix is usually a version bump that was published weeks ago.', 'security-check-report' ),
		__( 'Install the updates. Turn on automatic updates for the plugins you have no reason to hold back.', 'security-check-report' )
	),
	'outdated_themes'                => $cascr_doc(
		__( 'Whether any installed theme has an update waiting.', 'security-check-report' ),
		__( 'Themes get less attention than plugins, but they ship the same kind of code and are reachable on every page load.', 'security-check-report' ),
		__( 'Install the updates and delete themes the site does not use.', 'security-check-report' )
	),
	'plugin_hygiene'                 => $cascr_doc(
		__( 'Plugins that are installed but not active, and themes that are neither the active theme nor its parent.', 'security-check-report' ),
		__( 'Deactivated code still sits on disk and is still reachable by direct request in some setups. It also stops being updated the moment people forget about it.', 'security-check-report' ),
		__( 'Delete what the site does not use. Keeping one spare default theme for troubleshooting is reasonable.', 'security-check-report' )
	),
	'plugin_abandonment'             => $cascr_doc(
		__( 'How long ago each active plugin was last released, and which WordPress version its author last tested against.', 'security-check-report' ),
		__( 'An abandoned plugin has no one left to publish a fix. The code keeps working right up until the day someone finds a hole in it.', 'security-check-report' ),
		__( 'Look for a maintained alternative before it becomes urgent. File dates on disk say nothing about this, which is why the directory is asked instead.', 'security-check-report' )
	),
	'plugin_removed_from_repo'       => $cascr_doc(
		__( 'Whether any active plugin has had its listing closed in the WordPress plugin directory.', 'security-check-report' ),
		__( 'A listing is usually closed because of an unfixed security problem. That makes it more serious than a plugin with a known, patched vulnerability, not less.', 'security-check-report' ),
		__( 'Remove the plugin and replace it. Updates will never arrive for it again.', 'security-check-report' )
	),
	'plugin_ownership_change'        => $cascr_doc(
		__( 'Whether the author line of an installed plugin changed since the first scan.', 'security-check-report' ),
		__( 'Buying an established plugin and shipping a malicious update to its existing users has become a common route in. The author line is the earliest thing a site can notice on its own.', 'security-check-report' ),
		__( 'Confirm the handover is genuine and read the changelog of the release that came with it. Most changes are legitimate.', 'security-check-report' )
	),
	'mu_plugins_and_dropins'         => $cascr_doc(
		__( 'Must-use plugins and drop-in files such as object-cache.php, advanced-cache.php and db.php, compared against what was there at the first scan.', 'security-check-report' ),
		__( 'Both load on every single request and neither can be switched off from the dashboard. That combination makes them a favourite hiding place for code that is meant to stay.', 'security-check-report' ),
		__( 'Open anything that appeared without you installing it. Managed hosts legitimately place their own caching drop-ins here.', 'security-check-report' )
	),
	'other_wp_installs'              => $cascr_doc(
		__( 'Whether other WordPress installations share the same hosting account.', 'security-check-report' ),
		__( 'On most shared hosting, one compromised site can write into its neighbours. A forgotten test installation next door is a way into this one.', 'security-check-report' ),
		__( 'Keep every installation updated, or delete the ones nobody uses.', 'security-check-report' )
	),

	// Configuration.

	'wp_debug'                       => $cascr_doc(
		__( 'Whether debug output is switched on, and whether errors are printed into the page.', 'security-check-report' ),
		__( 'Error output names file paths, database details and plugin internals. It is a free map of the installation for whoever triggers an error on purpose.', 'security-check-report' ),
		__( 'Set WP_DEBUG to false in production and do the debugging on a staging copy.', 'security-check-report' )
	),
	'debug_log_exposure'             => $cascr_doc(
		__( 'Whether a debug log exists and whether the web server hands it out.', 'security-check-report' ),
		__( 'The log accumulates file paths, query fragments and occasionally credentials. A publicly readable one is a slow leak that nobody watches.', 'security-check-report' ),
		__( 'Delete the file and keep the log outside the web root by setting WP_DEBUG_LOG to a path above it.', 'security-check-report' )
	),
	'file_edit'                      => $cascr_doc(
		__( 'Whether the built-in theme and plugin editor is available.', 'security-check-report' ),
		__( 'The editor turns one stolen administrator password into arbitrary code execution, with no upload and no vulnerability required.', 'security-check-report' ),
		__( "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php. Nobody edits production code in a browser textarea anyway.", 'security-check-report' )
	),
	'disallow_file_mods'             => $cascr_doc(
		__( 'Whether plugins and themes can be installed from the dashboard.', 'security-check-report' ),
		__( 'Blocking the editor still leaves the installer. Uploading a zip is the shortest path from a stolen login to running code.', 'security-check-report' ),
		__( "On sites where code is deployed rather than clicked in, add define( 'DISALLOW_FILE_MODS', true ); to wp-config.php. Be aware that it also stops automatic updates, so the deployment has to cover those.", 'security-check-report' )
	),
	'security_keys_salts'            => $cascr_doc(
		__( 'Whether all eight authentication keys and salts are defined, long enough, not placeholders and not repeated.', 'security-check-report' ),
		__( 'These values sign every login cookie and every nonce. Weak or duplicated ones make a stolen cookie easier to forge and harder to invalidate.', 'security-check-report' ),
		__( 'Generate a fresh set at api.wordpress.org/secret-key/1.1/salt/ and paste it over the block in wp-config.php. Everyone is logged out once, which is also how you evict a stolen session.', 'security-check-report' )
	),
	'db_prefix'                      => $cascr_doc(
		__( 'Whether the database still uses the default table prefix.', 'security-check-report' ),
		__( 'A predictable prefix makes blind injection attempts easier, because the attacker does not have to discover the table names first. It is a small hurdle, not a wall.', 'security-check-report' ),
		__( 'Change it during a migration rather than as a standalone step on a live site. Doing it in place breaks serialised option data if done carelessly.', 'security-check-report' )
	),
	'database_user_privileges'       => $cascr_doc(
		__( 'Whether the database account WordPress uses holds rights beyond its own database.', 'security-check-report' ),
		__( 'Full rights on the site database are normal. Full rights on every database, or the right to hand out rights, means one injection reaches past this site.', 'security-check-report' ),
		__( 'Create a dedicated account limited to this database and update wp-config.php.', 'security-check-report' )
	),
	'wp_cron_health'                 => $cascr_doc(
		__( 'Whether scheduled events actually run, and whether anything is scheduled that no code listens to.', 'security-check-report' ),
		__( 'Update checks, backups and scans all live in the scheduler. A stalled scheduler is silent: everything looks fine and nothing happens. Schedules with no code behind them are usually leftovers from a removed plugin, occasionally something that was planted.', 'security-check-report' ),
		__( 'If DISABLE_WP_CRON is set, make sure a server cron job triggers wp-cron.php. Otherwise remove the constant.', 'security-check-report' )
	),
	'autoload_options_size'          => $cascr_doc(
		__( 'How much option data WordPress loads on every single request.', 'security-check-report' ),
		__( 'This is usually a performance topic, but a bloated autoload set is also where forgotten logs and planted payloads accumulate, because nobody ever looks at it.', 'security-check-report' ),
		__( 'Look at what the largest entries contain before deleting anything. Some plugins legitimately store a lot.', 'security-check-report' )
	),
	'suspicious_options'             => $cascr_doc(
		__( 'Option values that contain code fragments or load scripts from another host, and whether the site and home addresses agree.', 'security-check-report' ),
		__( 'Search engine spam is written into the options table far more often than into files, because it survives a plugin reinstall and never shows up in a file comparison.', 'security-check-report' ),
		__( 'Check each entry before removing it. Analytics and consent tools legitimately store script tags this way.', 'security-check-report' )
	),
	'backup'                         => $cascr_doc(
		__( 'Whether a known backup plugin is active.', 'security-check-report' ),
		__( 'Every other check on this page is about avoiding a bad day. A backup is what turns a bad day into an afternoon.', 'security-check-report' ),
		__( 'A backup taken by the host counts just as much. This check can only see plugins, so ignore it if the host handles it.', 'security-check-report' )
	),
	'security_plugins'               => $cascr_doc(
		__( 'Which general security plugins are active. This one is informational and does not affect the grade.', 'security-check-report' ),
		__( 'Having a security plugin installed says nothing about whether it is configured. It is listed here for context, not as a score.', 'security-check-report' ),
		__( 'Nothing to do. If several are active, check that they are not fighting over the same rules.', 'security-check-report' )
	),
	'brute_force'                    => $cascr_doc(
		__( 'Whether anything limits repeated login attempts.', 'security-check-report' ),
		__( 'Without a limit, passwords can be guessed at whatever rate the server will answer. Combined with readable user names, that is the most common way in.', 'security-check-report' ),
		__( 'Install a login limiter, or rate limit wp-login.php and xmlrpc.php at the web server, which is cheaper and harder to bypass.', 'security-check-report' )
	),
	'password_policy'                => $cascr_doc(
		__( 'Whether anything enforces a minimum password strength.', 'security-check-report' ),
		__( 'WordPress warns about a weak password and then accepts it anyway. A warning is not a policy.', 'security-check-report' ),
		__( 'Enforce a minimum strength at least for accounts that can publish or administer.', 'security-check-report' )
	),

	// Files and permissions.

	'wp_config_permissions'          => $cascr_doc(
		__( 'The permission bits on wp-config.php.', 'security-check-report' ),
		__( 'The file holds the database credentials and the authentication keys. On shared hosting, world-readable means readable by every other account on the machine.', 'security-check-report' ),
		__( 'Set it to 640, or 440 if the web server runs as the owning account. Never 777.', 'security-check-report' )
	),
	'uploads_permissions'            => $cascr_doc(
		__( 'Whether the uploads directory is writable by everyone on the server.', 'security-check-report' ),
		__( 'The directory has to be writable by PHP. It does not have to be writable by every other account on the machine, and on shared hosting those are not the same thing.', 'security-check-report' ),
		__( 'Set it to 755, or 750 where the group is right. This check deliberately accepts anything that is not world-writable.', 'security-check-report' )
	),
	'directory_permissions'          => $cascr_doc(
		__( 'Whether wp-content, wp-includes or wp-admin are writable by everyone.', 'security-check-report' ),
		__( 'A world-writable core directory lets any account on the server drop a file that WordPress will then execute.', 'security-check-report' ),
		__( 'Set the directories to 755 or 750.', 'security-check-report' )
	),
	'world_writable_paths'           => $cascr_doc(
		__( 'Files and folders below the web root that carry the world-writable bit.', 'security-check-report' ),
		__( 'Nothing in a WordPress installation needs to be writable by everyone. Where it happens it is nearly always a botched chmod during troubleshooting that was never undone.', 'security-check-report' ),
		__( 'Files 644, directories 755. If something only works at 777, the ownership is wrong and that is the thing to fix.', 'security-check-report' )
	),
	'unallowed_files'                => $cascr_doc(
		__( 'Executable files sitting among the media uploads.', 'security-check-report' ),
		__( 'Media never needs to be executable. A script in this directory is either a leftover or a shell that someone uploaded through a flaw elsewhere.', 'security-check-report' ),
		__( 'Open each file before deleting it, and check the upload date against the server log. A hardening .htaccess in this directory is not a finding and is not reported here.', 'security-check-report' )
	),
	'php_execution'                  => $cascr_doc(
		__( 'Whether the server actually runs a PHP file placed in the uploads directory. A file is written, requested once and deleted again.', 'security-check-report' ),
		__( 'This is what turns a file upload flaw from an annoyance into code execution. It is the single most valuable hardening step on this page.', 'security-check-report' ),
		__( 'Block PHP in the uploads directory in the server configuration, or place an .htaccess there that denies .php files.', 'security-check-report' )
	),
	'exposed_config_files'           => $cascr_doc(
		__( 'Editor leftovers and backup copies around wp-config.php, plus .env and similar files. Existence is checked first, then whether the web server actually serves them.', 'security-check-report' ),
		__( 'A file named wp-config.php.bak is not parsed as PHP, so the server hands out its contents as text, credentials and all. Whether that happens depends on the server, which is why both questions get asked.', 'security-check-report' ),
		__( 'Delete the files. If one was reachable, assume its contents are known: rotate the database password and the authentication keys.', 'security-check-report' )
	),
	'exposed_repo_dirs'              => $cascr_doc(
		__( 'Whether .git, .svn or .hg directories are readable over HTTP.', 'security-check-report' ),
		__( 'A readable .git directory is the entire source history, including files that were committed once and deleted later. Credentials are found this way regularly.', 'security-check-report' ),
		__( 'Block the directory at the web server, and preferably deploy without the repository metadata in the first place.', 'security-check-report' )
	),
	'exposed_db_dumps'               => $cascr_doc(
		__( 'Database dumps and archives in the web root or in wp-content, and whether they can be downloaded.', 'security-check-report' ),
		__( 'A downloadable dump is every password hash, every email address and every private post in one file. It is usually left behind after a migration.', 'security-check-report' ),
		__( 'Delete it. If it was reachable, rotate the database password and the authentication keys, and treat the user data as disclosed.', 'security-check-report' )
	),
	'unwanted_files_root'            => $cascr_doc(
		__( 'Files in the web root that give away version and tooling details.', 'security-check-report' ),
		__( 'None of these is a hole. Together they tell an attacker which WordPress version, which build tooling and which dependencies to look up.', 'security-check-report' ),
		__( 'Deleting them is safe. WordPress recreates readme.html on every core update, so this one comes back.', 'security-check-report' )
	),
	'upgrade_leftovers'              => $cascr_doc(
		__( 'Contents of wp-content/upgrade and upgrade-temp-backup that are more than a day old.', 'security-check-report' ),
		__( 'An interrupted update leaves an unpacked copy of a plugin behind, sometimes the old vulnerable version, and it stays reachable by direct request.', 'security-check-report' ),
		__( 'Delete the contents of both folders. WordPress recreates them when it needs them.', 'security-check-report' )
	),
	'directory_listing'              => $cascr_doc(
		__( 'Whether the server lists the contents of wp-content, the plugin folder, the uploads folder and wp-includes.', 'security-check-report' ),
		__( 'A listing names every installed plugin and its folder structure, which is a ready-made list of things to look up vulnerabilities for.', 'security-check-report' ),
		__( 'Switch off autoindex in the server configuration, or add Options -Indexes to .htaccess.', 'security-check-report' )
	),
	'htaccess'                       => $cascr_doc(
		__( 'Whether an .htaccess file exists, on servers that use one.', 'security-check-report' ),
		__( 'On Apache this file carries the rewrite rules and most hardening directives. Its absence means none of them are in place.', 'security-check-report' ),
		__( 'Save the permalink settings once and WordPress writes a basic file. On nginx there is no .htaccess and this check reports nothing.', 'security-check-report' )
	),

	// Accounts and access.

	'weak_password_users'            => $cascr_doc(
		__( 'Whether any account that can publish or administer uses a password from the common list, or a variation of its own login name. The stored hash is compared, no login is attempted.', 'security-check-report' ),
		__( 'Password guessing is still how most WordPress sites are taken over. One weak administrator password makes every other measure on this page irrelevant.', 'security-check-report' ),
		__( 'Reset those passwords now, then look at what the accounts did recently. Comparing hashes leaves no entry in the login log and triggers no lockout, so this check is safe to run repeatedly.', 'security-check-report' )
	),
	'admin_username'                 => $cascr_doc(
		__( 'Whether an administrator uses a predictable login name such as admin or root.', 'security-check-report' ),
		__( 'Guessing a password needs the name too. A predictable name removes half the problem for the attacker.', 'security-check-report' ),
		__( 'Create a new administrator with a different name, reassign the content, then delete the old account. Renaming in place is not possible from the dashboard.', 'security-check-report' )
	),
	'admin_account_hygiene'          => $cascr_doc(
		__( 'How many accounts hold administrator rights, whether the account with ID 1 is one of them, and which administrators have not signed in for a long time.', 'security-check-report' ),
		__( 'Every administrator account is a separate way in. Dormant ones are the most dangerous, because nobody would notice them being used.', 'security-check-report' ),
		__( 'Give people the lowest role that lets them work, and remove accounts nobody uses. Sign-in times are only known from the moment this plugin was installed, since WordPress keeps no login history of its own.', 'security-check-report' )
	),
	'role_capability_drift'          => $cascr_doc(
		__( 'Whether any role below administrator holds capabilities such as install_plugins, edit_files or manage_options, and whether the role definitions changed since the first scan.', 'security-check-report' ),
		__( 'A subscriber with install_plugins is an administrator with a friendlier label. Compromised plugins add capabilities like this because it survives a password reset.', 'security-check-report' ),
		__( 'Some plugins add capabilities on purpose, for instance shop or membership plugins. Remove anything you cannot account for.', 'security-check-report' )
	),
	'open_registration'              => $cascr_doc(
		__( 'Whether anyone can register, and which role new accounts receive.', 'security-check-report' ),
		__( 'Open registration is fine. Open registration handing out a role that can publish or install is an open door, and it is a setting that gets changed once and forgotten.', 'security-check-report' ),
		__( 'Under Settings, General, set the default role to Subscriber, or switch registration off if the site does not need accounts.', 'security-check-report' )
	),
	'two_factor_coverage'            => $cascr_doc(
		__( 'Whether a second factor is available at all, and which administrators actually have one set up.', 'security-check-report' ),
		__( 'Whether the feature exists matters far less than who uses it. One administrator without a second factor is the account that will be targeted.', 'security-check-report' ),
		__( 'Set it up for the accounts that are missing it, or require it for the administrator role. Coverage can only be read for the more common plugins; for others this check says so rather than guessing.', 'security-check-report' )
	),
	'application_password_inventory' => $cascr_doc(
		__( 'Which application passwords exist for privileged accounts, when they were created, when they were last used and from where.', 'security-check-report' ),
		__( 'Application passwords bypass the second factor by design. That makes a forgotten one the quietest way to keep access to a site, and an unused one from two years ago is worth more attention than the feature being switched on.', 'security-check-report' ),
		__( 'Revoke what is no longer in use, under Users, Profile. Each one is a standing credential.', 'security-check-report' )
	),

	// Network and transport.

	'ssl'                            => $cascr_doc(
		__( 'Whether the site address uses https, whether the dashboard is forced onto it, and whether the http address redirects permanently.', 'security-check-report' ),
		__( 'A site that merely answers on https while still advertising http lets a login travel in the clear whenever someone types the address without the s.', 'security-check-report' ),
		__( "Set the site and home addresses to https, add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php and redirect http with a 301.", 'security-check-report' )
	),
	'tls_certificate'                => $cascr_doc(
		__( 'How long the certificate is still valid and which protocol version the connection negotiates.', 'security-check-report' ),
		__( 'An expired certificate replaces the site with a browser warning. Automatic renewal fails quietly more often than anyone expects.', 'security-check-report' ),
		__( 'Renew it and then check that the renewal job actually ran, rather than assuming it will.', 'security-check-report' )
	),
	'security_headers'               => $cascr_doc(
		__( 'Which of the recommended response headers the site sends. Each missing header counts separately.', 'security-check-report' ),
		__( 'These headers are what limits the damage of a flaw elsewhere. They are cheap to add and nothing else on this page substitutes for them.', 'security-check-report' ),
		__( 'Send them from the web server so static files are covered too. X-Content-Type-Options and Referrer-Policy are safe to add immediately; the cross-origin isolation headers are treated as optional here because they break embeds on ordinary sites.', 'security-check-report' )
	),
	'hsts_quality'                   => $cascr_doc(
		__( 'Not just whether the HSTS header exists, but whether its max-age is long enough and whether it covers subdomains.', 'security-check-report' ),
		__( 'A max-age of a few minutes passes an existence check and protects nobody. The header only does its job when a browser remembers it for months.', 'security-check-report' ),
		__( 'Use max-age=31536000 with includeSubDomains once the whole site is reliably on HTTPS. Add preload only when you are certain, since it is hard to undo.', 'security-check-report' )
	),
	'csp_quality'                    => $cascr_doc(
		__( "Whether a Content Security Policy is enforced, and whether it contains 'unsafe-inline', 'unsafe-eval' or a wildcard source.", 'security-check-report' ),
		__( "A policy that allows 'unsafe-inline' permits exactly what a policy exists to prevent. Report-only mode blocks nothing at all.", 'security-check-report' ),
		__( 'Start with Content-Security-Policy-Report-Only, watch the reports until they are quiet, then send the same policy as the enforcing header. Replace unsafe-inline with a nonce.', 'security-check-report' )
	),
	'cookie_flags'                   => $cascr_doc(
		__( 'The attributes on the cookies the login page sets, in particular Secure and SameSite.', 'security-check-report' ),
		__( 'Without SameSite, a browser sends the session cookie along with requests started by other sites, which is the ingredient a cross-site request forgery needs.', 'security-check-report' ),
		__( 'Set SameSite=Lax on the session cookies at the web server, and Secure on every cookie once the site is on HTTPS. WordPress does not set SameSite by itself.', 'security-check-report' )
	),
	'cors_configuration'             => $cascr_doc(
		__( 'Whether the site tells browsers that any origin may read its responses.', 'security-check-report' ),
		__( 'A wildcard origin combined with credentials lets any website read logged-in responses from this one. It is a rare misconfiguration and a severe one.', 'security-check-report' ),
		__( 'Name the origins that are actually allowed. Never combine the wildcard with Access-Control-Allow-Credentials.', 'security-check-report' )
	),
	'php_version_in_headers'         => $cascr_doc(
		__( 'Whether the response headers name the exact PHP or server version.', 'security-check-report' ),
		__( 'This is not a hole, it is a shortcut. It tells an attacker which known flaws are worth trying before they try anything.', 'security-check-report' ),
		__( 'Set expose_php to Off in php.ini and trim the server token in the web server configuration.', 'security-check-report' )
	),
	'legacy_meta_exposure'           => $cascr_doc(
		__( 'Discovery tags in the front page markup: the generator tag, the Windows Live Writer manifest and the Really Simple Discovery link.', 'security-check-report' ),
		__( 'The generator tag publishes the exact WordPress version. The other two point at interfaces from an era when blogging clients were a thing.', 'security-check-report' ),
		__( 'Remove the corresponding hooks from wp_head. This is fingerprinting rather than a vulnerability, so it is weighted lightly.', 'security-check-report' )
	),
	'xmlrpc'                         => $cascr_doc(
		__( 'Whether the XML-RPC endpoint answers method calls, and whether system.multicall and pingback.ping are among them.', 'security-check-report' ),
		__( 'system.multicall lets one request carry hundreds of password attempts, which walks straight past a limiter that counts requests. pingback.ping lets the site be used to probe other hosts.', 'security-check-report' ),
		__( 'If nothing uses XML-RPC, block xmlrpc.php at the web server. Jetpack and the mobile apps are the usual reasons to keep it.', 'security-check-report' )
	),
	'user_enumeration'               => $cascr_doc(
		__( 'Three ways of reading out login names without being logged in: the ?author=N redirect, the REST users endpoint and the oEmbed endpoint.', 'security-check-report' ),
		__( 'Guessing a password needs a name and a password. Readable names turn that into one unknown instead of two.', 'security-check-report' ),
		__( 'Require authentication on the users endpoint and stop the author redirect. Setting display names that differ from login names helps regardless.', 'security-check-report' )
	),
	'rest_open_routes'               => $cascr_doc(
		__( 'REST routes that accept POST, PUT, PATCH or DELETE without checking permissions first.', 'security-check-report' ),
		__( 'A write route with no permission callback can be called by anyone who knows the URL. This finds the pattern in third-party plugins, not just in the ones people already know about.', 'security-check-report' ),
		__( 'The route belongs to whichever plugin registered it. Report it to the author, and remove the plugin until it is fixed.', 'security-check-report' )
	),
	'proxy_ip_configuration'         => $cascr_doc(
		__( 'Whether forwarded address headers arrive, and whether the request actually came through a proxy.', 'security-check-report' ),
		__( 'If the site sits directly on the internet and a forwarded header arrives anyway, the visitor wrote it. Anything that trusts it for rate limiting or blocking can be walked straight past by changing one header.', 'security-check-report' ),
		__( 'Configure security plugins to read the address from REMOTE_ADDR, or strip these headers at the edge. Behind Cloudflare or a load balancer the opposite is true, and reading the header is correct.', 'security-check-report' )
	),
);
