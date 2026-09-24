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
 * Shared closing sentence for the three permission checks.
 *
 * Every one of them ends in a three digit number, and the people who read this
 * report have a hosting panel rather than a shell. Without this the advice is
 * correct and not executable.
 *
 * @var string
 */
$cascr_chmod = __( 'No shell needed: every hosting panel has a file manager, and every FTP client has a permissions dialog. Look for "Change permissions", "CHMOD" or "File attributes" and enter the number there. The three digits are owner, group and everyone, in that order.', 'security-check-report' );

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
		__( 'Whether the installed WordPress release is the current one, read from the update information WordPress already holds.', 'security-check-report' ),
		__( 'Security releases are published together with a description of what they fix, which tells everyone exactly what to try against sites that have not updated yet.', 'security-check-report' ),
		__( 'Install the update. Leave automatic minor updates switched on so security releases arrive without anyone having to notice them. If the site cannot reach api.wordpress.org, the check says the version could not be determined rather than calling the site current.', 'security-check-report' )
	),
	'php_version'                    => $cascr_doc(
		__( 'Whether the PHP branch this site runs on still receives security fixes, measured against the published end-of-life dates. The last six months before that date and the phase in which a branch only gets security fixes and no more bug fixes are reported separately.', 'security-check-report' ),
		__( 'Once a branch is retired, flaws found in it are never fixed. The site keeps working, which is exactly why this goes unnoticed for years.', 'security-check-report' ),
		__( 'Ask the host to move the site to a supported branch. Test on a staging copy first: a PHP jump is the one upgrade that reliably breaks old plugins. A warning six months ahead of the date is there so the move can be planned rather than rushed.', 'security-check-report' )
	),
	'automatic_core_updates'         => $cascr_doc(
		__( 'Whether WordPress may install its own security releases, across all four switches: the WP_AUTO_UPDATE_CORE constant, AUTOMATIC_UPDATER_DISABLED, the ban on file modifications and the site setting for minor releases. A pre-release channel is reported as well, because it installs unfinished code on a production site.', 'security-check-report' ),
		__( 'The window between a security release and the first attempts against it is measured in hours. Nobody updates that fast by hand.', 'security-check-report' ),
		__( 'Leave the default in place, or set WP_AUTO_UPDATE_CORE to minor. Setting it to true is fine too and covers more. Where DISALLOW_FILE_MODS has to stay, the deployment has to install core updates instead, because that constant stops the updater as well.', 'security-check-report' )
	),
	'core_file_integrity'            => $cascr_doc(
		__( 'Every core file against the checksums WordPress.org publishes for this exact release. A checksum is a short fingerprint of a file: two files with the same fingerprint have the same contents.', 'security-check-report' ),
		__( 'A modified core file is either a botched update or someone else editing the site. Both are worth knowing about, and the second one is urgent.', 'security-check-report' ),
		__( 'Reinstall WordPress from Dashboard, Updates. If the same files change again afterwards, treat the site as compromised and rebuild it. Fingerprints are only published for release builds, so a nightly or a patched build is reported as undetermined rather than as clean.', 'security-check-report' )
	),
	'unknown_core_files'             => $cascr_doc(
		__( 'Executable files inside wp-admin and wp-includes that are not part of the official release.', 'security-check-report' ),
		__( 'Nothing but WordPress itself belongs in those two directories. A file that is not on the official list was put there by something else.', 'security-check-report' ),
		__( 'Open each file before deleting it. Note that a few hosts do drop their own helper files into these directories. On very large installations the scan stops after a set number of files and says so; that result is not an all clear.', 'security-check-report' )
	),
	'outdated_plugins'               => $cascr_doc(
		__( 'Whether any active plugin has an update waiting, using the update information WordPress already holds.', 'security-check-report' ),
		__( 'Nine out of ten new vulnerabilities in the WordPress ecosystem are in plugins, and the fix is usually a version bump that was published weeks ago.', 'security-check-report' ),
		__( 'Install the updates. Turn on automatic updates for the plugins you have no reason to hold back. When WordPress holds no update information at all, this is reported as undetermined instead of as up to date.', 'security-check-report' )
	),
	'outdated_themes'                => $cascr_doc(
		__( 'Whether any installed theme has an update waiting. Inactive themes count too, because the update is what they are missing either way.', 'security-check-report' ),
		__( 'Themes get less attention than plugins and ship the same kind of code. The active theme runs on every page load, and an inactive one still sits on disk where a direct request can reach its files.', 'security-check-report' ),
		__( 'Install the updates under Appearance, Themes, and delete the ones the site does not use. Keep one unmodified default theme so a broken theme can be switched out, and switch automatic updates on for it. A theme bought outside the directory updates only when its licence key is entered, so check that too.', 'security-check-report' )
	),
	'plugin_hygiene'                 => $cascr_doc(
		__( 'Plugins that are installed but not active, and themes that are neither the active theme nor its parent.', 'security-check-report' ),
		__( 'Deactivated code still sits on disk and is still reachable by direct request in some setups. It also stops being updated the moment people forget about it.', 'security-check-report' ),
		__( 'Delete what the site does not use. Keeping one spare default theme for troubleshooting is reasonable.', 'security-check-report' )
	),
	'plugin_abandonment'             => $cascr_doc(
		__( 'How long ago each active plugin was last released, and which WordPress version its author last tested against. Only plugins the WordPress directory knows are asked about; a commercial or in-house plugin is skipped rather than guessed at.', 'security-check-report' ),
		__( 'An abandoned plugin has no one left to publish a fix. The code keeps working right up until the day someone finds a hole in it.', 'security-check-report' ),
		__( 'Look for a maintained alternative before it becomes urgent. File dates on disk say nothing about this, which is why the directory is asked instead.', 'security-check-report' )
	),
	'plugin_removed_from_repo'       => $cascr_doc(
		__( 'Whether any active plugin has had its listing closed in the WordPress plugin directory. Plugins that were never listed there are left out, and a listing the site could not retrieve is reported as undetermined rather than as fine.', 'security-check-report' ),
		__( 'A listing is usually closed because of an unfixed security problem. That makes it more serious than a plugin with a known, patched vulnerability, not less.', 'security-check-report' ),
		__( 'Remove the plugin and replace it. Updates will never arrive for it again.', 'security-check-report' )
	),
	'plugin_ownership_change'        => $cascr_doc(
		__( 'Whether the author line of an installed plugin changed since the first scan. The first run only records the authors, so changes are reported from the second run on.', 'security-check-report' ),
		__( 'Buying an established plugin and shipping a malicious update to its existing users has become a common route in. The author line is the earliest thing a site can notice on its own.', 'security-check-report' ),
		__( 'Confirm the handover is genuine and read the changelog of the release that came with it. Most changes are legitimate.', 'security-check-report' )
	),
	'mu_plugins_and_dropins'         => $cascr_doc(
		__( 'Must-use plugins, which are files in wp-content/mu-plugins that WordPress loads without anyone activating them, and drop-ins such as object-cache.php, advanced-cache.php and db.php, which replace a piece of WordPress itself. Both are compared against what was there at the first scan.', 'security-check-report' ),
		__( 'Both load on every single request and neither can be switched off from the dashboard. That combination makes them a favourite hiding place for code that is meant to stay.', 'security-check-report' ),
		__( 'The first run records what is present and lists it for information. Only something that appears afterwards is reported as a finding, and that is what to open first. Managed hosts legitimately place their own caching drop-ins here.', 'security-check-report' )
	),
	'other_wp_installs'              => $cascr_doc(
		__( 'Whether other WordPress installations sit in the directory above this one, down to two levels.', 'security-check-report' ),
		__( 'On most shared hosting, one compromised site can write into its neighbours. A forgotten test installation next door is a way into this one.', 'security-check-report' ),
		__( 'Keep every installation updated, or delete the ones nobody uses. The check only sees what is next to this installation, not the rest of the hosting account.', 'security-check-report' )
	),

	// Configuration.

	'wp_debug'                       => $cascr_doc(
		__( 'Whether debug output is switched on, and whether errors are printed into the page. SCRIPT_DEBUG and SAVEQUERIES are listed along with it when they are set.', 'security-check-report' ),
		__( 'Error output names file paths, database details and plugin internals. It is a free map of the installation for whoever triggers an error on purpose. Debug mode with the output switched off is the milder case and is reported as such.', 'security-check-report' ),
		__( 'Set WP_DEBUG to false in production and do the debugging on a staging copy. If debug mode has to stay on for a while, at least set WP_DEBUG_DISPLAY to false so nothing reaches the page.', 'security-check-report' )
	),
	'debug_log_exposure'             => $cascr_doc(
		__( 'Whether a debug log exists and whether the web server hands it out. A log at a path of your own choosing is reported as present without the download test, because its address is not known from here.', 'security-check-report' ),
		__( 'The log accumulates file paths, query fragments and occasionally credentials. A publicly readable one is a slow leak that nobody watches.', 'security-check-report' ),
		__( 'Delete the file and keep the log outside the web root by setting WP_DEBUG_LOG to a path above it. A log that exists but is not served is still worth deleting once the problem is solved.', 'security-check-report' )
	),
	'file_edit'                      => $cascr_doc(
		__( 'Whether the built-in theme and plugin editor is available.', 'security-check-report' ),
		__( 'The editor turns one stolen administrator password into arbitrary code execution, with no upload and no vulnerability required. That is the shortest path there is from a stolen login to running code.', 'security-check-report' ),
		__( "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php. Nobody edits production code in a browser textarea anyway. Either constant closes it: DISALLOW_FILE_EDIT does it directly, DISALLOW_FILE_MODS does it as a side effect of blocking installs.", 'security-check-report' )
	),
	'disallow_file_mods'             => $cascr_doc(
		__( 'Whether plugins and themes can be installed from the dashboard.', 'security-check-report' ),
		__( 'Blocking the editor still leaves the installer. Uploading a zip is the other way from a stolen login to running code.', 'security-check-report' ),
		__( "On sites where code is deployed rather than clicked in, add define( 'DISALLOW_FILE_MODS', true ); to wp-config.php. Be aware that it also stops automatic updates and closes the editor, so the deployment has to cover the updates.", 'security-check-report' )
	),
	'security_keys_salts'            => $cascr_doc(
		__( 'Whether all eight authentication keys and salts are defined, long enough, not placeholders and not repeated. They are the random values in wp-config.php that WordPress mixes into everything it signs.', 'security-check-report' ),
		__( 'These values sign every login cookie and every nonce, the one-time token WordPress puts into its forms and links so that another site cannot submit them on your behalf. Weak or duplicated values make a stolen cookie easier to forge and harder to invalidate.', 'security-check-report' ),
		__( 'Generate a fresh set at api.wordpress.org/secret-key/1.1/salt/ and paste it over the block in wp-config.php. Everyone is logged out once, which is also how you evict a stolen session. Nothing records when the keys last changed, so the age reported here is the age of wp-config.php, which any unrelated edit resets.', 'security-check-report' )
	),
	'db_prefix'                      => $cascr_doc(
		__( 'Whether the database still uses the default table prefix wp_. On a network the base prefix is what is looked at, since every subsite adds its own number to it.', 'security-check-report' ),
		__( 'A predictable prefix makes blind injection attempts easier, because the attacker does not have to discover the table names first. It is a small hurdle, not a wall.', 'security-check-report' ),
		__( 'Change it during a migration rather than as a standalone step on a live site. Renaming the tables is not enough: the prefix also appears in the option name wp_user_roles and in the user meta keys wp_capabilities and wp_user_level, and missing those leaves every account without its role.', 'security-check-report' )
	),
	'database_user_privileges'       => $cascr_doc(
		__( 'Whether the database account WordPress uses holds rights beyond its own database. An account that is not allowed to look at its own rights is reported as undetermined.', 'security-check-report' ),
		__( 'Full rights on the site database are normal, including the right to pass those same rights on. Full rights on every database, or the right to hand out rights on every database, means one injection reaches past this site.', 'security-check-report' ),
		__( 'Create a dedicated account limited to this database and update wp-config.php. Most hosting panels have a form for exactly that under the database section.', 'security-check-report' )
	),
	'wp_cron_health'                 => $cascr_doc(
		__( 'Whether scheduled events actually run, and whether anything is scheduled that no code listens to.', 'security-check-report' ),
		__( 'Update checks, backups and scans all live in the scheduler. A stalled scheduler is silent: everything looks fine and nothing happens. Schedules with no code behind them are usually leftovers from a removed plugin, occasionally something that was planted.', 'security-check-report' ),
		__( 'If DISABLE_WP_CRON is set, make sure a server cron job triggers wp-cron.php. Otherwise remove the constant. WordPress has no screen that lists scheduled events, so use wp cron event list or a scheduler plugin to look at them. A hook listed here as having no listener was simply not registered during this request, which happens with plugins that only hook up in the front end.', 'security-check-report' )
	),
	'autoload_options_size'          => $cascr_doc(
		__( 'How much option data WordPress loads on every single request. Options marked to autoload are read before anything else happens, whether the page needs them or not.', 'security-check-report' ),
		__( 'This is usually a performance topic, but a bloated autoload set is also where forgotten logs and planted payloads accumulate, because nobody ever looks at it.', 'security-check-report' ),
		__( 'Look at what the largest entries contain before deleting anything. Some plugins legitimately store a lot. WordPress itself starts warning at roughly 800 KB of autoloaded options, and this check uses the same mark.', 'security-check-report' )
	),
	'suspicious_options'             => $cascr_doc(
		__( 'Option values that contain code fragments, and option values that load a script from another host.', 'security-check-report' ),
		__( 'Search engine spam is written into the options table far more often than into files, because it survives a plugin reinstall and never shows up in a file comparison. A code fragment in an option is the strong signal. A foreign script tag is the weak one, since analytics and consent tools store theirs the same way.', 'security-check-report' ),
		__( 'Trace a code fragment back to the plugin that wrote it before deleting anything. For script tags, go through the list once and check that every host is one you chose.', 'security-check-report' )
	),
	'backup'                         => $cascr_doc(
		__( 'Whether a known backup plugin is active. Only plugins are visible from here, not what the host does behind the scenes.', 'security-check-report' ),
		__( 'Every other check on this page is about avoiding a bad day. A backup is what turns a bad day into an afternoon.', 'security-check-report' ),
		__( 'A backup needs three things to count: it holds the database as well as the files, it is stored somewhere the site itself cannot write to, and it has been restored at least once so you know it works. A backup taken by the host counts just as much, and so does one from a plugin this check does not know. If the backup lives outside WordPress, mute this check so it stops asking.', 'security-check-report' )
	),
	'security_plugins'               => $cascr_doc(
		__( 'Which general security plugins are active. This one is informational and does not affect the grade.', 'security-check-report' ),
		__( 'Having a security plugin installed says nothing about whether it is configured. It is listed here for context, not as a score.', 'security-check-report' ),
		__( 'Nothing to do. If several are active, check that they are not fighting over the same rules.', 'security-check-report' )
	),
	'brute_force'                    => $cascr_doc(
		__( 'Whether anything limits repeated login attempts.', 'security-check-report' ),
		__( 'Without a limit, passwords can be guessed at whatever rate the server will answer. Combined with readable user names, that is the most common way in.', 'security-check-report' ),
		__( 'Install a login limiter, or rate limit wp-login.php and xmlrpc.php at the web server, which is cheaper and harder to bypass. This check only sees plugins, so if the limit already sits in the server or in front of the site, mute it.', 'security-check-report' )
	),
	'password_policy'                => $cascr_doc(
		__( 'Whether a plugin enforces a minimum password strength when an account sets or changes its password.', 'security-check-report' ),
		__( 'WordPress warns about a weak password, asks for a confirming tick and then accepts it anyway. A warning is not a policy, and the accounts that pick a weak password are rarely the ones reading the warning.', 'security-check-report' ),
		__( 'Enforce a minimum strength at least for accounts that can publish or administer. A password manager and a long passphrase beat any complexity rule, so aim for length rather than for symbols. This check only sees plugins, so a rule enforced by a theme, an identity provider or the hosting platform is invisible to it and the finding can be muted.', 'security-check-report' )
	),

	// Files and permissions.

	'wp_config_permissions'          => $cascr_doc(
		__( 'The permission bits on wp-config.php: whether every account on the server may write to it, and whether every account may read it.', 'security-check-report' ),
		__( 'The file holds the database credentials and the authentication keys. On shared hosting, world-readable means readable by every other account on the machine, and a writable wp-config.php means somebody else can add code that runs before WordPress does.', 'security-check-report' ),
		__( 'Take the read right away from everyone else: 640 keeps it readable for the owner and the group, 440 does the same without owner write. Both only work while PHP runs as the owning account or in the owning group, which is the normal setup with suEXEC or a per-account PHP-FPM pool. If the site goes blank after the change, PHP runs as a different account and the group ownership is what needs fixing, not the mode. Never 777.', 'security-check-report' ) . ' ' . $cascr_chmod
	),
	'uploads_permissions'            => $cascr_doc(
		__( 'Whether the uploads directory is writable by everyone on the server.', 'security-check-report' ),
		__( 'The directory has to be writable by PHP. It does not have to be writable by every other account on the machine, and on shared hosting those are not the same thing.', 'security-check-report' ),
		__( 'Set it to 755, or 750 where the group is right. This check deliberately accepts anything that is not world-writable, so 755 is enough to clear it.', 'security-check-report' ) . ' ' . $cascr_chmod
	),
	'directory_permissions'          => $cascr_doc(
		__( 'Whether wp-content, wp-includes or wp-admin are writable by everyone on the server.', 'security-check-report' ),
		__( 'A world-writable core directory lets any account on the server drop a file that WordPress will then execute. On shared hosting that is not a theoretical neighbour, it is every other customer on the same machine.', 'security-check-report' ),
		__( 'Set the directories to 755, or 750 where the group is right. Apply it to the directory itself, not recursively to everything inside, otherwise the files below end up executable too. Where the permissions cannot be read at all the check says so rather than reporting them as fine.', 'security-check-report' ) . ' ' . $cascr_chmod
	),
	'world_writable_paths'           => $cascr_doc(
		__( 'Files and folders one level below the web root, wp-content, the plugin folder and the theme folder that carry the world-writable bit.', 'security-check-report' ),
		__( 'Nothing in a WordPress installation needs to be writable by everyone. Where it happens it is nearly always a botched chmod during troubleshooting that was never undone.', 'security-check-report' ),
		__( 'Set files to 644 and directories to 755. wp-config.php is the exception, it belongs at 640 or 440. If something only works at 777, the ownership is wrong and that is the thing to fix.', 'security-check-report' )
	),
	'unallowed_files'                => $cascr_doc(
		__( 'Executable files sitting among the media uploads, separated by whether the web server would run them. A .php or .cgi file is code this site executes; an installer or a shell script is a download.', 'security-check-report' ),
		__( 'Media never needs to be executable. A script in this directory is either a leftover or a shell that someone uploaded through a flaw elsewhere.', 'security-check-report' ),
		__( 'Open each file before deleting it, and check the upload date against the server log. A hardening .htaccess in this directory is not a finding and is not reported here. Small index.php files that only stop the folder from being listed are read and waved through; when one is reported anyway, the finding names what it does that a placeholder would not, for instance reading request data or calling another file.', 'security-check-report' )
	),
	'php_execution'                  => $cascr_doc(
		__( 'Whether the server actually runs a PHP file placed in the uploads directory. A file is written, requested once and deleted again.', 'security-check-report' ),
		__( 'A server that runs PHP here turns a file upload flaw into code execution. A server that hands the file out as text instead runs nothing, but lets anyone read back what was uploaded, and that is a different fix.', 'security-check-report' ),
		__( 'Deny .php files in the uploads directory. On Apache and LiteSpeed an .htaccess in that directory does it, as long as AllowOverride allows the rule; on nginx and Caddy it belongs in the server configuration. Where the file comes back as text, deny access to it rather than only switching the interpreter off.', 'security-check-report' )
	),
	'exposed_config_files'           => $cascr_doc(
		__( 'Editor leftovers and backup copies around wp-config.php, plus .env and similar files. Existence is checked first, then whether the web server actually serves them.', 'security-check-report' ),
		__( 'A file named wp-config.php.bak is not parsed as PHP, so the server hands out its contents as text, credentials and all. Whether that happens depends on the server, which is why both questions get asked.', 'security-check-report' ),
		__( 'Delete the files. If one was reachable, assume its contents are known: rotate the database password and the authentication keys. Two on the list are exceptions: .user.ini is the per-directory PHP configuration of the CGI and FastCGI builds and .htpasswd holds the credentials of a running HTTP authentication. Deny access to those at the server instead of deleting them.', 'security-check-report' )
	),
	'exposed_repo_dirs'              => $cascr_doc(
		__( 'Whether .git, .svn or .hg directories are readable over HTTP. Those are the working folders of a version control system, the tool developers use to keep a history of every change.', 'security-check-report' ),
		__( 'A readable .git directory is the entire source history, including files that were committed once and deleted later. Credentials are found this way regularly.', 'security-check-report' ),
		__( 'Block the directory at the web server, and preferably deploy without the repository metadata in the first place.', 'security-check-report' )
	),
	'exposed_db_dumps'               => $cascr_doc(
		__( 'Database dumps and archives in the web root or in wp-content, and whether they can be downloaded.', 'security-check-report' ),
		__( 'A downloadable dump is every password hash, every email address and every private post in one file. It is usually left behind after a migration.', 'security-check-report' ),
		__( 'Delete it. If it was reachable, rotate the database password and the authentication keys, and treat the user data as disclosed. When the request for the file fails, the check says so instead of calling the file safe.', 'security-check-report' )
	),
	'unwanted_files_root'            => $cascr_doc(
		__( 'Files in the web root that give away version and tooling details.', 'security-check-report' ),
		__( 'Most of them are only information: which WordPress version, which build tooling, which dependencies. phpinfo.php, info.php and test.php are different, they print the full PHP environment including paths and environment variables, and on installations that pass credentials through the environment that means the database password.', 'security-check-report' ),
		__( 'Delete phpinfo.php, info.php and test.php first. The rest can go too, but keep composer.json and package.json if the site is deployed with Composer or npm. WordPress restores readme.html, license.txt and wp-config-sample.php on every core update.', 'security-check-report' )
	),
	'upgrade_leftovers'              => $cascr_doc(
		__( 'Contents of wp-content/upgrade and upgrade-temp-backup that are more than a day old.', 'security-check-report' ),
		__( 'An interrupted update leaves an unpacked copy of a plugin behind, sometimes the old vulnerable version, and it stays reachable by direct request.', 'security-check-report' ),
		__( 'Delete the contents of both folders. WordPress recreates them when it needs them.', 'security-check-report' )
	),
	'directory_listing'              => $cascr_doc(
		__( 'Whether the server lists the contents of wp-content, the plugin folder, the uploads folder, the upgrade folder and wp-includes instead of refusing the request.', 'security-check-report' ),
		__( 'A listing names every installed plugin and its folder structure, which is a ready-made list of things to look up vulnerabilities for.', 'security-check-report' ),
		__( 'Switch off autoindex in the server configuration, or add Options -Indexes to .htaccess.', 'security-check-report' )
	),
	'htaccess'                       => $cascr_doc(
		__( 'Whether an .htaccess file exists, on servers that use one. That file is where Apache takes per-directory rules from.', 'security-check-report' ),
		__( 'On Apache this file carries the rewrite rules and most hardening directives. Its absence means none of them are in place.', 'security-check-report' ),
		__( 'Save the permalink settings once and WordPress writes a basic file. On nginx, Caddy and IIS there is no .htaccess, and this check says so instead of judging: the rules live in the server configuration and cannot be read from here.', 'security-check-report' )
	),

	// Accounts and access.

	'weak_password_users'            => $cascr_doc(
		__( 'Whether any account that can publish or administer uses a password from the common list, or a variation of its own login name. The stored hash is compared, no login is attempted.', 'security-check-report' ),
		__( 'Password guessing is still how most WordPress sites are taken over. One weak administrator password makes every other measure on this page irrelevant.', 'security-check-report' ),
		__( 'Reset those passwords now, then look at what the accounts did recently. Comparing hashes leaves no entry in the login log and triggers no lockout, so this check is safe to run repeatedly. Only accounts that can publish or administer are looked at, and on a site with hundreds of them the check says how many it got through.', 'security-check-report' )
	),
	'admin_username'                 => $cascr_doc(
		__( 'Whether an administrator uses a predictable login name such as admin, administrator, root, test or wordpress.', 'security-check-report' ),
		__( 'Guessing a password needs the name too. A predictable name removes half the problem for the attacker.', 'security-check-report' ),
		__( 'Create a new administrator with a different name, reassign the content, then delete the old account. Renaming in place is not possible from the dashboard.', 'security-check-report' )
	),
	'admin_account_hygiene'          => $cascr_doc(
		__( 'How many accounts hold administrator rights, whether the account with ID 1 is one of them, and which administrators have not signed in for a long time.', 'security-check-report' ),
		__( 'Every administrator account is a separate way in. Dormant ones are the most dangerous, because nobody would notice them being used.', 'security-check-report' ),
		__( 'Give people the lowest role that lets them work, and remove accounts nobody uses. Sign-in times are only known from the moment this plugin was installed, since WordPress keeps no login history of its own.', 'security-check-report' )
	),
	'role_capability_drift'          => $cascr_doc(
		__( 'Whether any role below administrator holds capabilities such as install_plugins, edit_files or manage_options, and whether the role definitions changed since the first scan. A capability is one single permission; a role is a named bundle of them.', 'security-check-report' ),
		__( 'A subscriber with install_plugins is an administrator with a friendlier label. Compromised plugins add capabilities like this because it survives a password reset. A role that merely appeared since the first scan is reported apart from an escalation, because installing a shop or membership plugin does exactly that.', 'security-check-report' ),
		__( 'Some plugins add capabilities on purpose, shop and membership plugins in particular. For anything else: unfiltered_html lets an account save raw HTML and JavaScript into posts, pages and widgets, which is stored cross-site scripting against every visitor and against the next administrator who opens the editor. WordPress has no screen for taking a capability back, so this needs a role editor plugin or one line of code in a plugin, remove_cap on the role. Deactivating the plugin that added it does not undo it, the capability stays in the database. A role that changed for a known reason keeps being reported: the comparison baseline is written once and not updated, so muting the check is the only way to acknowledge it, and it hides the capability findings along with it.', 'security-check-report' )
	),
	'open_registration'              => $cascr_doc(
		__( 'Whether anyone can register, and which role new accounts receive. On a network the registration setting of the network is read, because multisite ignores the per-site one.', 'security-check-report' ),
		__( 'Open registration is fine. Open registration handing out a role that can publish or install is an open door, and it is a setting that gets changed once and forgotten.', 'security-check-report' ),
		__( 'Under Settings, General, set the default role to Subscriber, or switch registration off if the site does not need accounts. On a network the same switch sits under Network Admin, Settings, Registration Settings.', 'security-check-report' )
	),
	'two_factor_coverage'            => $cascr_doc(
		__( 'Whether a second factor is available at all, and which administrators actually have one set up.', 'security-check-report' ),
		__( 'Whether the feature exists matters far less than who uses it. One administrator without a second factor is the account that will be targeted. A plugin that is installed and that nobody finished setting up is the same exposure as having no second factor at all.', 'security-check-report' ),
		__( 'Set it up for the accounts that are missing it, or require it for the administrator role. Two Factor is a widely used free plugin kept up by WordPress contributors and is a solid option. ReportedIP Hive, which we build ourselves, covers TOTP, email and passkeys in its Full Edition; the copy in the plugin directory is Hive Light and brings login protection only. It is named here because it fits, not because you need it. Coverage can only be read for the more common plugins; for others this check says so rather than guessing.', 'security-check-report' )
	),
	'application_password_inventory' => $cascr_doc(
		__( 'Which application passwords exist for privileged accounts, when they were created, when they were last used and from which address, as far as the server sees it. An application password is a separate credential issued to a program rather than to a person.', 'security-check-report' ),
		__( 'Application passwords bypass the second factor by design. That makes a forgotten one the quietest way to keep access to a site, and an unused one from two years ago is worth more attention than the feature being switched on. WordPress records the last use at most once a day, and behind a content delivery network the address is the proxy address, not the caller.', 'security-check-report' ),
		__( 'Revoke what is no longer in use, under Users, Profile. Each one is a standing credential. WordPress only offers application passwords over HTTPS. On a site without it, this check cannot tell a deliberate switch-off from the missing certificate and says so; passwords issued earlier stay in the database and are not listed.', 'security-check-report' )
	),

	// Network and transport.

	'ssl'                            => $cascr_doc(
		__( 'Whether the site address uses https, whether the dashboard is forced onto it, and whether the http address redirects permanently.', 'security-check-report' ),
		__( 'A site that merely answers on https while still advertising http lets a login travel in the clear whenever someone types the address without the s.', 'security-check-report' ),
		__( "Set the site and home addresses to https, add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php and redirect http with a 301.", 'security-check-report' )
	),
	'tls_certificate'                => $cascr_doc(
		__( 'How long the certificate is still valid and which protocol version the connection negotiates. TLS is the encryption behind the s in https. The trust chain and the host name are not verified, so this is a date, not a statement that browsers accept the certificate.', 'security-check-report' ),
		__( 'An expired certificate replaces the site with a browser warning. Automatic renewal fails quietly more often than anyone expects, and the maximum certificate lifetime drops to 100 days in March 2027 and to 47 days in 2029.', 'security-check-report' ),
		__( 'Renew it and then check that the renewal job actually ran, rather than assuming it will. Use a browser or an external test when you want the trust chain checked as well. A connection negotiated over TLS 1.0 or 1.1 is reported too; ask the host to allow 1.2 and 1.3 only.', 'security-check-report' )
	),
	'security_headers'               => $cascr_doc(
		__( 'Which of the recommended response headers the site sends. A response header is a line the server sends along with a page that tells the browser how to treat it. Each missing header counts separately, except that X-Frame-Options is not asked for once the Content Security Policy sets frame-ancestors, which does the same job.', 'security-check-report' ),
		__( 'These headers are what limits the damage of a flaw elsewhere. They are cheap to add and nothing else on this page substitutes for them.', 'security-check-report' ),
		__( 'Send them from the web server so static files are covered too. Working starting values are X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, X-Frame-Options: SAMEORIGIN, Permissions-Policy: geolocation=(), camera=(), microphone=() and Strict-Transport-Security: max-age=31536000; includeSubDomains. The first two match what browsers already do and change nothing on an ordinary site. A Content Security Policy needs to be written for the site and has its own entry. The cross-origin isolation headers are treated as optional here because they break embeds on ordinary sites.', 'security-check-report' )
	),
	'hsts_quality'                   => $cascr_doc(
		__( 'Not just whether the HSTS header exists, but whether its max-age reaches the six months this check asks for and whether it covers subdomains. HSTS is the header that tells a browser to use https for this site from now on, without trying http first.', 'security-check-report' ),
		__( 'A max-age of a few minutes passes an existence check and protects nobody. The header only does its job when a browser remembers it for months.', 'security-check-report' ),
		__( 'Use max-age=31536000 with includeSubDomains once the whole site is reliably on HTTPS, which is one year. Add preload only when you are certain, since it is hard to undo.', 'security-check-report' )
	),
	'csp_quality'                    => $cascr_doc(
		__( "Whether a Content Security Policy is enforced, and whether a directive allows 'unsafe-inline' with no nonce beside it, allows 'unsafe-eval', or opens script loading to every host. A Content Security Policy, CSP for short, is a header that names which scripts a page is allowed to run.", 'security-check-report' ),
		__( "A policy that allows inline scripts with nothing else in the directive permits exactly what a policy exists to prevent. Report-only mode blocks nothing at all. 'unsafe-inline' next to a nonce or 'strict-dynamic' is a different matter: browsers that understand either one ignore it, so the strict policy keeps it as a fallback for older browsers and is not reported here.", 'security-check-report' ),
		__( 'Start with Content-Security-Policy-Report-Only, watch the reports until they are quiet, then send the same policy as the enforcing header. Give the inline scripts a per-request nonce in the script tag, a random value the policy names, instead of allowing them all. That nonce is a different thing from the nonce WordPress puts into its forms.', 'security-check-report' )
	),
	'cookie_flags'                   => $cascr_doc(
		__( 'The attributes on the cookies the login page hands out to a visitor who is not signed in: Secure, HttpOnly and SameSite. The session cookies themselves appear only after a successful sign-in and are out of reach of this check.', 'security-check-report' ),
		__( 'Without SameSite, a browser sends cookies along with requests started by other sites, which is the ingredient a cross-site request forgery needs. Without HttpOnly, any script on the page can read them. A server that drops the attributes on the cookie measured here usually drops them on the session cookies too.', 'security-check-report' ),
		__( 'Set HttpOnly and SameSite=Lax at the web server, and Secure on every cookie once the site is on HTTPS. WordPress sets HttpOnly on its authentication cookies itself but does not set SameSite.', 'security-check-report' )
	),
	'cors_configuration'             => $cascr_doc(
		__( 'Whether the site tells browsers that any origin may read its responses. Cross-origin resource sharing, CORS, is the rule set that decides which other websites may read what this one answers.', 'security-check-report' ),
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
		__( 'Whether the XML-RPC endpoint answers method calls, and whether system.multicall and pingback.ping are among them. XML-RPC is the old remote interface at xmlrpc.php, which desktop and mobile clients used before the REST API existed.', 'security-check-report' ),
		__( 'system.multicall bundles many calls into a single request. Since WordPress 4.4 the first failed login ends the rest of the batch, so it no longer multiplies password guesses, but one request still does the work of many. pingback.ping lets the site be used to probe other hosts.', 'security-check-report' ),
		__( 'If nothing uses XML-RPC, block xmlrpc.php in the web server, which is the only place that stops the requests before WordPress handles them. The xmlrpc_enabled filter, which most security plugins set, only turns away the methods that need a login and leaves the endpoint answering, so this check still reports it. Jetpack and the mobile apps are the usual reasons to keep it.', 'security-check-report' )
	),
	'user_enumeration'               => $cascr_doc(
		__( 'Three ways of reading out accounts without being logged in: the ?author=N parameter, the REST users endpoint and the oEmbed endpoint. Several accounts are probed, not only the first one.', 'security-check-report' ),
		__( 'Guessing a password needs a name and a password. Readable names turn that into one unknown instead of two. With pretty permalinks the ?author redirect hands over the login name itself; without them the author archive still confirms which account IDs exist.', 'security-check-report' ),
		__( 'Require authentication on the users endpoint and stop the author redirect. A different display name changes nothing: the author slug keeps the login name it was generated from, and that is what the redirect and the REST answer carry. Change user_nicename itself if the name must not be public.', 'security-check-report' )
	),
	'rest_open_routes'               => $cascr_doc(
		__( 'REST routes that accept POST, PUT, PATCH or DELETE without a permission check: either with no permission callback at all, or registered as open to everyone. A REST route is an address under /wp-json/ that a plugin registers so that programs can read or change something.', 'security-check-report' ),
		__( 'A route with no permission callback is a mistake WordPress itself complains about since 5.5. A route registered with __return_true is the spelling the handbook prescribes for a route that is meant to be public, so it is listed as a question: a shop cart or a contact form belongs there and authorises inside the callback. The WordPress batch endpoint and the WooCommerce Store API work exactly that way and are left out entirely.', 'security-check-report' ),
		__( 'The route belongs to whichever plugin registered it. Ask the author whether it is meant to be open, and remove the plugin until it is fixed if it is not. If it is meant to be public, mute the finding.', 'security-check-report' )
	),
	'proxy_ip_configuration'         => $cascr_doc(
		__( 'Whether forwarded address headers arrive with the current request, and whether anything can confirm that a proxy in front of the site wrote them.', 'security-check-report' ),
		__( 'Anything that trusts a forwarded header for rate limiting or blocking can be walked past by changing one header, unless a proxy overwrites it. From inside PHP a header written by an edge server and one a visitor sent along look exactly alike, so this check says so rather than guessing: a private REMOTE_ADDR or a Cloudflare edge that identifies itself counts as confirmed, everything else stays undecided.', 'security-check-report' ),
		__( 'If nothing sits in front of the site, have the security plugins read REMOTE_ADDR. If a proxy does, make sure it overwrites these headers rather than passing on whatever arrived. Running the report in the browser rather than on the command line is what gives this check a request to look at.', 'security-check-report' )
	),

	// Transparency and disclosure.

	'ai_content_disclosure'          => $cascr_doc(
		__( 'Whether a plugin that labels AI-generated content and discloses AI systems to visitors is active, and whether its settings have actually been saved. Only local state is read; nothing is sent anywhere.', 'security-check-report' ),
		__( 'Since 2 August 2026, Article 50 of the EU AI Act asks for a machine-readable label on AI-generated text, images, audio and video, and for a notice when a visitor is talking to an AI system. A site that publishes no AI output has nothing to label, and this check cannot tell those sites apart from the rest, which is why it only ever warns and carries a fraction of the usual weight.', 'security-check-report' ),
		__( 'If the site publishes AI-generated content or runs a chatbot, install one of the disclosure plugins from the directory and switch the labelling on. EU AI Label and EU AI Act Ready are free and cover media labels and a visitor notice. TransparAI, which we build ourselves, puts media labels, text marking and chatbot disclosure in one place; it is named here because it fits, not because you need it. An installed plugin whose settings were never saved counts as nothing, so the check reads those settings rather than trusting the folder on disk.', 'security-check-report' )
	),
);
