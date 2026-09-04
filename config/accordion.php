<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(

	__( 'WordPress Version', 'security-check-report' )     => __(
		'<p><strong>What it checks:</strong> Whether your WordPress installation is running the latest version.</p>
		<p><strong>Why it matters:</strong> WordPress regularly releases security patches. Outdated versions contain known vulnerabilities that attackers actively exploit.</p>
		<p><strong>Recommendation:</strong> Enable automatic updates or check for updates weekly. Always backup before major updates.</p>',
		'security-check-report'
	),

	__( 'PHP Version Check', 'security-check-report' )     => __(
		'<p><strong>What it checks:</strong> If your server runs a currently supported PHP version.</p>
		<p><strong>Why it matters:</strong> Unsupported PHP versions no longer receive security patches, leaving your site vulnerable to known exploits.</p>
		<p><strong>Recommendation:</strong> Use PHP 8.1 or higher. Coordinate upgrades with your hosting provider to ensure compatibility.</p>',
		'security-check-report'
	),

	__( 'wp-config.php File Permissions', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> File permissions of wp-config.php to prevent unauthorized access.</p>
		<p><strong>Why it matters:</strong> This file contains database credentials and security keys. Incorrect permissions could allow attackers to steal or modify these critical settings.</p>
		<p><strong>Recommendation:</strong> Set permissions to <code>400</code> or <code>440</code> on Linux servers. Never use <code>777</code>.</p>',
		'security-check-report'
	),

	__( 'Uploads Directory Permissions', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Permissions in the uploads directory.</p>
		<p><strong>Why it matters:</strong> Lenient permissions can allow attackers to upload and execute malicious scripts disguised as media files.</p>
		<p><strong>Recommendation:</strong> Use <code>755</code> for directories, <code>644</code> for files. Add a <code>.htaccess</code> to block PHP execution in uploads.</p>',
		'security-check-report'
	),

	__( 'WP_DEBUG Mode', 'security-check-report' )         => __(
		'<p><strong>What it checks:</strong> Whether WP_DEBUG is enabled in production.</p>
		<p><strong>Why it matters:</strong> Debug mode reveals error messages, file paths, and system information that help attackers understand your setup.</p>
		<p><strong>Recommendation:</strong> Set <code>WP_DEBUG</code> to <code>false</code> in production. Use a staging environment for debugging.</p>',
		'security-check-report'
	),

	__( 'Weak Password Users', 'security-check-report' )   => __(
		'<p><strong>What it checks:</strong> User accounts with common, easily guessed passwords.</p>
		<p><strong>Why it matters:</strong> Weak passwords are the primary entry point for brute-force attacks. One compromised account can give full site access.</p>
		<p><strong>Recommendation:</strong> Enforce strong passwords (12+ characters, mixed case, numbers, symbols). Use a password manager.</p>',
		'security-check-report'
	),

	__( 'Strong Password Policies', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether WordPress enforces complex password requirements.</p>
		<p><strong>Why it matters:</strong> Without enforcement, users tend to choose weak, memorable passwords that are easily cracked.</p>
		<p><strong>Recommendation:</strong> Install a password policy plugin that requires minimum length, complexity, and regular password changes.</p>',
		'security-check-report'
	),

	__( 'Two-Factor Authentication', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether 2FA is enabled for user accounts.</p>
		<p><strong>Why it matters:</strong> 2FA adds a second verification step, making stolen passwords useless without the second factor.</p>
		<p><strong>Recommendation:</strong> Enable 2FA for all administrator accounts at minimum. Consider authenticator apps over SMS.</p>',
		'security-check-report'
	),

	__( 'Admin Username', 'security-check-report' )        => __(
		"<p><strong>What it checks:</strong> Whether the default 'admin' username exists.</p>
		<p><strong>Why it matters:</strong> Attackers automatically target 'admin' in brute-force attacks, knowing it's the default username.</p>
		<p><strong>Recommendation:</strong> Create a custom administrator username. Don't display usernames publicly as author names.</p>",
		'security-check-report'
	),

	__( 'Outdated Plugins', 'security-check-report' )      => __(
		'<p><strong>What it checks:</strong> Installed plugins that have available updates.</p>
		<p><strong>Why it matters:</strong> Plugin vulnerabilities are the most common WordPress attack vector. Outdated plugins are actively exploited.</p>
		<p><strong>Recommendation:</strong> Update plugins weekly. Enable auto-updates for trusted plugins. Remove unused plugins entirely.</p>',
		'security-check-report'
	),

	__( 'Deactivated Plugins', 'security-check-report' )   => __(
		"<p><strong>What it checks:</strong> Plugins that are installed but not activated.</p>
		<p><strong>Why it matters:</strong> Deactivated plugins still contain executable code and can be exploited if vulnerabilities exist.</p>
		<p><strong>Recommendation:</strong> Delete any plugins you're not actively using. Keep your installation minimal.</p>",
		'security-check-report'
	),

	__( 'Outdated Themes', 'security-check-report' )       => __(
		'<p><strong>What it checks:</strong> Installed themes that need updates.</p>
		<p><strong>Why it matters:</strong> Theme vulnerabilities can be exploited just like plugin vulnerabilities, even on inactive themes.</p>
		<p><strong>Recommendation:</strong> Keep only your active theme and one default theme. Update regularly.</p>',
		'security-check-report'
	),

	__( '.htaccess File', 'security-check-report' )        => __(
		'<p><strong>What it checks:</strong> Whether .htaccess exists and contains security configurations.</p>
		<p><strong>Why it matters:</strong> A properly configured .htaccess blocks common attack patterns and prevents directory browsing.</p>
		<p><strong>Recommendation:</strong> Add rules to block suspicious requests, disable directory listing, and protect sensitive files.</p>',
		'security-check-report'
	),

	__( 'XML-RPC Interface', 'security-check-report' )     => __(
		'<p><strong>What it checks:</strong> Whether the XML-RPC interface is accessible.</p>
		<p><strong>Why it matters:</strong> XML-RPC is commonly exploited for brute-force amplification attacks and DDoS.</p>
		<p><strong>Recommendation:</strong> Disable XML-RPC unless you need it for Jetpack, mobile apps, or remote publishing.</p>',
		'security-check-report'
	),

	__( 'XML-RPC Methods', 'security-check-report' )       => __(
		'<p><strong>What it checks:</strong> Which XML-RPC methods are enabled.</p>
		<p><strong>Why it matters:</strong> Certain methods allow bulk login attempts or information disclosure.</p>
		<p><strong>Recommendation:</strong> If XML-RPC is needed, selectively disable dangerous methods like <code>system.multicall</code>.</p>',
		'security-check-report'
	),

	__( 'REST API', 'security-check-report' )              => __(
		'<p><strong>What it checks:</strong> Whether the REST API exposes user information publicly.</p>
		<p><strong>Why it matters:</strong> The /wp/v2/users endpoint can reveal usernames to attackers for targeted attacks.</p>
		<p><strong>Recommendation:</strong> Restrict REST API access for unauthenticated users. Block user enumeration endpoints.</p>',
		'security-check-report'
	),

	__( 'File Editing in Admin', 'security-check-report' ) => __(
		"<p><strong>What it checks:</strong> Whether theme/plugin file editing is enabled in the dashboard.</p>
		<p><strong>Why it matters:</strong> A compromised admin account can inject malicious code directly into theme or plugin files.</p>
		<p><strong>Recommendation:</strong> Add <code>define('DISALLOW_FILE_EDIT', true);</code> to wp-config.php.</p>",
		'security-check-report'
	),

	__( 'Directory Indexing', 'security-check-report' )    => __(
		'<p><strong>What it checks:</strong> Whether directory listing is disabled.</p>
		<p><strong>Why it matters:</strong> Enabled directory listing exposes file structures and can reveal sensitive files to attackers.</p>
		<p><strong>Recommendation:</strong> Add <code>Options -Indexes</code> to your .htaccess file.</p>',
		'security-check-report'
	),

	__( 'SSL Enabled', 'security-check-report' )           => __(
		"<p><strong>What it checks:</strong> Whether your site uses HTTPS.</p>
		<p><strong>Why it matters:</strong> Without SSL, login credentials and sensitive data are transmitted in plain text. Browsers mark non-HTTPS sites as insecure.</p>
		<p><strong>Recommendation:</strong> Install an SSL certificate (Let's Encrypt is free). Force HTTPS for all traffic.</p>",
		'security-check-report'
	),

	__( 'Other WordPress Installations', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Additional WordPress installations in nearby directories.</p>
		<p><strong>Why it matters:</strong> Each WordPress installation is a potential entry point. A compromised test site can lead to compromising your main site.</p>
		<p><strong>Recommendation:</strong> Remove unused installations. Isolate staging sites on separate hosting accounts.</p>',
		'security-check-report'
	),

	__( 'Unallowed Files in Uploads Directory', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Suspicious or executable files in the uploads folder.</p>
		<p><strong>Why it matters:</strong> Attackers often hide backdoor scripts in the uploads directory disguised as legitimate files.</p>
		<p><strong>Recommendation:</strong> Restrict allowed upload types. Scan uploads regularly. Block PHP execution in uploads via .htaccess.</p>',
		'security-check-report'
	),

	__( 'Regular Backups', 'security-check-report' )       => __(
		'<p><strong>What it checks:</strong> Whether backup plugins are installed and active.</p>
		<p><strong>Why it matters:</strong> Backups are your recovery plan after a hack. Without them, you may lose everything.</p>
		<p><strong>Recommendation:</strong> Automate daily backups. Store copies off-site (cloud storage). Test restoration periodically.</p>',
		'security-check-report'
	),

	__( 'Security Plugins Installed', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether security-focused plugins are active.</p>
		<p><strong>Why it matters:</strong> Security plugins provide firewall protection, malware scanning, and real-time threat alerts.</p>
		<p><strong>Recommendation:</strong> Install at least one reputable security plugin (Wordfence, Sucuri, iThemes Security). Keep it updated.</p>',
		'security-check-report'
	),

	__( 'Database Prefix', 'security-check-report' )       => __(
		"<p><strong>What it checks:</strong> Whether the default 'wp_' database prefix has been changed.</p>
		<p><strong>Why it matters:</strong> Automated SQL injection attacks target the default prefix. A custom prefix adds a layer of obscurity.</p>
		<p><strong>Recommendation:</strong> Use a custom prefix during installation. Changing it later requires careful database migration.</p>",
		'security-check-report'
	),

	__( 'Brute-Force Protection', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether your site defends against repeated login attempts.</p>
		<p><strong>Why it matters:</strong> Without protection, attackers can try unlimited password combinations until they succeed.</p>
		<p><strong>Recommendation:</strong> Install login limiting plugins. Consider CAPTCHA or two-factor authentication.</p>',
		'security-check-report'
	),

	__( 'Login Attempts Limiting', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether failed login attempts trigger lockouts.</p>
		<p><strong>Why it matters:</strong> Rate limiting makes brute-force attacks impractical by slowing down or blocking repeated attempts.</p>
		<p><strong>Recommendation:</strong> Lock accounts after 5 failed attempts. Implement progressive delays for repeated failures.</p>',
		'security-check-report'
	),

	__( 'PHP Execution in Uploads Directory', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether PHP files can be executed from the uploads folder.</p>
		<p><strong>Why it matters:</strong> This is a critical vulnerability. Uploaded backdoor scripts can execute and take over your site.</p>
		<p><strong>Recommendation:</strong> Block PHP execution in uploads: add <code>php_flag engine off</code> to uploads/.htaccess.</p>',
		'security-check-report'
	),

	__( 'Server Headers', 'security-check-report' )        => __(
		'<p><strong>What it checks:</strong> Security-related HTTP headers sent by your server.</p>
		<p><strong>Why it matters:</strong> Headers like Content-Security-Policy, X-Frame-Options, and HSTS protect against XSS, clickjacking, and protocol downgrade attacks.</p>
		<p><strong>Recommendation:</strong> Configure security headers via .htaccess, server config, or a security plugin.</p>',
		'security-check-report'
	),

	__( 'Malware Check', 'security-check-report' )         => __(
		'<p><strong>What it checks:</strong> Core files for known malicious code signatures.</p>
		<p><strong>Why it matters:</strong> Malware can remain hidden while stealing data, sending spam, or creating backdoors for future access.</p>
		<p><strong>Recommendation:</strong> Run regular malware scans. Use a security plugin with real-time monitoring.</p>',
		'security-check-report'
	),

	__( 'Automatic WordPress Core Updates', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether automatic core updates are enabled.</p>
		<p><strong>Why it matters:</strong> Minor updates contain critical security fixes. Delays in applying them leave you vulnerable.</p>
		<p><strong>Recommendation:</strong> Enable automatic updates for minor releases. Test major releases on staging first.</p>',
		'security-check-report'
	),

	__( 'Security Keys and Salts', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether security keys in wp-config.php are properly configured.</p>
		<p><strong>Why it matters:</strong> These keys encrypt cookies and sessions. Weak or default keys make session hijacking easier.</p>
		<p><strong>Recommendation:</strong> Generate new keys using the WordPress.org secret-key service. Regenerate every 6-12 months.</p>',
		'security-check-report'
	),

	__( 'Unwanted Files in Root Directory', 'security-check-report' ) => __(
		"<p><strong>What it checks:</strong> Unnecessary or suspicious files in your WordPress root.</p>
		<p><strong>Why it matters:</strong> Leftover files like readme.html, license.txt, or backup files can reveal version info or sensitive data.</p>
		<p><strong>Recommendation:</strong> Delete installation remnants, backup files, and any files you don't recognize.</p>",
		'security-check-report'
	),

	__( 'Legacy Meta Exposure', 'security-check-report' )  => __(
		'<p><strong>What it checks:</strong> Meta tags that reveal WordPress version and configuration details.</p>
		<p><strong>Why it matters:</strong> Generator tags, RSD links, and Windows Live Writer manifests help attackers fingerprint your site and target known vulnerabilities.</p>
		<p><strong>Recommendation:</strong> Remove unnecessary meta tags using a security plugin or functions.php code.</p>',
		'security-check-report'
	),

	__( 'Server PHP Version in Headers', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Whether your server reveals its PHP version in response headers.</p>
		<p><strong>Why it matters:</strong> Version disclosure helps attackers identify and exploit version-specific vulnerabilities.</p>
		<p><strong>Recommendation:</strong> Disable <code>expose_php</code> in php.ini or remove the X-Powered-By header.</p>',
		'security-check-report'
	),

	__( 'Directory Permissions', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Permissions on critical WordPress directories.</p>
		<p><strong>Why it matters:</strong> Overly permissive settings (like 777) allow anyone to modify or upload malicious files.</p>
		<p><strong>Recommendation:</strong> Use <code>755</code> for directories and <code>644</code> for files. Never use 777.</p>',
		'security-check-report'
	),

	__( 'PHP Version Support', 'security-check-report' )   => __(
		'<p><strong>What it checks:</strong> Whether your PHP version is still officially supported.</p>
		<p><strong>Why it matters:</strong> End-of-life PHP versions receive no security updates, leaving known vulnerabilities unpatched.</p>
		<p><strong>Recommendation:</strong> Check php.net for support dates. Plan upgrades before your version reaches end-of-life.</p>',
		'security-check-report'
	),

	__( 'Database User Privileges', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> The privilege level of your WordPress database user.</p>
		<p><strong>Why it matters:</strong> Excessive privileges (like FILE, GRANT) can be abused if credentials are compromised.</p>
		<p><strong>Recommendation:</strong> WordPress only needs SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP. Remove others.</p>',
		'security-check-report'
	),

	__( 'Database Structure', 'security-check-report' )    => __(
		'<p><strong>What it checks:</strong> Database table engines and integrity.</p>
		<p><strong>Why it matters:</strong> InnoDB provides better data integrity and crash recovery than MyISAM. Proper structure aids recovery after incidents.</p>
		<p><strong>Recommendation:</strong> Convert MyISAM tables to InnoDB. Run regular database optimizations.</p>',
		'security-check-report'
	),

	__( 'Outdated Libraries', 'security-check-report' )    => __(
		'<p><strong>What it checks:</strong> JavaScript libraries like jQuery for outdated versions.</p>
		<p><strong>Why it matters:</strong> Outdated frontend libraries may contain exploitable security flaws like XSS vulnerabilities.</p>
		<p><strong>Recommendation:</strong> Ensure themes and plugins use current library versions. Replace or update problematic plugins.</p>',
		'security-check-report'
	),

	__( 'User Enumeration', 'security-check-report' )      => __(
		'<p><strong>What it checks:</strong> Whether attackers can discover valid usernames through various methods.</p>
		<p><strong>Why it matters:</strong> Known usernames make brute-force attacks faster and enable targeted phishing.</p>
		<p><strong>Recommendation:</strong> Block ?author=N queries, restrict REST API /users endpoint, and disable oEmbed user exposure.</p>',
		'security-check-report'
	),

	__( 'Application Passwords', 'security-check-report' ) => __(
		'<p><strong>What it checks:</strong> Application Passwords configured for user accounts (WordPress 5.6+).</p>
		<p><strong>Why it matters:</strong> While more secure than sharing main passwords, Application Passwords provide API access and should be monitored.</p>
		<p><strong>Recommendation:</strong> Audit Application Passwords regularly. Revoke any that are unused or unrecognized.</p>',
		'security-check-report'
	),

	__( 'WP-Cron Security', 'security-check-report' )      => __(
		"<p><strong>What it checks:</strong> WP-Cron configuration and scheduled task integrity.</p>
		<p><strong>Why it matters:</strong> Malicious cron jobs can maintain backdoor persistence. Default WP-Cron can impact performance.</p>
		<p><strong>Recommendation:</strong> Use a real server cron job. Add <code>define('DISABLE_WP_CRON', true);</code> and configure crontab.</p>",
		'security-check-report'
	),

	__( 'Debug Log Exposure', 'security-check-report' )    => __(
		'<p><strong>What it checks:</strong> Whether debug.log is publicly accessible.</p>
		<p><strong>Why it matters:</strong> Debug logs can contain file paths, database queries, error details, and potentially credentials.</p>
		<p><strong>Recommendation:</strong> Block access to debug.log via .htaccess. Disable WP_DEBUG_LOG in production. Delete old logs.</p>',
		'security-check-report'
	),

	__( 'CORS Configuration', 'security-check-report' )    => __(
		'<p><strong>What it checks:</strong> Cross-Origin Resource Sharing header settings.</p>
		<p><strong>Why it matters:</strong> Wildcard (*) CORS allows any website to make requests to your site, potentially stealing data from authenticated users.</p>
		<p><strong>Recommendation:</strong> Only configure CORS if needed. Specify exact allowed domains instead of using wildcards.</p>',
		'security-check-report'
	),

	__( 'Core File Integrity', 'security-check-report' )   => __(
		'<p><strong>What it checks:</strong> WordPress core files against official checksums from WordPress.org.</p>
		<p><strong>Why it matters:</strong> Modified core files often indicate malware injection or incomplete updates.</p>
		<p><strong>Recommendation:</strong> Reinstall WordPress core via Dashboard > Updates if files are unexpectedly modified. Investigate the cause.</p>',
		'security-check-report'
	),

);
