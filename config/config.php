<?php
/**
 * Lookup lists used by the checks.
 *
 * Plugin detection is by necessity a list of known paths. It answers "is
 * something taking care of this", never "is it configured well", which is why
 * the checks that use it stay on the cautious side.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(

	/*
	 * Plugins that provide a general security layer. Informational only.
	 */
	'security_plugins'         => array(
		'wordfence/wordfence.php',
		'sucuri-scanner/sucuri.php',
		'better-wp-security/better-wp-security.php',
		'ithemes-security-pro/ithemes-security-pro.php',
		'all-in-one-wp-security-and-firewall/wp-security.php',
		'shield-security/shield-security.php',
		'wp-simple-firewall/wp-simple-firewall.php',
		'malcare-security/malcare.php',
		'wp-cerber/wp-cerber.php',
		'bulletproof-security/bulletproof-security.php',
		'defender-security/wp-defender.php',
		'security-ninja/security-ninja.php',
		'secupress/secupress.php',
		'patchstack/patchstack.php',
		'wpscan/wpscan.php',
		'jetpack-protect/jetpack-protect.php',
		'blackhole-for-bad-bots/blackhole-for-bad-bots.php',
		'cleantalk-spam-protect/cleantalk.php',
	),

	/*
	 * Plugins that slow down or block repeated login attempts.
	 */
	'brute_force_plugins'      => array(
		'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
		'limit-login-attempts/limit-login-attempts.php',
		'wp-limit-login-attempts/wp-limit-login-attempts.php',
		'brute-force-login-protection/brute-force-login-protection.php',
		'login-lockdown/login-lockdown.php',
		'simple-login-lockdown/simple-login-lockdown.php',
		'loginizer/loginizer.php',
		'wordfence/wordfence.php',
		'wordfence-login-security/wordfence-login-security.php',
		'sucuri-scanner/sucuri.php',
		'better-wp-security/better-wp-security.php',
		'ithemes-security-pro/ithemes-security-pro.php',
		'all-in-one-wp-security-and-firewall/wp-security.php',
		'jetpack/jetpack.php',
		'jetpack-protect/jetpack-protect.php',
		'wp-cerber/wp-cerber.php',
		'bulletproof-security/bulletproof-security.php',
		'defender-security/wp-defender.php',
		'shield-security/shield-security.php',
		'wp-simple-firewall/wp-simple-firewall.php',
		'malcare-security/malcare.php',
		'secupress/secupress.php',
		'wp-fail2ban/wp-fail2ban.php',
	),

	/*
	 * Plugins whose main job is protecting the login form itself.
	 */
	'login_protection_plugins' => array(
		'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
		'loginizer/loginizer.php',
		'wps-hide-login/wps-hide-login.php',
		'wp-cerber/wp-cerber.php',
		'captcha-on-login/captcha-on-login.php',
		'google-captcha/google-captcha.php',
		'advanced-nocaptcha-recaptcha/advanced-nocaptcha-recaptcha.php',
		'wordfence/wordfence.php',
		'better-wp-security/better-wp-security.php',
		'all-in-one-wp-security-and-firewall/wp-security.php',
		'shield-security/shield-security.php',
		'wp-simple-firewall/wp-simple-firewall.php',
	),

	/*
	 * Plugins that enforce a minimum password strength.
	 */
	'password_plugins'         => array(
		'force-strong-passwords/force-strong-passwords.php',
		'wp-force-strong-passwords/wp-force-strong-passwords.php',
		'wp-password-policy-manager/wp-password-policy-manager.php',
		'advanced-password-policy-manager/advanced-password-policy-manager.php',
		'password-policy-manager/password-policy-manager.php',
		'require-strong-password/require-strong-password.php',
		'better-wp-security/better-wp-security.php',
		'ithemes-security-pro/ithemes-security-pro.php',
		'wordfence/wordfence.php',
		'shield-security/shield-security.php',
		'wp-simple-firewall/wp-simple-firewall.php',
		'all-in-one-wp-security-and-firewall/wp-security.php',
	),

	/*
	 * Plugins that add a second authentication factor.
	 */
	'two_factor_plugins'       => array(
		'two-factor/two-factor.php',
		'two-factor-provider-webauthn/two-factor-provider-webauthn.php',
		'wp-2fa/wp-2fa.php',
		'wordfence-login-security/wordfence-login-security.php',
		'miniorange-2-factor-authentication/miniorange_2_factor_settings.php',
		'miniOrange-2-factor-authentication/miniorange-2-factor.php',
		'duo-wordpress/duo.php',
		'rublon/rublon.php',
		'keyy-two-factor-authentication/keyy.php',
		'google-authenticator/google-authenticator.php',
		'wp-google-authenticator/wp-google-authenticator.php',
		'two-factor-authentication/two-factor-authentication.php',
		'better-wp-security/better-wp-security.php',
		'ithemes-security-pro/ithemes-security-pro.php',
		'shield-security/shield-security.php',
		'wp-simple-firewall/wp-simple-firewall.php',
		'defender-security/wp-defender.php',
		'jetpack/jetpack.php',
	),

	/*
	 * Plugins that take backups. A backup taken by the host counts too, which
	 * is why a missing entry here is only a warning.
	 */
	'backup_plugins'           => array(
		'updraftplus/updraftplus.php',
		'backwpup/backwpup.php',
		'backwpup-pro/backwpup-pro.php',
		'duplicator/duplicator.php',
		'duplicator-pro/duplicator-pro.php',
		'all-in-one-wp-migration/all-in-one-wp-migration.php',
		'wpvivid-backuprestore/wpvivid-backuprestore.php',
		'backup-backup/backup-backup.php',
		'backupbuddy/backupbuddy.php',
		'wp-time-capsule/wp-time-capsule.php',
		'backup-guard/backup-guard.php',
		'blogvault-real-time-backup/blogvault.php',
		'xcloner-backup-and-restore/xcloner.php',
		'wp-staging/wp-staging.php',
		'wp-staging-pro/wp-staging-pro.php',
		'wp-backitup/wp-backitup.php',
		'vaultpress/vaultpress.php',
		'jetpack-backup/jetpack-backup.php',
		'snapshot-pro/snapshot.php',
	),

	/*
	 * Files that give away version or tooling details. Harmless on their own,
	 * useful to an attacker mapping the installation.
	 */
	'unwanted_files'           => array(
		'readme.html',
		'license.txt',
		'wp-config-sample.php',
		'.DS_Store',
		'Thumbs.db',
		'.editorconfig',
		'.gitignore',
		'.gitattributes',
		'package.json',
		'package-lock.json',
		'yarn.lock',
		'composer.json',
		'composer.lock',
		'npm-debug.log',
		'phpinfo.php',
		'info.php',
		'test.php',
	),

	/*
	 * Files that carry secrets. Checked for existence and then for whether the
	 * web server actually hands them out, because the answer differs between
	 * Apache and nginx.
	 *
	 * The list follows what Wordfence probes for, which is the most complete
	 * public collection of editor and backup leftovers around wp-config.php.
	 */
	'exposed_files'            => array(
		'.env',
		'.env.local',
		'.env.production',
		'.user.ini',
		'.htpasswd',
		'wp-config.php.bak',
		'wp-config.php.old',
		'wp-config.php.orig',
		'wp-config.php.original',
		'wp-config.php.save',
		'wp-config.php.swp',
		'wp-config.php.swo',
		'wp-config.php_bak',
		'wp-config.php~',
		'#wp-config.php#',
		'.wp-config.php.swp',
		'wp-config.bak',
		'wp-config.old',
		'wp-config.orig',
		'wp-config.original',
		'wp-config.save',
		'wp-config.txt',
		'searchreplacedb2.php',
		'adminer.php',
		'error_log',
		'.bash_history',
	),

	/*
	 * Version control metadata served over HTTP. The value is a string that
	 * must appear in the response, so a soft 404 page does not count as a hit.
	 */
	'repo_paths'               => array(
		'.git/config'  => '[core]',
		'.git/HEAD'    => 'ref:',
		'.svn/entries' => '',
		'.hg/requires' => '',
		'.bzr/branch'  => '',
	),

	/*
	 * Passwords that turn up in every credential dump. Compared against the
	 * stored hash, never sent to the login form.
	 */
	'weak_passwords'           => array(
		'123456',
		'password',
		'12345678',
		'123456789',
		'1234567890',
		'12345',
		'1234567',
		'qwerty',
		'qwerty123',
		'qwertyuiop',
		'abc123',
		'password1',
		'password123',
		'Password1',
		'Password123',
		'admin',
		'admin123',
		'administrator',
		'letmein',
		'welcome',
		'welcome1',
		'monkey',
		'dragon',
		'iloveyou',
		'sunshine',
		'princess',
		'football',
		'baseball',
		'master',
		'shadow',
		'superman',
		'trustno1',
		'root',
		'toor',
		'pass',
		'passwort',
		'test',
		'test123',
		'guest',
		'changeme',
		'default',
		'secret',
		'111111',
		'000000',
		'123123',
		'654321',
		'1q2w3e4r',
		'zaq12wsx',
		'wordpress',
		'wp-admin',
	),
);
