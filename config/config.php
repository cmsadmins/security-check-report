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
	 * Plugins that add a second authentication factor, each with the user meta
	 * it writes once an account has actually set the factor up.
	 *
	 * The meta matters as much as the plugin file. Without it the check cannot
	 * tell an account that skipped the setup from one it simply cannot read,
	 * and reports the reassuring answer to both. An empty list means the
	 * storage is unknown, which is the one case where saying nothing is right.
	 *
	 * iThemes Security became Solid Security and then Kadence Security. All
	 * three ship under the folder names below and keep the same user meta.
	 */
	'two_factor_plugins'       => array(
		'two-factor/two-factor.php'                     => array( '_two_factor_enabled_providers' ),
		'two-factor-provider-webauthn/two-factor-provider-webauthn.php' => array( '_two_factor_enabled_providers' ),
		'wp-2fa/wp-2fa.php'                             => array( 'wp_2fa_enabled_methods', 'wp_2fa_totp_key' ),
		'wordfence-login-security/wordfence-login-security.php' => array(),
		'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => array(),
		'miniOrange-2-factor-authentication/miniorange-2-factor.php' => array(),
		'duo-wordpress/duo.php'                         => array(),
		'rublon/rublon.php'                             => array(),
		'keyy-two-factor-authentication/keyy.php'       => array(),
		'google-authenticator/google-authenticator.php' => array( 'googleauthenticator_enabled' ),
		'wp-google-authenticator/wp-google-authenticator.php' => array( 'wpga_active' ),
		'two-factor-authentication/two-factor-authentication.php' => array(),
		'better-wp-security/better-wp-security.php'     => array( 'itsec_two_factor_enabled_providers' ),
		'ithemes-security-pro/ithemes-security-pro.php' => array( 'itsec_two_factor_enabled_providers' ),
		'solid-security/solid-security.php'             => array( 'itsec_two_factor_enabled_providers' ),
		'solid-security-pro/solid-security-pro.php'     => array( 'itsec_two_factor_enabled_providers' ),
		'kadence-security/kadence-security.php'         => array( 'itsec_two_factor_enabled_providers' ),
		'kadence-security-pro/kadence-security-pro.php' => array( 'itsec_two_factor_enabled_providers' ),
		'reportedip-hive/reportedip-hive.php'           => array( 'reportedip_hive_2fa_enabled' ),
		'shield-security/shield-security.php'           => array(),
		'wp-simple-firewall/wp-simple-firewall.php'     => array(),
		'defender-security/wp-defender.php'             => array( '_wpdef_two_fa_enabled' ),
		'jetpack/jetpack.php'                           => array(),
	),

	/*
	 * Plugins that label AI-generated content or disclose an AI system to
	 * visitors, each with the option it writes once the labelling is switched
	 * on. Every entry was read out of the plugin itself, not guessed from the
	 * slug: a folder on disk only says someone meant to do this.
	 *
	 * The list covers what the directory offered in September 2026. It is
	 * young and it will grow, which is what the cascr_registry filter is for.
	 */
	'ai_disclosure_plugins'    => array(
		'transparai/transparai.php'                     => array( 'transparai_settings', 'transparai_compliance' ),
		'eu-ai-label/eu-ai-label.php'                   => array( 'eu_ai_label_options' ),
		'eu-ai-act-ready/eu-ai-act-ready.php'           => array( 'euaiactready_transparency_enabled', 'euaiactready_media_transparency' ),
		'legalithm-ai-act/legalithm-ai-act.php'         => array( 'legalithm_ai_act_settings' ),
		'legibright-ai-act-compliance/legibright-ai-act-compliance.php' => array( 'legibright_settings' ),
		'tiriri-transparency-for-eu-ai-act/tiriri-transparency-for-eu-ai-act.php' => array( 'tiriri_settings' ),
		'studiomeyer-ai-transparency-toolkit/studiomeyer-ai-transparency-toolkit.php' => array( 'smtt_settings' ),
		'aim-transparency/aim-transparency.php'         => array( 'aicl_settings' ),
		'klarvo-ai-transparency/klarvo-ai-transparency.php' => array( 'klarvo_ain_settings' ),
		'intigra-disclosio/intigra-disclosio.php'       => array( 'aiid_settings' ),
		'ai-image-disclosure-labels/ai-image-disclosure-labels.php' => array( 'gdaiidl_settings' ),
		'oznaczai-image-labeling/oznaczai.php'          => array( 'oznaczai_image_labeling_settings' ),
		'image-ai-labels-free/image-ai-labels-free.php' => array( 'kiimg_settings' ),
		'onestep-ai-image-marker/onestep-ai-image-marker.php' => array( 'aiim_settings' ),
		'radermacher-ai-media-marker/radermacher-ai-media-marker.php' => array( 'aiim_settings' ),
		'schnieders-ai-media-labels/schnieders-ai-media-labels.php' => array( 'saiml_settings' ),
		'ropemark-image-marking-for-eu-ai-act/ropemark-image-marking-for-eu-ai-act.php' => array( 'ropemark_settings' ),
		'seonai-ai-image-checkmark/seonai-ai-image-checkmark.php' => array( 'sicm_settings' ),
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
