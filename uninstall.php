<?php
/**
 * Removes everything the plugin stored.
 *
 * @package CmsAdmins\SecurityCheck
 */

// Exit if accessed directly or not uninstalling.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

foreach ( array( 'cascr_last_scan', 'cascr_previous_scan', 'cascr_ignored', 'cascr_baseline', 'cascr_consent', 'cascr_badge', 'cascr_history' ) as $cascr_option ) {
	delete_option( $cascr_option );
}

// Cached plugin directory lookups.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transients are removed in bulk during uninstall.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		'_transient_cascr_%',
		'_transient_timeout_cascr_%'
	)
);

// Login timestamps recorded for the dormant administrator check, and the
// per user note that the reminder notice was dismissed. User meta is shared
// across a network, so one delete covers every site.
foreach ( array( 'cascr_last_login', 'cascr_nudge' ) as $cascr_meta_key ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- One bulk delete during uninstall is the right shape here.
	$wpdb->delete( $wpdb->usermeta, array( 'meta_key' => $cascr_meta_key ) );
}

wp_cache_flush();
