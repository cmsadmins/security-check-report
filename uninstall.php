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

foreach ( array( 'cascr_last_scan', 'cascr_previous_scan', 'cascr_ignored', 'cascr_baseline' ) as $cascr_option ) {
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

// Login timestamps recorded for the dormant administrator check.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- One bulk delete during uninstall is the right shape here.
$wpdb->delete( $wpdb->usermeta, array( 'meta_key' => 'cascr_last_login' ) );

wp_cache_flush();
