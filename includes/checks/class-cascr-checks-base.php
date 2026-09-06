<?php
/**
 * Shared helpers for the check groups.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Utilities every check group needs.
 */
abstract class CASCR_Checks_Base {

	/**
	 * Lazily loaded lists from config/config.php.
	 *
	 * @var array|null
	 */
	private static $config = null;

	/**
	 * A list from config/config.php.
	 *
	 * @param string $key List name.
	 * @return array
	 */
	protected static function config( $key ) {
		if ( null === self::$config ) {
			self::$config = include CASCR_PATH . 'config/config.php';
		}

		return isset( self::$config[ $key ] ) ? self::$config[ $key ] : array();
	}

	/**
	 * The WordPress filesystem abstraction, or null when it cannot be set up.
	 *
	 * @return WP_Filesystem_Base|null
	 */
	protected static function filesystem() {
		global $wp_filesystem;

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		if ( ! WP_Filesystem() ) {
			return null;
		}

		return $wp_filesystem;
	}

	/**
	 * Makes sure the plugin API is available before get_plugins() is used.
	 */
	protected static function load_plugin_api() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
	}

	/**
	 * Permission bits of a path, or null when it cannot be read.
	 *
	 * @param string $path Absolute path.
	 * @return int|null
	 */
	protected static function permissions( $path ) {
		if ( ! file_exists( $path ) ) {
			return null;
		}

		$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir restrictions are handled by the null return.

		if ( false === $perms ) {
			return null;
		}

		return $perms & 0777;
	}

	/**
	 * Whether a path is writable by everyone.
	 *
	 * This replaces the previous comparison against exactly 0755, which
	 * reported 0750 and the setgid 2755 that many hosts use as insecure.
	 * What actually matters is the world-writable bit.
	 *
	 * @param string $path Absolute path.
	 * @return bool|null Null when the permissions cannot be read.
	 */
	protected static function is_world_writable( $path ) {
		$perms = self::permissions( $path );

		if ( null === $perms ) {
			return null;
		}

		return (bool) ( $perms & 0002 );
	}

	/**
	 * Formats permission bits the way chmod expects them.
	 *
	 * @param int $perms Permission bits.
	 * @return string
	 */
	protected static function format_permissions( $perms ) {
		return substr( '0' . decoct( $perms ), -4 );
	}

	/**
	 * Whether a plugin from a config list is active.
	 *
	 * @param string $key Config list name.
	 * @return string[] Names of the active plugins from that list.
	 */
	protected static function active_from_list( $key ) {
		self::load_plugin_api();

		$active = array();

		foreach ( array_unique( self::config( $key ) ) as $plugin ) {
			if ( ! is_plugin_active( $plugin ) ) {
				continue;
			}

			$file = WP_PLUGIN_DIR . '/' . $plugin;
			$data = file_exists( $file ) ? get_plugin_data( $file, false, false ) : array();

			$active[] = ! empty( $data['Name'] ) ? $data['Name'] : basename( dirname( $plugin ) );
		}

		return $active;
	}

	/**
	 * Header value from a response, case-insensitively.
	 *
	 * @param array|WP_Error $response Response.
	 * @param string         $header   Header name.
	 * @return string
	 */
	protected static function header( $response, $header ) {
		if ( is_wp_error( $response ) ) {
			return '';
		}

		$value = wp_remote_retrieve_header( $response, strtolower( $header ) );

		if ( is_array( $value ) ) {
			$value = implode( ', ', $value );
		}

		return (string) $value;
	}

	/**
	 * Truncates a list of findings for display and appends the remainder count.
	 *
	 * @param string[] $items Items.
	 * @param int      $limit Maximum entries to keep.
	 * @return string[]
	 */
	protected static function cap( $items, $limit = 20 ) {
		if ( count( $items ) <= $limit ) {
			return array_values( $items );
		}

		$kept = array_slice( array_values( $items ), 0, $limit );
		$rest = count( $items ) - $limit;

		$kept[] = sprintf(
			/* translators: %d: number of further findings that are not listed. */
			_n( 'and %d more', 'and %d more', $rest, 'security-check-report' ),
			$rest
		);

		return $kept;
	}

	/**
	 * Reads a two level string value out of an untyped array.
	 *
	 * Used for stream metadata, whose shape depends on whether the stream is
	 * encrypted and is therefore not described by any stub.
	 *
	 * @param array  $data Source array.
	 * @param string $key  Outer key.
	 * @param string $sub  Inner key.
	 * @return string
	 */
	protected static function nested_string( $data, $key, $sub ) {
		if ( ! isset( $data[ $key ] ) || ! is_array( $data[ $key ] ) ) {
			return '';
		}

		return isset( $data[ $key ][ $sub ] ) ? (string) $data[ $key ][ $sub ] : '';
	}

	/**
	 * Path relative to the WordPress root, for readable output.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	protected static function relative( $path ) {
		$path = wp_normalize_path( $path );
		$root = wp_normalize_path( ABSPATH );

		if ( 0 === strpos( $path, $root ) ) {
			return substr( $path, strlen( $root ) );
		}

		return $path;
	}
}
