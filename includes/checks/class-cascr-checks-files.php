<?php
/**
 * Checks for file permissions and anything readable that should not be.
 *
 * @package CmsAdmins\SecurityCheck
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Filesystem and exposure checks.
 */
class CASCR_Checks_Files extends CASCR_Checks_Base {

	/**
	 * Prefix of the temporary file used by the PHP execution check.
	 */
	const PROBE_PREFIX = 'cascr-test-';

	/**
	 * Can wp-config.php be written to by the web server?
	 *
	 * @return array
	 */
	public static function wp_config_permissions() {
		$file = ABSPATH . 'wp-config.php';

		if ( ! file_exists( $file ) ) {
			$file = dirname( ABSPATH ) . '/wp-config.php';
		}

		if ( ! file_exists( $file ) ) {
			return CASCR_Result::inconclusive( __( 'wp-config.php could not be located.', 'security-check-report' ) );
		}

		$perms = self::permissions( $file );

		if ( null === $perms ) {
			return CASCR_Result::inconclusive( __( 'The permissions of wp-config.php could not be read.', 'security-check-report' ) );
		}

		$item = sprintf(
			/* translators: 1: file path, 2: octal permissions. */
			__( '%1$s has permissions %2$s', 'security-check-report' ),
			self::relative( $file ),
			self::format_permissions( $perms )
		);

		if ( $perms & 0002 ) {
			return CASCR_Result::fail(
				__( 'wp-config.php is writable by everyone on the server. It holds the database credentials and the authentication keys.', 'security-check-report' ),
				10,
				array( $item ),
				__( 'Set the file to 640 or 440 and make sure it is owned by the site account.', 'security-check-report' )
			);
		}

		if ( $perms & 0004 ) {
			return CASCR_Result::warn(
				__( 'wp-config.php is readable by every account on the server.', 'security-check-report' ),
				5,
				array( $item ),
				__( 'On shared hosting, set the file to 640 or 440.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'The permissions of wp-config.php are restrictive.', 'security-check-report' ), array( $item ) );
	}

	/**
	 * Is the uploads directory writable by everyone?
	 *
	 * @return array
	 */
	public static function uploads_permissions() {
		$dir = wp_upload_dir();

		if ( ! empty( $dir['error'] ) || empty( $dir['basedir'] ) ) {
			return CASCR_Result::inconclusive( __( 'The uploads directory could not be located.', 'security-check-report' ) );
		}

		$perms = self::permissions( $dir['basedir'] );

		if ( null === $perms ) {
			return CASCR_Result::inconclusive( __( 'The permissions of the uploads directory could not be read.', 'security-check-report' ) );
		}

		$item = sprintf(
			/* translators: 1: directory path, 2: octal permissions. */
			__( '%1$s has permissions %2$s', 'security-check-report' ),
			self::relative( $dir['basedir'] ),
			self::format_permissions( $perms )
		);

		if ( $perms & 0002 ) {
			return CASCR_Result::fail(
				__( 'The uploads directory is writable by everyone on the server.', 'security-check-report' ),
				7,
				array( $item ),
				__( 'Set the directory to 755 or 750. It only needs to be writable by the account that runs PHP.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'The uploads directory is not writable by everyone.', 'security-check-report' ), array( $item ) );
	}

	/**
	 * Are the core directories writable by everyone?
	 *
	 * @return array
	 */
	public static function directory_permissions() {
		$insecure = array();
		$unknown  = 0;

		foreach ( array( 'wp-content', 'wp-includes', 'wp-admin' ) as $dir ) {
			$path = ABSPATH . $dir;

			if ( ! is_dir( $path ) ) {
				continue;
			}

			$perms = self::permissions( $path );

			if ( null === $perms ) {
				++$unknown;
				continue;
			}

			if ( $perms & 0002 ) {
				$insecure[] = sprintf(
					/* translators: 1: directory name, 2: octal permissions. */
					__( '%1$s has permissions %2$s', 'security-check-report' ),
					$dir,
					self::format_permissions( $perms )
				);
			}
		}

		if ( ! empty( $insecure ) ) {
			return CASCR_Result::fail(
				__( 'Core directories are writable by everyone on the server.', 'security-check-report' ),
				7,
				$insecure,
				__( 'Set the directories to 755 or 750.', 'security-check-report' )
			);
		}

		if ( $unknown > 0 ) {
			return CASCR_Result::inconclusive( __( 'The permissions of the core directories could not be read.', 'security-check-report' ) );
		}

		return CASCR_Result::pass( __( 'No core directory is writable by everyone.', 'security-check-report' ) );
	}

	/**
	 * Anything below the web root that everyone may write to.
	 *
	 * @return array
	 */
	public static function world_writable_paths() {
		$found   = array();
		$visited = 0;
		$limit   = 4000;

		$roots = array(
			ABSPATH,
			WP_CONTENT_DIR,
			WP_PLUGIN_DIR,
			get_theme_root(),
		);

		foreach ( array_unique( $roots ) as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}

			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $root, RecursiveDirectoryIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::SELF_FIRST
				);
				$iterator->setMaxDepth( 1 );

				foreach ( $iterator as $entry ) {
					if ( ++$visited > $limit ) {
						break 2;
					}

					if ( self::is_world_writable( $entry->getPathname() ) ) {
						$found[] = self::relative( $entry->getPathname() );
					}
				}
			} catch ( Exception $e ) {
				continue;
			}
		}

		$found = array_values( array_unique( $found ) );

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'Nothing below the web root is writable by everyone.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of world-writable paths. */
				_n(
					'%d path is writable by every account on the server.',
					'%d paths are writable by every account on the server.',
					count( $found ),
					'security-check-report'
				),
				count( $found )
			),
			8,
			self::cap( $found ),
			__( 'Set files to 644 and directories to 755. Nothing needs to be world-writable.', 'security-check-report' )
		);
	}

	/**
	 * Executable files sitting in the uploads directory.
	 *
	 * A hardening .htaccess in uploads is deliberately not flagged here. The
	 * previous version treated it as dangerous, which reported the very fix
	 * the php_execution check recommends.
	 *
	 * @return array
	 */
	public static function unallowed_files() {
		$dir = wp_upload_dir();

		if ( empty( $dir['basedir'] ) || ! is_dir( $dir['basedir'] ) ) {
			return CASCR_Result::inconclusive( __( 'The uploads directory could not be read.', 'security-check-report' ) );
		}

		$dangerous = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'phar', 'sh', 'cgi', 'pl', 'py', 'exe' );
		$found     = array();
		$visited   = 0;
		$limit     = 20000;

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir['basedir'], RecursiveDirectoryIterator::SKIP_DOTS )
			);

			foreach ( $iterator as $file ) {
				if ( ++$visited > $limit ) {
					break;
				}

				if ( ! $file->isFile() ) {
					continue;
				}

				if ( ! in_array( strtolower( $file->getExtension() ), $dangerous, true ) ) {
					continue;
				}

				$reason = null;

				if ( 'index.php' === strtolower( $file->getFilename() ) ) {
					$reason = self::guard_verdict( $file->getPathname() );

					if ( null === $reason ) {
						continue;
					}
				}

				// Size is the cheapest hint at what a file is, and for an
				// index.php that did not pass as a guard the reason says which
				// line of it to look at first.
				$found[] = sprintf(
					/* translators: 1: file path, 2: file size, already formatted, 3: why the file was reported, or an empty string. */
					__( '%1$s (%2$s)%3$s', 'security-check-report' ),
					self::relative( $file->getPathname() ),
					size_format( (int) $file->getSize() ),
					null === $reason ? '' : sprintf(
						/* translators: %s: reason the file was reported, for example "it reads $_SERVER". */
						__( ', reported because %s', 'security-check-report' ),
						$reason
					)
				);
			}
		} catch ( Exception $e ) {
			return CASCR_Result::inconclusive( __( 'The uploads directory could not be scanned completely.', 'security-check-report' ) );
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'The uploads directory holds no executable files.', 'security-check-report' ) );
		}

		return CASCR_Result::fail(
			sprintf(
				/* translators: %d: number of executable files found in uploads. */
				_n(
					'%d executable file sits in the uploads directory.',
					'%d executable files sit in the uploads directory.',
					count( $found ),
					'security-check-report'
				),
				count( $found )
			),
			9,
			self::cap( $found ),
			__( 'Media uploads never need to be executable. Inspect each file before deleting it.', 'security-check-report' )
		);
	}

	/**
	 * Why is this small file worth reporting, if it is?
	 *
	 * Every upload folder collects the same handful of files: an index.php with
	 * nothing but a comment, or one that exits or answers 403 so the folder
	 * cannot be listed. Reporting those buries the real findings and, since this
	 * check counts as critical, drags the grade of an otherwise clean site down.
	 *
	 * The name alone decides nothing: only index.php is ever considered, and it
	 * still has to pass here. A file is waved through when it stays under a few
	 * kilobytes and reads no request data, runs no other file and reaches none of
	 * the functions a dropped shell needs. Anything else stays a finding.
	 *
	 * @param string $path Absolute path.
	 * @return string|null Null when the file is a guard, otherwise why it is not.
	 */
	private static function guard_verdict( $path ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return 'the tokeniser is unavailable';
		}

		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- An unreadable file stays a finding.

		if ( false === $size ) {
			return 'its size could not be read';
		}

		if ( $size > 8192 ) {
			return 'it is too large to be a guard';
		}

		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file, read verbatim for tokenising.

		if ( false === $contents ) {
			return 'it could not be read';
		}

		$forbidden_tokens = array( T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE, T_OPEN_TAG_WITH_ECHO, T_ECHO, T_PRINT );

		// $_SERVER is left out on purpose. The most common guard of all builds
		// its 403 header from SERVER_PROTOCOL, and without a call from the list
		// below it cannot turn that into anything. The rest carry attacker
		// input straight into the file and have no business in a guard.
		$forbidden_globals = array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_ENV', '$GLOBALS' );

		$forbidden_calls = array(
			'eval',
			'assert',
			'system',
			'exec',
			'passthru',
			'shell_exec',
			'popen',
			'proc_open',
			'create_function',
			'call_user_func',
			'call_user_func_array',
			'base64_decode',
			'gzinflate',
			'gzuncompress',
			'str_rot13',
			'hex2bin',
			'unserialize',
			'file_get_contents',
			'file_put_contents',
			'fopen',
			'fwrite',
			'fputs',
			'copy',
			'rename',
			'unlink',
			'curl_exec',
			'curl_init',
			'move_uploaded_file',
			'extract',
			'preg_replace',
			'preg_replace_callback',
			'set_error_handler',
		);

		$tokens = @token_get_all( $contents ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Malformed input must not raise a parse warning.
		$count  = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$token = $tokens[ $i ];

			if ( ! is_array( $token ) ) {
				// A backtick runs a shell command, and $ starts a variable variable.
				if ( '`' === $token ) {
					return 'it runs a shell command';
				}

				if ( '$' === $token ) {
					return 'it builds a variable name at runtime';
				}

				continue;
			}

			if ( in_array( $token[0], $forbidden_tokens, true ) ) {
				return sprintf(
					/* translators: %s: a PHP keyword such as require or eval. */
					__( 'it uses %s', 'security-check-report' ),
					trim( $token[1] )
				);
			}

			// Request data has no business in a guard file.
			if ( T_VARIABLE === $token[0] && in_array( $token[1], $forbidden_globals, true ) ) {
				return sprintf(
					/* translators: %s: name of a PHP superglobal, for example $_GET. */
					__( 'it reads %s', 'security-check-report' ),
					$token[1]
				);
			}

			// A variable used as a function name hides the call from this list.
			if ( T_VARIABLE === $token[0] && self::next_is_call( $tokens, $i ) ) {
				return 'it calls a function held in a variable';
			}

			if ( T_STRING === $token[0] && in_array( strtolower( $token[1] ), $forbidden_calls, true ) ) {
				return sprintf(
					/* translators: %s: name of a PHP function, for example base64_decode. */
					__( 'it calls %s', 'security-check-report' ),
					$token[1]
				);
			}

			if ( T_INLINE_HTML === $token[0] && '' !== trim( $token[1] ) ) {
				return 'it prints output of its own';
			}
		}

		return null;
	}

	/**
	 * Does an opening bracket follow, ignoring whitespace?
	 *
	 * @param array $tokens Token list from token_get_all().
	 * @param int   $index  Position of the current token.
	 * @return bool
	 */
	private static function next_is_call( $tokens, $index ) {
		$count = count( $tokens );

		for ( $i = $index + 1; $i < $count; $i++ ) {
			if ( is_array( $tokens[ $i ] ) && T_WHITESPACE === $tokens[ $i ][0] ) {
				continue;
			}

			return '(' === $tokens[ $i ];
		}

		return false;
	}

	/**
	 * Will the server run a PHP file that lands in the uploads directory?
	 *
	 * @return array
	 */
	public static function php_execution() {
		$filesystem = self::filesystem();

		if ( ! $filesystem ) {
			return CASCR_Result::inconclusive( __( 'The filesystem could not be initialised for this check.', 'security-check-report' ) );
		}

		$dir = wp_upload_dir();

		if ( empty( $dir['basedir'] ) || empty( $dir['baseurl'] ) ) {
			return CASCR_Result::inconclusive( __( 'The uploads directory could not be located.', 'security-check-report' ) );
		}

		self::remove_stale_probes( $filesystem, $dir['basedir'] );

		$name   = self::PROBE_PREFIX . wp_generate_password( 12, false ) . '.php';
		$path   = trailingslashit( $dir['basedir'] ) . $name;
		$url    = trailingslashit( $dir['baseurl'] ) . $name;
		$marker = 'CASCR_PHP_EXEC_TEST';

		if ( ! $filesystem->put_contents( $path, '<?php echo "' . $marker . '";', FS_CHMOD_FILE ) ) {
			return CASCR_Result::inconclusive( __( 'A test file could not be written to the uploads directory.', 'security-check-report' ) );
		}

		// If PHP dies between writing and deleting, the shutdown handler still
		// removes the file. The previous version could leave it behind.
		register_shutdown_function(
			function () use ( $path ) {
				if ( file_exists( $path ) ) {
					wp_delete_file( $path );
				}
			}
		);

		$response = CASCR_Http::get( $url, array( 'redirection' => 0 ) );

		$filesystem->delete( $path );

		if ( is_wp_error( $response ) ) {
			return CASCR_Result::inconclusive( __( 'The test file could not be requested over HTTP.', 'security-check-report' ) );
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 403 === $code || 404 === $code ) {
			return CASCR_Result::pass( __( 'PHP files in the uploads directory are not served.', 'security-check-report' ) );
		}

		if ( false !== strpos( wp_remote_retrieve_body( $response ), $marker ) ) {
			return CASCR_Result::fail(
				__( 'The server runs PHP files from the uploads directory, which turns any file upload flaw into code execution.', 'security-check-report' ),
				9,
				array(),
				__( 'Block PHP in the uploads directory in the server configuration, or add an .htaccess there that denies .php files.', 'security-check-report' )
			);
		}

		return CASCR_Result::pass( __( 'PHP files in the uploads directory are not executed.', 'security-check-report' ) );
	}

	/**
	 * Configuration and backup files that the web server hands out.
	 *
	 * Whether a file exists and whether it is served are two different
	 * questions, and the answers differ between Apache and nginx.
	 *
	 * @return array
	 */
	public static function exposed_config_files() {
		$candidates = self::config( 'exposed_files' );
		$served     = array();
		$present    = array();
		$unknown    = 0;

		foreach ( $candidates as $name ) {
			if ( ! file_exists( ABSPATH . $name ) ) {
				continue;
			}

			$public = CASCR_Http::is_public( home_url( '/' . ltrim( $name, '/' ) ) );

			if ( null === $public ) {
				++$unknown;
				continue;
			}

			if ( $public ) {
				$served[] = $name;
			} else {
				$present[] = $name;
			}
		}

		if ( ! empty( $served ) ) {
			return CASCR_Result::fail(
				sprintf(
					/* translators: %d: number of publicly readable configuration files. */
					_n(
						'%d configuration or backup file is readable from the web.',
						'%d configuration or backup files are readable from the web.',
						count( $served ),
						'security-check-report'
					),
					count( $served )
				),
				10,
				$served,
				__( 'Delete the files. Anything readable here can contain database credentials and API keys.', 'security-check-report' )
			);
		}

		if ( ! empty( $present ) ) {
			return CASCR_Result::warn(
				sprintf(
					/* translators: %d: number of configuration files present but not served. */
					_n(
						'%d configuration or backup file sits in the web root but is not served.',
						'%d configuration or backup files sit in the web root but are not served.',
						count( $present ),
						'security-check-report'
					),
					count( $present )
				),
				5,
				$present,
				__( 'Move the files out of the web root. A server configuration change is all it takes to expose them.', 'security-check-report' )
			);
		}

		if ( $unknown > 0 ) {
			return CASCR_Result::inconclusive( __( 'It could not be verified whether these files are publicly readable.', 'security-check-report' ) );
		}

		return CASCR_Result::pass( __( 'No configuration or backup files were found in the web root.', 'security-check-report' ) );
	}

	/**
	 * Version control directories served over HTTP.
	 *
	 * @return array
	 */
	public static function exposed_repo_dirs() {
		$probes  = self::config( 'repo_paths' );
		$served  = array();
		$unknown = 0;

		foreach ( $probes as $path => $needle ) {
			$public = CASCR_Http::is_public( home_url( '/' . ltrim( $path, '/' ) ), $needle );

			if ( null === $public ) {
				++$unknown;
				continue;
			}

			if ( $public ) {
				$served[] = $path;
			}
		}

		if ( ! empty( $served ) ) {
			return CASCR_Result::fail(
				__( 'A version control directory is readable from the web, which exposes the full source history and often credentials along with it.', 'security-check-report' ),
				10,
				$served,
				__( 'Block the directory at the server, or deploy without the repository metadata.', 'security-check-report' )
			);
		}

		if ( $unknown === count( $probes ) ) {
			return CASCR_Result::inconclusive( __( 'The version control paths could not be checked.', 'security-check-report' ) );
		}

		return CASCR_Result::pass( __( 'No version control directory is readable from the web.', 'security-check-report' ) );
	}

	/**
	 * Database dumps and archives lying in the web root.
	 *
	 * @return array
	 */
	public static function exposed_db_dumps() {
		$patterns = array( '*.sql', '*.sql.gz', '*.sql.zip', '*.sql.bz2', '*.dump', 'backup*.zip', 'backup*.tar.gz', '*.tar.gz' );
		$found    = array();

		foreach ( array( ABSPATH, WP_CONTENT_DIR . '/' ) as $root ) {
			foreach ( $patterns as $pattern ) {
				$matches = glob( $root . $pattern );

				if ( ! is_array( $matches ) ) {
					continue;
				}

				foreach ( $matches as $match ) {
					if ( is_file( $match ) ) {
						$found[ self::relative( $match ) ] = $match;
					}
				}
			}
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'No database dumps or archives were found in the web root.', 'security-check-report' ) );
		}

		$served  = array();
		$present = array();

		foreach ( $found as $relative => $absolute ) {
			$public = CASCR_Http::is_public( home_url( '/' . $relative ) );

			if ( $public ) {
				$served[] = sprintf(
					/* translators: 1: file path, 2: human readable file size. */
					__( '%1$s (%2$s)', 'security-check-report' ),
					$relative,
					size_format( (int) filesize( $absolute ) )
				);
			} else {
				$present[] = $relative;
			}
		}

		if ( ! empty( $served ) ) {
			return CASCR_Result::fail(
				__( 'A database dump or archive can be downloaded from the site.', 'security-check-report' ),
				10,
				$served,
				__( 'Delete the file immediately and assume its contents are known. Then rotate the database password and the authentication keys.', 'security-check-report' )
			);
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of dumps or archives found. */
				_n(
					'%d database dump or archive sits in the web root but is not served.',
					'%d database dumps or archives sit in the web root but are not served.',
					count( $present ),
					'security-check-report'
				),
				count( $present )
			),
			6,
			$present,
			__( 'Move the files somewhere outside the web root.', 'security-check-report' )
		);
	}

	/**
	 * Files that only give away information about the installation.
	 *
	 * @return array
	 */
	public static function unwanted_files_root() {
		$found = array();

		foreach ( self::config( 'unwanted_files' ) as $name ) {
			if ( file_exists( ABSPATH . $name ) ) {
				$found[] = $name;
			}
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'The web root holds no leftover files.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of leftover files. */
				_n(
					'%d leftover file sits in the web root.',
					'%d leftover files sit in the web root.',
					count( $found ),
					'security-check-report'
				),
				count( $found )
			),
			4,
			$found,
			__( 'These files reveal version and tooling details. Deleting them is safe.', 'security-check-report' )
		);
	}

	/**
	 * Directories left behind by interrupted updates.
	 *
	 * @return array
	 */
	public static function upgrade_leftovers() {
		$found = array();

		foreach ( array( 'upgrade', 'upgrade-temp-backup' ) as $name ) {
			$dir = WP_CONTENT_DIR . '/' . $name;

			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$entries = glob( $dir . '/*' );

			if ( ! is_array( $entries ) || empty( $entries ) ) {
				continue;
			}

			foreach ( $entries as $entry ) {
				$age = time() - (int) filemtime( $entry );

				if ( $age < DAY_IN_SECONDS ) {
					continue;
				}

				$found[] = sprintf(
					/* translators: 1: path, 2: human readable age. */
					__( '%1$s, left behind %2$s ago', 'security-check-report' ),
					self::relative( $entry ),
					human_time_diff( time() - $age, time() )
				);
			}
		}

		if ( empty( $found ) ) {
			return CASCR_Result::pass( __( 'No leftovers from interrupted updates were found.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			sprintf(
				/* translators: %d: number of leftover directories. */
				_n(
					'%d leftover from an interrupted update is still on disk.',
					'%d leftovers from interrupted updates are still on disk.',
					count( $found ),
					'security-check-report'
				),
				count( $found )
			),
			5,
			self::cap( $found ),
			__( 'These folders can hold unpacked, outdated copies of plugins that are still reachable. Delete them.', 'security-check-report' )
		);
	}

	/**
	 * Does the server list directory contents?
	 *
	 * @return array
	 */
	public static function directory_listing() {
		$paths = array(
			'wp-content/',
			'wp-content/plugins/',
			'wp-content/uploads/',
			'wp-content/upgrade/',
			'wp-includes/',
		);

		$listed  = array();
		$unknown = 0;

		foreach ( $paths as $path ) {
			$response = CASCR_Http::get( home_url( '/' . $path ), array( 'redirection' => 0 ) );

			if ( is_wp_error( $response ) ) {
				++$unknown;
				continue;
			}

			if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}

			$body = wp_remote_retrieve_body( $response );

			if ( false !== stripos( $body, 'Index of /' ) || false !== stripos( $body, '<title>Index of' ) ) {
				$listed[] = $path;
			}
		}

		if ( ! empty( $listed ) ) {
			return CASCR_Result::warn(
				__( 'The server lists directory contents, which hands attackers a map of the installation.', 'security-check-report' ),
				6,
				$listed,
				__( 'Switch off autoindex in the server configuration, or add Options -Indexes to .htaccess.', 'security-check-report' )
			);
		}

		if ( $unknown === count( $paths ) ) {
			return CASCR_Result::inconclusive( __( 'Directory listing could not be checked.', 'security-check-report' ) );
		}

		return CASCR_Result::pass( __( 'The server does not list directory contents.', 'security-check-report' ) );
	}

	/**
	 * Is there a rule file protecting the installation?
	 *
	 * @return array
	 */
	public static function htaccess() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) )
			: '';

		if ( false !== strpos( $server, 'nginx' ) || false !== strpos( $server, 'caddy' ) ) {
			return CASCR_Result::info(
				__( 'This server does not use .htaccess. Its rules live in the server configuration and cannot be inspected from here.', 'security-check-report' )
			);
		}

		if ( file_exists( ABSPATH . '.htaccess' ) ) {
			return CASCR_Result::pass( __( 'An .htaccess file is present.', 'security-check-report' ) );
		}

		return CASCR_Result::warn(
			__( 'No .htaccess file was found, so none of the usual hardening rules are in place.', 'security-check-report' ),
			5,
			array(),
			__( 'Save the permalink settings once. WordPress writes a basic .htaccess by itself.', 'security-check-report' )
		);
	}

	/**
	 * Deletes probe files an earlier interrupted run may have left behind.
	 *
	 * @param WP_Filesystem_Base $filesystem Filesystem handle.
	 * @param string             $basedir    Uploads base directory.
	 */
	private static function remove_stale_probes( $filesystem, $basedir ) {
		$stale = glob( trailingslashit( $basedir ) . self::PROBE_PREFIX . '*.php' );

		if ( ! is_array( $stale ) ) {
			return;
		}

		foreach ( $stale as $file ) {
			$filesystem->delete( $file );
		}
	}
}
