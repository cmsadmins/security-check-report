=== CMS ADMINS Security Check Report ===
Contributors: contexlabs
Donate link: https://www.cms-admins.de/
Tags: security, audit, vulnerability, malware, scanner
Requires at least: 6.4
Tested up to: 6.9
Requires PHP: 8.2
Stable tag: 2.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Comprehensive security audit for your WordPress installation with 45 security tests and weighted A-F risk grading.

== Description ==

The **CMS ADMINS Security Check Report** plugin performs a comprehensive series of security checks on your WordPress site. It evaluates different aspects of security using a weighted scoring system and provides clear recommendations for improvements.

**Key Features:**

* **45 Security Tests** covering all critical aspects of WordPress security
* **Weighted A-F Risk Grading** - Critical issues have higher impact on your score
* **Category-Based Scoring** - Tests grouped into Critical, High, Medium, and Low categories
* **Real-Time Progress** - Watch tests run with live percentage updates
* **Searchable Documentation** - Find specific test information instantly
* **Dark Mode Support** - Automatic theme detection
* **Fully Accessible** - WCAG 2.1 AA compliant with keyboard navigation
* **Copy Report** - One-click export of results for sharing

**Security Tests Include:**

* WordPress and PHP version checks
* wp-config.php file permissions and security keys
* File and directory permissions audit
* Debug mode and error logging detection
* Weak password and admin username checks
* Plugin and theme update status
* XML-RPC and REST API exposure
* SSL/HTTPS configuration
* Server security headers analysis
* Malware signature scanning
* Database prefix and user privileges
* Brute-force and login protection detection
* User enumeration protection
* And many more...

**Risk Grading System:**

| Grade | Risk Level | Description |
|-------|------------|-------------|
| A | Excellent | Very well protected |
| B | Good | Good protection with minor improvements possible |
| C | Moderate | Several improvements recommended |
| D | Poor | Significant security risks detected |
| F | Critical | Immediate action required |

**Disclaimer:**

Please note that CMS ADMINS does not take any responsibility for any damages to the system/server and does not guarantee the accuracy of the results. Users are advised to take appropriate precautions and backup their site before making any changes based on the plugin's recommendations.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/security-check-report` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to 'Tools' -> 'Security Check Report' to view the security check results.

== Frequently Asked Questions ==

= What security checks does this plugin perform? =

The plugin performs 45 security checks across four categories:

**Critical Category:**
1. Malware Check - Scans for malware signatures in WordPress files
2. PHP Execution in Uploads - Checks if PHP can execute in uploads directory
3. Weak Password Users - Detects users with common weak passwords
4. Two-Factor Authentication - Checks for 2FA plugin presence
5. Admin Username - Detects insecure "admin" username
6. Database User Privileges - Analyzes database permissions
7. wp-config.php - Validates configuration file security
8. Unallowed Files - Scans uploads for dangerous file types

**High Category:**
9. WordPress Version - Checks if WordPress is up to date
10. Outdated Plugins - Identifies plugins needing updates
11. SSL Enabled - Verifies HTTPS configuration
12. File Editing - Checks if admin file editing is disabled
13. Brute-Force Protection - Detects protection plugins
14. Automatic Core Updates - Verifies auto-update settings
15. PHP Version - Checks PHP version currency
16. PHP Version Support - Verifies PHP is still supported
17. Security Keys and Salts - Validates wp-config security keys

**Medium Category:**
18. Server Headers - Analyzes security headers
19. Directory Permissions - Checks folder permissions
20. Uploads Permissions - Verifies uploads directory security
21. WP_DEBUG Mode - Detects debug mode status
22. Password Policy - Checks for password policy plugins
23. Login Attempts Limiting - Detects rate limiting
24. User Enumeration - Tests for user enumeration protection
25. Outdated Themes - Identifies themes needing updates
26. Outdated Libraries - Checks for vulnerable libraries

**Low Category:**
27. Database Prefix - Checks for custom table prefix
28. XML-RPC Interface - Detects XML-RPC exposure
29. REST API - Analyzes REST API configuration
30. Windows Live Writer - Checks for legacy meta tags
31. Deactivated Plugins - Lists inactive plugins
32. .htaccess File - Verifies htaccess presence
33. Directory Indexing - Tests for index exposure
34. Unwanted Files in Root - Scans for leftover files
35. Other WordPress Installations - Detects multiple installs

Plus additional tests for PHP version in headers, file change detection, configuration backups, and more.

Note: For SSL/TLS vulnerability testing (Heartbleed, POODLE, DROWN), we recommend using external tools like [SSL Labs](https://www.ssllabs.com/ssltest/).

= How does the weighted scoring system work? =

Tests are assigned to categories based on their security impact:
- **Critical tests** (weight 3.0x): Authentication, malware, code execution
- **High tests** (weight 2.0x): Updates, SSL, important configurations
- **Medium tests** (weight 1.5x): Headers, permissions, policies
- **Low tests** (weight 1.0x): Best practices, cosmetic issues

A single critical failure will significantly impact your grade, ensuring serious issues are never hidden by passing minor tests.

= How often should I run the plugin? =

It is recommended to run the plugin regularly, especially after updates or changes to your site. Monthly scans are a good baseline, with additional scans after major changes.

= What should I do if the plugin reports a security risk? =

Follow the plugin's recommendations to mitigate the security risk. Each test includes detailed documentation explaining what was checked, why it matters, and specific steps to resolve issues.

== Screenshots ==

1. **Dashboard:** Overview of security checks with A-F grade display
2. **Results Table:** Detailed test results with color-coded scores
3. **Documentation:** Searchable accordion with test explanations

== Changelog ==

= 2.2.1 =
* First release on the WordPress.org plugin directory
* Renamed plugin folder, main file and text domain to security-check-report
* Removed the Spamhaus IP blacklist test (sent the server IP to a third-party service without opt-in); the plugin now performs 45 tests
* Removed unused legacy code and files
* Fixed translation loading on WordPress 6.7+ (no more _load_textdomain_just_in_time notice)
* Enabled SSL verification for the PHP execution test request

= 2.2.0 =
* **UI/UX Overhaul:**
  * Completely redesigned header with cleaner, professional appearance
  * New accordion system with native HTML5 details/summary elements
  * Added real-time search functionality for test documentation
  * Unified color scheme across all components
  * Improved progress indicator with spinner animation
  * Added CMS ADMINS footer with copyright and support links
* **CSS Improvements:**
  * Fixed accordion overflow issues with box-shadow technique
  * Removed conflicting legacy styles from backend.css
  * Better visual consistency across all UI elements
  * Improved checkbox and form styling
* **Documentation:**
  * Rewrote all 46 test descriptions with consistent format
  * Each test now includes: What it checks, Why it matters, Recommendation
  * Better organization and readability

= 2.1.0 =
* **New Weighted Scoring System:**
  * Implemented category-based risk calculation (Critical, High, Medium, Low)
  * Category weights: Critical 3.0x, High 2.0x, Medium 1.5x, Low 1.0x
  * New A-F letter grade display (A=Excellent to F=Critical)
  * Single critical failure properly impacts overall grade
* **Test Improvements:**
  * Fixed XML-RPC check to actually test endpoint accessibility
  * Fixed REST API check to verify real exposure status
  * Enhanced user enumeration check with multiple detection methods
  * Improved weak password detection with expanded password list
  * Better automatic core updates detection
* **New Tests Added:**
  * Application Passwords audit
  * WP-Cron security check
  * Debug log exposure detection
  * CORS configuration analysis
  * WordPress core file integrity verification
* **Configuration Updates:**
  * Updated security headers list (added COOP, COEP, CORP)
  * Improved malware signature patterns with severity levels
  * Expanded allowed file types list
  * Better test categorization

= 2.0.0 =
* **Major Security Overhaul:**
  * Added capability checks to all AJAX handlers
  * Fixed XSS vulnerability in accordion descriptions
  * Removed dangerous shell_exec tests (Shellshock, Heartbleed, POODLE, DROWN)
  * Fixed SQL injection vulnerability in WordPress installations scanner
  * Replaced file_get_contents with WP_Filesystem
  * Fixed temp file race condition with unique filenames
* **Architecture Improvements:**
  * Modernized to PHP 8.2+ with PSR-4 autoloading (Composer)
  * New class-based architecture with services, interfaces, and dependency injection
  * Added ConfigProvider, CacheService, FileSystemService, DatabaseService
  * Implemented TestRunner with RiskCalculator
* **Frontend Modernization:**
  * Vanilla JavaScript ES2022+ (no jQuery dependency)
  * Modern ES modules with async/await and Fetch API
  * Full WCAG 2.1 AA accessibility compliance
  * Keyboard navigation support throughout
  * Screen reader compatible with ARIA attributes
* **CSS Improvements:**
  * CSS Custom Properties for theming
  * Dark Mode support via prefers-color-scheme
  * Responsive design for all screen sizes
  * prefers-reduced-motion support
  * Improved focus states for accessibility
* **New Features:**
  * Added missing test methods (backup, security_plugins, db_prefix, brute_force, login_attempts)
  * Better progress tracking with percentage display
  * Modern clipboard API with fallback
  * Improved risk calculation and reporting
* **Removed Features:**
  * Removed shell-based vulnerability tests (use SSL Labs for SSL/TLS testing)
  * Recommendation: Use https://www.ssllabs.com/ssltest/ for comprehensive SSL/TLS checks

= 1.1.5 =
* Improved security by sanitizing and validating IP address before checking blacklist status

= 1.1.4 =
* Remove invalid files from the plugin folder
* Added tested up to: WP 6.5.5
* Added Infos for Third-Party Services in readme.txt and Plugin-Frontend
* Security Enhancements:
  * Added sanitization, validation, and escaping for all input and output data
  * Sanitized and escaped server variables
  * Validated IP addresses using filter_var
  * Escaped shell commands to prevent command injection
  * Properly escaped HTML output to prevent XSS attacks
* Updated function, class, namespace, and option names to use unique prefix "CASC_"
* Improved code readability and maintainability

= 1.1.3 =
* Added security checks for PHP version support
* Added security checks for directory permissions
* Added security checks for database user privileges
* Added file change detection for important files
* Added outdated libraries check
* Optimized existing security checks for better performance

= 1.1.2 =
* Added check for PHP version in server response headers
* Added check for unwanted files in the root directory
* Added check for Windows Live Writer link in headers
* Added check for security keys and salts in wp-config.php
* Added check for automatic WordPress core updates
* Added check for deactivated plugins

= 1.1.1 =
* Fix Text-Domain
* Add Tests

= 1.1 =
* Added comprehensive security checks
* Improved UI for displaying security check results
* Enhanced performance and reliability

= 1.0 =
* Initial release

== Upgrade Notice ==

= 2.2.1 =
First release on WordPress.org. The Spamhaus IP blacklist test has been removed, no data is sent to third parties other than the WordPress.org API anymore.

= 2.2.0 =
Major UI overhaul with redesigned interface, searchable documentation, and improved visual consistency. All test descriptions have been rewritten for clarity.

= 2.1.0 =
New weighted scoring system with A-F grades ensures critical issues properly impact your risk assessment. Several test methods have been fixed and new tests added.

= 2.0.0 =
Major security and architecture update. Important security fixes - please update immediately. Now requires PHP 8.2+.

== License & Credits ==

This plugin is free software and is released under the GPLv2 or later.

Developed by Patrick Schlesinger / CMS ADMINS
Website: https://www.cms-admins.de/

### Third-Party Services

This plugin uses the following third-party services:

1. **WordPress.org API**
   - **Purpose**: Used to fetch the latest version of WordPress, plugins, themes, security keys, and core file checksums.
   - **Service URLs**:
     - [WordPress Version Check](https://api.wordpress.org/core/version-check/1.7/)
     - [Plugin Info](https://api.wordpress.org/plugins/info/1.0/)
     - [Theme Info](https://api.wordpress.org/themes/info/1.0/)
     - [Security Keys and Salts](https://api.wordpress.org/secret-key/1.1/salt/)
     - [Core Checksums](https://api.wordpress.org/core/checksums/1.0/)
   - **Privacy Policy**: [WordPress.org Privacy Policy](https://wordpress.org/about/privacy/)
   - **Terms of Use**: [WordPress.org Terms of Service](https://wordpress.org/about/terms-of-service/)
