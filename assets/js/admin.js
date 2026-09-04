/**
 * CMS ADMINS Security Check Report
 * Modern Vanilla JavaScript ES2022+
 */

(() => {
    'use strict';

    const config = window.cascr || window.cmsadmins_ajax || {};

    /**
     * Test Runner Module
     */
    class TestRunner {
        #tests = [];
        #testNames = {};
        #currentIndex = 0;
        #results = [];
        #isRunning = false;
        #abortController = null;

        constructor(tests, testNames) {
            this.#tests = tests || [];
            this.#testNames = testNames || {};
        }

        get totalTests() {
            return this.#tests.length;
        }

        get currentTest() {
            return this.#currentIndex;
        }

        get progress() {
            return this.totalTests > 0 ? (this.#currentIndex / this.totalTests) * 100 : 0;
        }

        get isRunning() {
            return this.#isRunning;
        }

        get results() {
            return [...this.#results];
        }

        async runAll(callbacks = {}) {
            if (this.#isRunning) return;

            this.#isRunning = true;
            this.#currentIndex = 0;
            this.#results = [];
            this.#abortController = new AbortController();

            const { onProgress, onResult, onComplete, onError } = callbacks;

            try {
                for (const testId of this.#tests) {
                    if (this.#abortController.signal.aborted) break;

                    const testName = this.#testNames[testId] || testId;
                    onProgress?.(this.#currentIndex, this.totalTests, testName);

                    try {
                        const result = await this.#runSingleTest(testId);
                        this.#results.push({ id: testId, name: testName, ...result });
                        onResult?.(testId, testName, result);
                    } catch (error) {
                        const errorResult = { result: config.i18n?.errorMessage || 'Error', score: 0 };
                        this.#results.push({ id: testId, name: testName, ...errorResult });
                        onError?.(testId, testName, error);
                    }

                    this.#currentIndex++;
                }

                onComplete?.(this.#results);
            } finally {
                this.#isRunning = false;
                this.#abortController = null;
            }
        }

        async #runSingleTest(testId) {
            const formData = new FormData();
            formData.append('action', 'run_security_check');
            formData.append('test_name', testId);
            formData.append('security_nonce', config.nonce || config.security_nonce);

            const response = await fetch(config.ajaxUrl || config.ajax_url, {
                method: 'POST',
                body: formData,
                signal: this.#abortController?.signal,
                credentials: 'same-origin',
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.data?.message || 'Test failed');
            }

            return data.data;
        }

        abort() {
            this.#abortController?.abort();
        }
    }

    /**
     * Results Renderer Module
     */
    class ResultsRenderer {
        #container;
        #tbody;

        constructor(tableId) {
            this.#container = document.getElementById(tableId);
            this.#tbody = document.getElementById(`${tableId.replace('-table', '')}-body`) ||
                          this.#container?.querySelector('tbody');
        }

        clear() {
            if (this.#tbody) {
                this.#tbody.innerHTML = '';
            }
        }

        addRow(testName, result, score) {
            if (!this.#tbody) return;

            const row = document.createElement('tr');
            row.className = this.#getRowClass(score);

            row.innerHTML = `
                <td class="cascr-table__cell cascr-table__cell--name">${this.#escapeHtml(testName)}</td>
                <td class="cascr-table__cell cascr-table__cell--result">${this.#escapeHtml(result)}</td>
                <td class="cascr-table__cell cascr-table__cell--score">${score}/10</td>
                <td class="cascr-table__cell cascr-table__cell--status">
                    <span class="cascr-status cascr-status--${this.#getStatusClass(score)}">${this.#getStatusLabel(score)}</span>
                </td>
            `;

            this.#tbody.appendChild(row);
        }

        #getRowClass(score) {
            if (score >= 7) return 'cascr-table__row cascr-table__row--critical';
            if (score >= 4) return 'cascr-table__row cascr-table__row--warning';
            return 'cascr-table__row cascr-table__row--success';
        }

        #getStatusClass(score) {
            if (score >= 7) return 'critical';
            if (score >= 4) return 'warning';
            return 'success';
        }

        #getStatusLabel(score) {
            if (score >= 7) return 'Critical';
            if (score >= 4) return 'Warning';
            return 'Passed';
        }

        #escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    }

    /**
     * Progress Bar Module
     */
    class ProgressBar {
        #container;
        #fill;
        #text;

        constructor(containerId) {
            this.#container = document.getElementById(containerId);
            this.#fill = document.getElementById(`${containerId}-fill`);
            this.#text = document.getElementById(`${containerId}-text`);
        }

        show() {
            this.#container?.removeAttribute('hidden');
        }

        hide() {
            this.#container?.setAttribute('hidden', '');
        }

        update(current, total, testName = '') {
            const percentage = total > 0 ? Math.round((current / total) * 100) : 0;

            if (this.#fill) {
                this.#fill.style.width = `${percentage}%`;
            }

            if (this.#container) {
                const progressbar = this.#container.querySelector('[role="progressbar"]');
                progressbar?.setAttribute('aria-valuenow', percentage.toString());
            }

            if (this.#text && testName) {
                const i18n = config.i18n || config;
                const label = i18n.runningCheck || i18n.running_check || 'Running';
                this.#text.innerHTML = `${label}<br><strong>${testName}</strong> (${current + 1}/${total})`;
            }
        }

        reset() {
            this.update(0, 1, '');
        }
    }

    /**
     * Clipboard Manager Module
     */
    class ClipboardManager {
        static async copy(text) {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(text);
                    return true;
                }
                return ClipboardManager.#fallbackCopy(text);
            } catch {
                return ClipboardManager.#fallbackCopy(text);
            }
        }

        static #fallbackCopy(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();

            try {
                document.execCommand('copy');
                return true;
            } catch {
                return false;
            } finally {
                document.body.removeChild(textarea);
            }
        }
    }

    /**
     * Accordion Search Module
     */
    class AccordionSearch {
        #container;
        #searchInput;
        #clearButton;
        #countDisplay;
        #noResults;
        #items = [];
        #totalCount = 0;
        #debounceTimer = null;

        constructor(containerId = 'cascr-accordion') {
            this.#container = document.getElementById(containerId);
            this.#searchInput = document.getElementById('cascr-accordion-search');
            this.#clearButton = document.getElementById('cascr-search-clear');
            this.#countDisplay = document.getElementById('cascr-search-count');
            this.#noResults = document.getElementById('cascr-no-results');

            if (!this.#container || !this.#searchInput) return;

            this.#items = Array.from(this.#container.querySelectorAll('.cascr-accordion__item'));
            this.#totalCount = this.#items.length;

            this.#bindEvents();
        }

        #bindEvents() {
            // Search input with debounce
            this.#searchInput?.addEventListener('input', () => {
                clearTimeout(this.#debounceTimer);
                this.#debounceTimer = setTimeout(() => this.#performSearch(), 150);
                this.#updateClearButton();
            });

            // Clear button
            this.#clearButton?.addEventListener('click', () => {
                this.#searchInput.value = '';
                this.#performSearch();
                this.#updateClearButton();
                this.#searchInput.focus();
            });

            // Keyboard shortcut: Escape to clear
            this.#searchInput?.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    this.#searchInput.value = '';
                    this.#performSearch();
                    this.#updateClearButton();
                }
            });
        }

        #performSearch() {
            const query = this.#searchInput.value.toLowerCase().trim();
            let visibleCount = 0;

            this.#items.forEach(item => {
                const searchText = item.dataset.searchText || '';
                const titleElement = item.querySelector('.cascr-accordion__title');
                const originalTitle = titleElement?.textContent || '';

                if (!query) {
                    // No search query - show all items
                    item.hidden = false;
                    visibleCount++;
                    // Remove highlight
                    if (titleElement) {
                        titleElement.innerHTML = this.#escapeHtml(originalTitle);
                    }
                } else if (searchText.includes(query)) {
                    // Match found
                    item.hidden = false;
                    visibleCount++;
                    // Highlight matching text in title
                    if (titleElement) {
                        titleElement.innerHTML = this.#highlightText(originalTitle, query);
                    }
                } else {
                    // No match
                    item.hidden = true;
                    // Remove highlight
                    if (titleElement) {
                        titleElement.innerHTML = this.#escapeHtml(originalTitle);
                    }
                }
            });

            // Update count display
            if (this.#countDisplay) {
                this.#countDisplay.textContent = visibleCount;
            }

            // Show/hide no results message
            if (this.#noResults) {
                this.#noResults.hidden = visibleCount > 0 || !query;
            }

            // Hide accordion border when no results
            if (this.#container) {
                this.#container.style.display = (visibleCount === 0 && query) ? 'none' : '';
            }
        }

        #updateClearButton() {
            if (this.#clearButton) {
                this.#clearButton.hidden = !this.#searchInput.value;
            }
        }

        #highlightText(text, query) {
            const escaped = this.#escapeHtml(text);
            const regex = new RegExp(`(${this.#escapeRegex(query)})`, 'gi');
            return escaped.replace(regex, '<mark>$1</mark>');
        }

        #escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        #escapeRegex(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
    }

    /**
     * Report Generator Module
     */
    class ReportGenerator {
        #results = [];

        // Category weights for weighted scoring
        static CATEGORY_WEIGHTS = {
            critical: 3.0,
            high: 2.0,
            medium: 1.5,
            low: 1.0
        };

        // Test categories
        static TEST_CATEGORIES = {
            critical: [
                'malware_check', 'php_execution', 'weak_password_users', 'two_factor',
                'admin_username', 'database_user_privileges',
                'wp_config', 'unallowed_files'
            ],
            high: [
                'wordpress_version', 'outdated_plugins', 'ssl', 'file_edit',
                'brute_force', 'automatic_core_updates', 'php_version',
                'php_version_support', 'security_keys_salts', 'core_file_integrity'
            ],
            medium: [
                'server_headers', 'directory_permissions', 'uploads_permissions',
                'wp_debug', 'password_policy', 'login_attempts', 'user_enumeration',
                'outdated_themes', 'outdated_libraries', 'debug_log_exposure',
                'cors_configuration', 'wp_cron_security'
            ],
            low: [
                'db_prefix', 'xmlrpc', 'xmlrpc_methods', 'rest_api', 'legacy_meta_exposure',
                'deactivated_plugins', 'htaccess', 'directory_indexing', 'unwanted_files_root',
                'other_wp_installs', 'database_structure', 'backup', 'security_plugins',
                'php_version_in_headers', 'application_passwords'
            ]
        };

        // Risk grades
        static RISK_GRADES = {
            A: { max: 10, label: 'Excellent', color: '#22c55e' },
            B: { max: 25, label: 'Good', color: '#84cc16' },
            C: { max: 40, label: 'Moderate', color: '#eab308' },
            D: { max: 60, label: 'Poor', color: '#f97316' },
            F: { max: 100, label: 'Critical', color: '#ef4444' }
        };

        setResults(results) {
            this.#results = results;
        }

        #getTestCategory(testId) {
            for (const [category, tests] of Object.entries(ReportGenerator.TEST_CATEGORIES)) {
                if (tests.includes(testId)) return category;
            }
            return 'low';
        }

        #calculateWeightedScore() {
            let weightedScore = 0;
            let totalWeight = 0;
            let hasCriticalFailure = false;
            const criticalFailures = [];
            const categoryStats = {
                critical: { score: 0, max: 0, count: 0, issues: [] },
                high: { score: 0, max: 0, count: 0, issues: [] },
                medium: { score: 0, max: 0, count: 0, issues: [] },
                low: { score: 0, max: 0, count: 0, issues: [] }
            };

            for (const result of this.#results) {
                const category = this.#getTestCategory(result.id);
                const weight = ReportGenerator.CATEGORY_WEIGHTS[category];
                const score = result.score || 0;

                weightedScore += score * weight;
                totalWeight += 10 * weight;

                categoryStats[category].score += score;
                categoryStats[category].max += 10;
                categoryStats[category].count++;

                if (score >= 4) {
                    categoryStats[category].issues.push({
                        name: result.name,
                        result: result.result,
                        score: score
                    });
                }

                if (category === 'critical' && score >= 8) {
                    hasCriticalFailure = true;
                    criticalFailures.push(result.name);
                }
            }

            let percentage = totalWeight > 0 ? (weightedScore / totalWeight) * 100 : 0;

            // Critical failure penalty
            if (hasCriticalFailure && percentage < 41) {
                percentage = 41;
            }

            return { percentage, hasCriticalFailure, criticalFailures, categoryStats };
        }

        #getRiskGrade(percentage) {
            for (const [letter, grade] of Object.entries(ReportGenerator.RISK_GRADES)) {
                if (percentage <= grade.max) {
                    return { grade: letter, ...grade };
                }
            }
            return { grade: 'F', ...ReportGenerator.RISK_GRADES.F };
        }

        generate() {
            const weighted = this.#calculateWeightedScore();
            const gradeInfo = this.#getRiskGrade(weighted.percentage);

            let report = '╔══════════════════════════════════════════════════════════════╗\n';
            report += '║       CMS ADMINS Security Check Report                       ║\n';
            report += '╚══════════════════════════════════════════════════════════════╝\n\n';
            report += `Generated: ${new Date().toLocaleString()}\n\n`;

            report += '┌──────────────────────────────────────────────────────────────┐\n';
            report += `│  SECURITY GRADE: ${gradeInfo.grade} (${gradeInfo.label})`.padEnd(63) + '│\n';
            report += `│  Risk Score: ${weighted.percentage.toFixed(1)}%`.padEnd(63) + '│\n';
            report += '└──────────────────────────────────────────────────────────────┘\n\n';

            report += '═══ TEST RESULTS ═══\n\n';

            for (const { name, result, score } of this.#results) {
                const status = score >= 7 ? '❌ CRITICAL' : score >= 4 ? '⚠️ WARNING' : '✅ PASSED';
                report += `${status} | ${name}\n`;
                report += `   Result: ${result}\n`;
                report += `   Score: ${score}/10\n\n`;
            }

            const summary = this.#calculateSummary();
            report += '═══ SUMMARY ═══\n';
            report += `Security Grade: ${gradeInfo.grade} (${gradeInfo.label})\n`;
            report += `Risk Score: ${weighted.percentage.toFixed(1)}%\n`;
            report += `Tests Passed: ${summary.passing}/${summary.total}\n`;
            report += `Critical Issues: ${summary.critical}\n`;
            report += `Warnings: ${summary.warnings}\n`;

            return report;
        }

        #calculateSummary() {
            const total = this.#results.length;
            const scores = this.#results.map(r => r.score || 0);
            const sum = scores.reduce((a, b) => a + b, 0);
            const average = total > 0 ? sum / total : 0;
            const passing = this.#results.filter(r => (r.score || 0) < 4).length;
            const warnings = this.#results.filter(r => (r.score || 0) >= 4 && (r.score || 0) < 7).length;
            const critical = this.#results.filter(r => (r.score || 0) >= 7).length;

            return { total, average, passing, warnings, critical };
        }

        getSummaryHtml() {
            const weighted = this.#calculateWeightedScore();
            const gradeInfo = this.#getRiskGrade(weighted.percentage);
            const summary = this.#calculateSummary();

            // Collect issues by severity
            const criticalIssues = this.#results.filter(r => (r.score || 0) >= 7);
            const warningIssues = this.#results.filter(r => (r.score || 0) >= 4 && (r.score || 0) < 7);

            return `
                <div class="cascr-final-evaluation">
                    <div class="cascr-grade-display" style="--grade-color: ${gradeInfo.color}">
                        <div class="cascr-grade-circle">
                            <span class="cascr-grade-letter">${gradeInfo.grade}</span>
                            <span class="cascr-grade-label">${gradeInfo.label}</span>
                        </div>
                        <div class="cascr-grade-details">
                            <div class="cascr-risk-score">
                                <span class="cascr-risk-value">${weighted.percentage.toFixed(1)}%</span>
                                <span class="cascr-risk-label">Risk Score</span>
                            </div>
                            <div class="cascr-test-stats">
                                <span class="cascr-stat cascr-stat--passed">${summary.passing} Passed</span>
                                <span class="cascr-stat cascr-stat--warning">${summary.warnings} Warnings</span>
                                <span class="cascr-stat cascr-stat--critical">${summary.critical} Critical</span>
                            </div>
                        </div>
                    </div>

                    <div class="cascr-evaluation-text">
                        <h3>Security Assessment Summary</h3>
                        ${this.#generateEvaluationText(gradeInfo, weighted, summary, criticalIssues, warningIssues)}
                    </div>

                    ${criticalIssues.length > 0 ? `
                    <div class="cascr-issues-section cascr-issues--critical">
                        <h4>🚨 Critical Issues Requiring Immediate Attention</h4>
                        <ul>
                            ${criticalIssues.map(i => `<li><strong>${i.name}:</strong> ${i.result}</li>`).join('')}
                        </ul>
                    </div>
                    ` : ''}

                    ${warningIssues.length > 0 ? `
                    <div class="cascr-issues-section cascr-issues--warning">
                        <h4>⚠️ Warnings - Recommended Improvements</h4>
                        <ul>
                            ${warningIssues.map(i => `<li><strong>${i.name}:</strong> ${i.result}</li>`).join('')}
                        </ul>
                    </div>
                    ` : ''}
                </div>
            `;
        }

        #generateEvaluationText(gradeInfo, weighted, summary, criticalIssues, warningIssues) {
            const date = new Date().toLocaleDateString('de-DE', {
                year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
            });

            let text = `<p>This security audit was conducted on <strong>${date}</strong> and evaluated <strong>${summary.total} security aspects</strong> of your WordPress installation.</p>`;

            // Grade-specific assessment
            switch(gradeInfo.grade) {
                case 'A':
                    text += `<p class="cascr-assessment cascr-assessment--excellent">Your WordPress installation demonstrates <strong>excellent security practices</strong>. All critical security measures are properly implemented and maintained. Continue monitoring and keep all components updated.</p>`;
                    break;
                case 'B':
                    text += `<p class="cascr-assessment cascr-assessment--good">Your WordPress installation has <strong>good security</strong> overall. Minor improvements are recommended to achieve optimal protection. Address the identified warnings when convenient.</p>`;
                    break;
                case 'C':
                    text += `<p class="cascr-assessment cascr-assessment--moderate">Your WordPress installation has <strong>moderate security</strong>. Several improvements are recommended to better protect your site. Review the warnings and plan to address them in the near future.</p>`;
                    break;
                case 'D':
                    text += `<p class="cascr-assessment cascr-assessment--poor">Your WordPress installation has <strong>significant security vulnerabilities</strong>. Immediate action is required to address critical issues. Your site may be at risk of compromise.</p>`;
                    break;
                case 'F':
                    text += `<p class="cascr-assessment cascr-assessment--critical"><strong>⚠️ URGENT:</strong> Your WordPress installation has <strong>critical security vulnerabilities</strong>. Immediate action is required. Your site is at high risk of being compromised. Address all critical issues as soon as possible.</p>`;
                    break;
            }

            // Statistics
            text += `<p class="cascr-stats-summary">`;
            text += `<strong>Test Results:</strong> ${summary.passing} tests passed successfully, `;
            if (summary.critical > 0) {
                text += `<span class="cascr-highlight--critical">${summary.critical} critical issue${summary.critical > 1 ? 's' : ''}</span> detected`;
            }
            if (summary.warnings > 0) {
                text += `${summary.critical > 0 ? ' and ' : ''}<span class="cascr-highlight--warning">${summary.warnings} warning${summary.warnings > 1 ? 's' : ''}</span> identified`;
            }
            if (summary.critical === 0 && summary.warnings === 0) {
                text += `no issues detected`;
            }
            text += `.</p>`;

            // Critical failure notice
            if (weighted.hasCriticalFailure) {
                text += `<p class="cascr-critical-notice"><strong>Note:</strong> Due to critical security failures in essential areas, the minimum grade has been adjusted. Address these issues immediately to improve your security rating.</p>`;
            }

            return text;
        }
    }

    /**
     * Main Application
     */
    class SecurityCheckApp {
        #testRunner;
        #renderer;
        #progressBar;
        #reportGenerator;
        #accordionSearch;
        #elements = {};

        constructor() {
            const tests = config.tests?.list || [];
            const testNames = config.tests?.names || {};

            this.#testRunner = new TestRunner(tests, testNames);
            this.#renderer = new ResultsRenderer('cascr-results-table');
            this.#progressBar = new ProgressBar('cascr-progress');
            this.#reportGenerator = new ReportGenerator();
            this.#accordionSearch = new AccordionSearch('cascr-accordion');

            this.#cacheElements();
            this.#bindEvents();
        }

        #cacheElements() {
            this.#elements = {
                controls: document.getElementById('cascr-controls'),
                results: document.getElementById('cascr-results'),
                report: document.getElementById('cascr-report'),
                disclaimer: document.getElementById('cascr-disclaimer-checkbox'),
                startButton: document.getElementById('cascr-start-tests'),
                copyButton: document.getElementById('cascr-copy-report'),
                reportText: document.getElementById('cascr-report-text'),
                summary: document.getElementById('cascr-summary'),
                // Legacy element IDs for backwards compatibility
                legacyCheckbox: document.getElementById('disclaimer-checkbox'),
                legacyStart: document.getElementById('start-tests'),
                legacyCopy: document.getElementById('copy-report'),
                legacyReport: document.getElementById('final-report'),
                legacySummary: document.getElementById('final-summary'),
                legacyResults: document.getElementById('security-check-results'),
                legacyResultsBody: document.getElementById('results-body'),
                legacyLoader: document.getElementById('security-check-loader'),
                legacyWrap: document.getElementById('security-check-wrap'),
                legacyReportContainer: document.getElementById('final-report-container'),
            };
        }

        #bindEvents() {
            const checkbox = this.#elements.disclaimer || this.#elements.legacyCheckbox;
            const startBtn = this.#elements.startButton || this.#elements.legacyStart;
            const copyBtn = this.#elements.copyButton || this.#elements.legacyCopy;

            checkbox?.addEventListener('change', (e) => {
                if (startBtn) startBtn.disabled = !e.target.checked;
            });

            startBtn?.addEventListener('click', () => this.#startTests());
            copyBtn?.addEventListener('click', () => this.#copyReport());
        }

        async #startTests() {
            const startBtn = this.#elements.startButton || this.#elements.legacyStart;
            if (startBtn) startBtn.disabled = true;

            this.#showProgress();
            this.#renderer.clear();

            // Also clear legacy results
            if (this.#elements.legacyResultsBody) {
                this.#elements.legacyResultsBody.innerHTML = '';
            }

            await this.#testRunner.runAll({
                onProgress: (current, total, testName) => {
                    this.#progressBar.update(current, total, testName);
                    this.#updateLegacyProgress(current, total, testName);
                },
                onResult: (id, name, result) => {
                    this.#renderer.addRow(name, result.result, result.score);
                    this.#addLegacyRow(name, result.result, result.score);
                },
                onError: (id, name) => {
                    const errorMsg = config.i18n?.errorMessage || config.error_message || 'Error';
                    this.#renderer.addRow(name, errorMsg, 0);
                    this.#addLegacyRow(name, errorMsg, 0);
                },
                onComplete: (results) => this.#onTestsComplete(results),
            });
        }

        #showProgress() {
            this.#progressBar.show();

            // Legacy support
            if (this.#elements.legacyLoader) {
                this.#elements.legacyLoader.style.display = 'block';
            }
        }

        #updateLegacyProgress(current, total, testName) {
            const loaderText = document.getElementById('loader-text');
            const progress = document.getElementById('progress');

            if (loaderText) {
                const label = config.running_check || config.i18n?.runningCheck || 'Running security check';
                loaderText.innerHTML = `${label}<strong>${testName} (${current + 1}/${total})</strong>`;
            }

            if (progress) {
                const percentage = ((current / total) * 100).toFixed(2);
                progress.style.width = `${percentage}%`;
            }
        }

        #addLegacyRow(testName, result, score) {
            const tbody = this.#elements.legacyResultsBody;
            if (!tbody) return;

            const statusClass = score >= 7 ? 'critical' : score >= 4 ? 'warning' : 'success';
            const statusLabel = score >= 7 ? 'Critical' : score >= 4 ? 'Warning' : 'Passed';
            const row = document.createElement('tr');
            row.className = `cascr-table__row cascr-table__row--${statusClass}`;

            const nameCell = document.createElement('td');
            nameCell.textContent = testName;
            row.appendChild(nameCell);

            const resultCell = document.createElement('td');
            resultCell.textContent = result;
            row.appendChild(resultCell);

            const scoreCell = document.createElement('td');
            scoreCell.textContent = `${score}/10`;
            row.appendChild(scoreCell);

            const statusCell = document.createElement('td');
            const statusSpan = document.createElement('span');
            statusSpan.className = `cascr-status cascr-status--${statusClass}`;
            statusSpan.textContent = statusLabel;
            statusCell.appendChild(statusSpan);
            row.appendChild(statusCell);

            tbody.appendChild(row);
        }

        #onTestsComplete(results) {
            this.#progressBar.hide();
            this.#reportGenerator.setResults(results);

            const report = this.#reportGenerator.generate();

            // Modern UI
            if (this.#elements.results) {
                this.#elements.results.removeAttribute('hidden');
            }
            if (this.#elements.report) {
                this.#elements.report.removeAttribute('hidden');
            }
            if (this.#elements.reportText) {
                this.#elements.reportText.value = report;
            }
            if (this.#elements.summary) {
                this.#elements.summary.innerHTML = this.#reportGenerator.getSummaryHtml();
            }
            if (this.#elements.controls) {
                this.#elements.controls.setAttribute('hidden', '');
            }

            // Legacy UI - Set summary HTML on legacy element as well
            if (this.#elements.legacySummary) {
                this.#elements.legacySummary.innerHTML = this.#reportGenerator.getSummaryHtml();
            }
            if (this.#elements.legacyWrap) {
                this.#elements.legacyWrap.style.display = 'none';
            }
            if (this.#elements.legacyLoader) {
                this.#elements.legacyLoader.style.display = 'none';
            }
            if (this.#elements.legacyResults) {
                this.#elements.legacyResults.style.display = 'table';
            }
            if (this.#elements.legacyReportContainer) {
                this.#elements.legacyReportContainer.style.display = 'block';
            }
            if (this.#elements.legacyReport) {
                this.#elements.legacyReport.value = report;
            }

            const startBtn = this.#elements.startButton || this.#elements.legacyStart;
            if (startBtn) {
                startBtn.style.display = 'none';
            }
        }

        async #copyReport() {
            const textarea = this.#elements.reportText || this.#elements.legacyReport;
            if (!textarea) return;

            const success = await ClipboardManager.copy(textarea.value);
            const message = success
                ? (config.i18n?.copySuccess || config.copy_report_text || 'Copied!')
                : (config.i18n?.copyError || 'Failed to copy');

            this.#showNotification(message, success ? 'success' : 'error');
        }

        #showNotification(message, type = 'info') {
            // Simple alert for now, can be enhanced with a toast notification
            alert(message);
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => new SecurityCheckApp());
    } else {
        new SecurityCheckApp();
    }
})();
