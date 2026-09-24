/**
 * CMS ADMINS Security Check Report
 *
 * The page itself is rendered in PHP, and every action that changes something
 * reloads it rather than patching the markup back into agreement. What is left
 * here is what a stored run cannot do on its own: run the checks, trigger a
 * re-check, filter the list, search the documentation and hand the report out
 * as a file.
 */
(() => {
    'use strict';

    const config = window.cascr || {};
    const i18n = config.i18n || {};
    const tests = config.tests || {};
    const categories = config.categories || {};
    const severities = config.severities || {};

    const STATUS = {
        pass: 'pass',
        warn: 'warn',
        fail: 'fail',
        inconclusive: 'inconclusive',
    };

    const priorities = Array.isArray(config.priorities) ? config.priorities : [];

    const statusLabel = (status) => ({
        pass: i18n.statusPass,
        warn: i18n.statusWarn,
        fail: i18n.statusFail,
        inconclusive: i18n.statusUnknown,
    }[status] || status);

    /**
     * The status as an export has to spell it out.
     *
     * A muted finding keeps its own status in the stored run, so without the
     * addition the file says "Failed" about something the report page counts as
     * settled and the totals above it stop adding up.
     */
    const statusText = (result) => (result.ignored
        ? `${statusLabel(result.status)} (${i18n.statusMuted})`
        : statusLabel(result.status));

    /**
     * Comes back on the given anchor.
     *
     * The page is built from the stored run, so a second renderer in here would
     * only ever be the half of it somebody forgets to keep in step. The anchor
     * is what keeps the reload from throwing the reader back to the top.
     */
    const reloadTo = (anchor) => {
        window.location.hash = anchor;
        window.location.reload();
    };

    const announce = (message) => {
        if (window.wp && window.wp.a11y && typeof window.wp.a11y.speak === 'function') {
            window.wp.a11y.speak(message);
        }
    };

    const el = (tag, className, text) => {
        const node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined && text !== null) {
            node.textContent = String(text);
        }
        return node;
    };

    const sprintf = (template, ...values) => {
        let index = 0;
        return String(template || '')
            .replace(/%(\d+)\$[ds]/g, (match, position) => values[Number(position) - 1])
            .replace(/%[ds]/g, () => values[index++]);
    };

    /**
     * Talks to the cascr/v1 routes.
     */
    class Api {
        static async request(path, options = {}) {
            const response = await fetch(`${config.root}${path}`, {
                credentials: 'same-origin',
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': config.nonce,
                    ...(options.headers || {}),
                },
            });

            if (!response.ok) {
                const body = await response.json().catch(() => ({}));
                throw new Error(body.message || `HTTP ${response.status}`);
            }

            return response.json();
        }

        static runTest(id, signal) {
            return Api.request(`/run/${encodeURIComponent(id)}`, { method: 'POST', signal });
        }

        static recheck(id) {
            return Api.request(`/recheck/${encodeURIComponent(id)}`, { method: 'POST' });
        }

        static saveReport(results) {
            return Api.request('/report', {
                method: 'POST',
                body: JSON.stringify({ results }),
            });
        }

        static report() {
            return Api.request('/report');
        }

        static consent() {
            return Api.request('/consent', { method: 'POST' });
        }

        static setIgnore(id, ignore) {
            return Api.request('/ignore', {
                method: 'POST',
                body: JSON.stringify({ id, ignore }),
            });
        }
    }

    /**
     * Runs the checks, a few at a time.
     *
     * Strictly sequential requests made a full run take as long as the slowest
     * chain of them. A small concurrency limit keeps the progress readable
     * without hammering the site the checks are inspecting.
     */
    class TestRunner {
        #ids;
        #limit;
        #controller = null;

        constructor(ids, limit) {
            this.#ids = ids;
            this.#limit = Math.max(1, Number(limit) || 1);
        }

        async run({ onProgress }) {
            this.#controller = new AbortController();

            const results = {};
            const queue = [...this.#ids];
            const total = queue.length;
            let done = 0;

            const worker = async () => {
                while (queue.length) {
                    if (this.#controller.signal.aborted) {
                        return;
                    }

                    const id = queue.shift();

                    let result;
                    try {
                        result = await Api.runTest(id, this.#controller.signal);
                    } catch (error) {
                        result = {
                            id,
                            status: STATUS.inconclusive,
                            score: 0,
                            summary: i18n.error,
                            items: [],
                            fix: '',
                            ignored: false,
                        };
                    }

                    results[id] = result;
                    done += 1;

                    onProgress(done, total, id);
                }
            };

            await Promise.all(
                Array.from({ length: Math.min(this.#limit, total) }, () => worker())
            );

            this.#controller = null;

            return results;
        }

        abort() {
            if (this.#controller) {
                this.#controller.abort();
            }
        }
    }

    /**
     * Turns a stored run into text, JSON and CSV.
     */
    class Exporter {
        constructor(results, summary) {
            this.results = results;
            this.summary = summary;
        }

        get filename() {
            const date = new Date().toISOString().slice(0, 10);
            return `security-check-${date}`;
        }

        text() {
            const grade = this.summary.grade;
            const counts = this.summary.counts;
            const lines = [];

            lines.push(i18n.reportTitle);
            lines.push('='.repeat(i18n.reportTitle.length));
            lines.push('');
            lines.push(`${config.siteName} (${config.siteUrl})`);
            lines.push(`${i18n.generatedOn}: ${new Date().toLocaleString()}`);
            lines.push('');
            lines.push(`${i18n.grade}: ${grade} (${(config.grades || {})[grade] || ''})`);
            lines.push(`${i18n.riskScore}: ${this.summary.risk}%`);
            lines.push(
                `${i18n.summary}: ${counts.pass} ${i18n.statusPass}, ` +
                `${counts.warn} ${i18n.statusWarn}, ${counts.fail} ${i18n.statusFail}, ` +
                `${counts.inconclusive} ${i18n.statusUnknown}`
            );
            lines.push('');

            // A finding that has been sent away is not a to-do. The list is
            // scored on the server and reaches us with the page, so a mute
            // recorded since then is filtered out against the run itself.
            const todo = (this.summary.priorities || [])
                .filter((item) => !(this.results[item.id] || {}).ignored);

            if (todo.length) {
                lines.push(i18n.nextActions);
                lines.push('-'.repeat(i18n.nextActions.length));
                todo.forEach((item, index) => {
                    lines.push(`${index + 1}. ${item.label}: ${item.summary}`);
                    if (item.fix) {
                        lines.push(`   ${item.fix}`);
                    }
                });
                lines.push('');
            }

            lines.push(i18n.checks);
            lines.push('-'.repeat(i18n.checks.length));

            Object.keys(this.results).forEach((id) => {
                const result = this.results[id];
                const label = (tests[id] || {}).label || id;
                lines.push(`[${statusText(result)}] ${label}`);
                lines.push(`  ${result.summary}`);
                (result.items || []).forEach((item) => lines.push(`  - ${item}`));
                if (result.fix) {
                    lines.push(`  ${i18n.recommendation}: ${result.fix}`);
                }
                lines.push('');
            });

            return lines.join('\n');
        }

        json() {
            return JSON.stringify(
                {
                    site: { name: config.siteName, url: config.siteUrl },
                    generated: new Date().toISOString(),
                    summary: this.summary,
                    results: this.results,
                },
                null,
                2
            );
        }

        csv() {
            const escape = (value) => `"${String(value).replace(/"/g, '""')}"`;
            const rows = [(i18n.csvColumns || []).map(escape).join(',')];

            Object.keys(this.results).forEach((id) => {
                const result = this.results[id];
                const test = tests[id] || {};
                const detail = [result.summary, ...(result.items || [])].join(' | ');

                rows.push([
                    escape(test.label || id),
                    escape(categories[test.category] || test.category || ''),
                    escape(severities[test.severity] || test.severity || ''),
                    escape(statusText(result)),
                    result.score,
                    escape(detail),
                ].join(','));
            });

            return rows.join('\n');
        }

        static download(content, filename, type) {
            const blob = new Blob([content], { type: `${type};charset=utf-8` });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');

            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            URL.revokeObjectURL(url);
        }
    }

    const openDoc = (id) => {
        const doc = document.getElementById(`cascr-doc-${id}`);
        if (doc) {
            doc.open = true;
        }
    };

    const copyText = async (text) => {
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch (error) {
                // Fall through to the textarea approach below.
            }
        }

        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', 'readonly');
        area.style.cssText = 'position:fixed;left:-9999px;top:0';
        document.body.appendChild(area);
        area.select();

        let ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (error) {
            ok = false;
        } finally {
            document.body.removeChild(area);
        }

        return ok;
    };

    const notify = (message, type) => {
        const app = document.getElementById('cascr-app');
        if (!app) {
            return;
        }

        const existing = app.querySelector('.cascr-notice');
        if (existing) {
            existing.remove();
        }

        const notice = el('div', `notice notice-${type === 'error' ? 'error' : 'success'} is-dismissible cascr-notice`);
        notice.appendChild(el('p', null, message));
        app.insertBefore(notice, app.firstChild);

        window.setTimeout(() => notice.remove(), 6000);
    };

    /**
     * Filters the documentation list as you type.
     */
    class DocSearch {
        constructor() {
            this.input = document.getElementById('cascr-doc-search');
            this.count = document.getElementById('cascr-doc-count');
            this.empty = document.getElementById('cascr-doc-empty');
            this.items = Array.from(document.querySelectorAll('.cascr-doc'));
            this.groups = Array.from(document.querySelectorAll('.cascr-docs__group'));

            if (!this.input) {
                return;
            }

            let timer = null;
            this.input.addEventListener('input', () => {
                window.clearTimeout(timer);
                timer = window.setTimeout(() => this.filter(), 150);
            });

            this.input.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    this.input.value = '';
                    this.filter();
                }
            });
        }

        filter() {
            const query = this.input.value.trim().toLowerCase();
            let visible = 0;

            this.items.forEach((item) => {
                const match = !query || (item.dataset.search || '').includes(query);
                item.hidden = !match;
                if (match) {
                    visible += 1;
                }
            });

            this.groups.forEach((group) => {
                group.hidden = !group.querySelector('.cascr-doc:not([hidden])');
            });

            if (this.count) {
                this.count.textContent = String(visible);
            }

            if (this.empty) {
                this.empty.hidden = visible > 0;
            }
        }
    }

    /**
     * The filter chips above the full list.
     *
     * The counts come from the server with the markup. Muting reloads the
     * page, so there is never a moment where they disagree with the rows.
     */
    class Filters {
        constructor() {
            this.bar = document.getElementById('cascr-filters');
            this.empty = document.getElementById('cascr-results-empty');
            this.rows = Array.from(document.querySelectorAll('[data-cascr-row]'));
            this.groups = Array.from(document.querySelectorAll('[data-cascr-group]'));
            this.active = 'all';

            if (!this.bar) {
                return;
            }

            this.bar.addEventListener('click', (event) => {
                const button = event.target.closest('[data-cascr-filter]');
                if (button) {
                    this.active = button.dataset.cascrFilter;
                    this.apply();
                }
            });
        }

        apply() {
            if (!this.bar) {
                return;
            }

            let visible = 0;

            this.rows.forEach((row) => {
                const match = this.active === 'all' || row.dataset.cascrStatus === this.active;
                row.hidden = !match;
                if (match) {
                    visible += 1;
                }
            });

            this.groups.forEach((group) => {
                group.hidden = !group.querySelector('[data-cascr-row]:not([hidden])');
            });

            if (this.empty) {
                this.empty.hidden = visible > 0;
            }

            this.bar.querySelectorAll('[data-cascr-filter]').forEach((button) => {
                const on = button.dataset.cascrFilter === this.active;
                button.classList.toggle('is-active', on);
                button.setAttribute('aria-pressed', String(on));
            });
        }

    }

    /**
     * The checklist, the re-check and everything that hangs off a stored run.
     */
    class Dashboard {
        constructor() {
            this.filters = new Filters();
            this.busy = false;

            document.addEventListener('click', (event) => this.#dispatch(event));
        }

        #dispatch(event) {
            const doc = event.target.closest('[data-cascr-doc]');
            if (doc) {
                openDoc(doc.dataset.cascrDoc);
                return;
            }

            const recheck = event.target.closest('[data-cascr-recheck]');
            if (recheck) {
                this.#recheck(recheck);
                return;
            }

            const later = event.target.closest('[data-cascr-later]');
            if (later) {
                this.#later(later);
                return;
            }

            const mute = event.target.closest('[data-cascr-mute]');
            if (mute) {
                this.#mute(mute);
                return;
            }

            const exportButton = event.target.closest('[data-cascr-export]');
            if (exportButton) {
                this.#export(exportButton);
            }
        }

        /**
         * Locks every task button while one check is being re-checked.
         *
         * Two re-checks answered at the same time both write the run, and the
         * one that finished first is simply gone. The server keeps its own
         * window as narrow as it can; this closes the one the interface opens.
         */
        #lock(on) {
            this.busy = on;

            document.querySelectorAll('[data-cascr-recheck], [data-cascr-later]')
                .forEach((button) => {
                    button.disabled = on;
                });
        }

        /**
         * Checks one task again. The outcome is recorded in the run, so the
         * reloaded page can report it to everyone, not just to a screen reader.
         */
        async #recheck(button) {
            if (this.busy) {
                return;
            }

            const caption = button.textContent;

            this.#lock(true);
            button.textContent = i18n.taskChecking;

            try {
                await Api.recheck(button.dataset.cascrRecheck);
                reloadTo('cascr-recheck');
            } catch (error) {
                notify(error.message || i18n.error, 'error');
                this.#lock(false);
                button.textContent = caption;
            }
        }

        /**
         * Mutes a task until its finding says something else.
         */
        async #later(button) {
            if (this.busy) {
                return;
            }

            this.#lock(true);

            try {
                await Api.setIgnore(button.dataset.cascrLater, true);
                reloadTo('cascr-tasks');
            } catch (error) {
                notify(error.message || i18n.error, 'error');
                this.#lock(false);
            }
        }

        /**
         * Mutes or unmutes a finding in the full list.
         *
         * The mute moves the grade, the verdict, the chips, the checklist and
         * the menu bubble along with the row. The page comes back on the row
         * itself, so none of that has to be kept in step twice.
         */
        async #mute(button) {
            const row = button.closest('[data-cascr-row]');
            if (!row) {
                return;
            }

            button.disabled = true;

            try {
                await Api.setIgnore(button.dataset.cascrMute, row.dataset.cascrStatus !== 'ignored');
                reloadTo(row.id);
            } catch (error) {
                notify(error.message || i18n.error, 'error');
                button.disabled = false;
            }
        }

        async #export(button) {
            const format = button.dataset.cascrExport;

            button.disabled = true;

            try {
                const data = await Api.report();

                if (!data || !data.run) {
                    return;
                }

                const exporter = new Exporter(data.run.tests, {
                    grade: data.run.grade,
                    risk: data.run.risk,
                    counts: data.run.counts,
                    priorities,
                });

                if (format === 'copy') {
                    const ok = await copyText(exporter.text());
                    announce(ok ? i18n.copied : i18n.copyFailed);
                    notify(ok ? i18n.copied : i18n.copyFailed, ok ? 'success' : 'error');
                    return;
                }

                const files = {
                    text: [exporter.text(), `${exporter.filename}.txt`, 'text/plain'],
                    json: [exporter.json(), `${exporter.filename}.json`, 'application/json'],
                    csv: [exporter.csv(), `${exporter.filename}.csv`, 'text/csv'],
                };

                if (files[format]) {
                    Exporter.download(...files[format]);
                }
            } catch (error) {
                notify(error.message || i18n.error, 'error');
            } finally {
                button.disabled = false;
            }
        }
    }

    /**
     * The full pass.
     */
    class Runner {
        constructor() {
            this.button = document.getElementById('cascr-run');
            this.consent = document.getElementById('cascr-consent');
            this.hint = document.getElementById('cascr-launch-hint');
            this.progress = document.getElementById('cascr-progress');
            this.bar = document.getElementById('cascr-progress-bar');
            this.label = document.getElementById('cascr-progress-label');

            if (!this.button) {
                return;
            }

            if (this.consent) {
                this.consent.addEventListener('change', (event) => {
                    const ready = event.target.checked;
                    this.button.disabled = !ready;
                    if (this.hint) {
                        this.hint.hidden = ready;
                    }
                });
            }

            this.button.addEventListener('click', () => this.start());
        }

        async start() {
            const ids = Object.keys(tests);

            this.button.disabled = true;
            this.progress.hidden = false;
            if (this.hint) {
                this.hint.hidden = true;
            }
            this.setProgress(0, ids.length, '');

            if (this.consent && this.consent.checked) {
                await Api.consent().catch(() => {});
            }

            const results = await new TestRunner(ids, config.concurrency).run({
                onProgress: (done, total, id) => this.setProgress(done, total, id),
            });

            try {
                await Api.saveReport(results);
            } catch (error) {
                this.progress.hidden = true;
                this.button.disabled = false;
                notify(error.message || i18n.error, 'error');
                return;
            }

            announce(i18n.scanFinished);

            // The run is stored by now, and the page is built from the stored
            // run. Reloading is cheaper than a second renderer in here.
            window.location.reload();
        }

        setProgress(done, total, id) {
            const percent = total ? Math.round((done / total) * 100) : 0;
            this.bar.style.width = `${percent}%`;

            const label = id && tests[id] ? tests[id].label : '';
            this.label.textContent = label
                ? `${sprintf(i18n.progress, done, total)}: ${label}`
                : sprintf(i18n.progress, done, total);
        }
    }

    const boot = () => {
        new DocSearch();
        new Dashboard();
        new Runner();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
