/**
 * CMS ADMINS Security Check Report
 *
 * The page itself is rendered in PHP. What is left here is what a stored run
 * cannot do on its own: run the checks, re-check a single task, filter the
 * list, search the documentation and hand the report out as a file.
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

    const state = {
        priorities: Array.isArray(config.priorities) ? config.priorities : [],
    };

    const statusLabel = (status) => ({
        pass: i18n.statusPass,
        warn: i18n.statusWarn,
        fail: i18n.statusFail,
        inconclusive: i18n.statusUnknown,
    }[status] || status);

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

            if (this.summary.priorities && this.summary.priorities.length) {
                lines.push(i18n.nextActions);
                lines.push('-'.repeat(i18n.nextActions.length));
                this.summary.priorities.forEach((item, index) => {
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
                lines.push(`[${statusLabel(result.status)}] ${label}`);
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
                    escape(test.severity || ''),
                    escape(statusLabel(result.status)),
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
     * Counts are taken from the rows on screen rather than from the stored
     * run, so muting a finding moves the numbers straight away.
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

        refresh() {
            if (!this.bar) {
                return;
            }

            const counts = { all: 0 };

            this.rows.forEach((row) => {
                const status = row.dataset.cascrStatus;
                counts.all += 1;
                counts[status] = (counts[status] || 0) + 1;
            });

            this.bar.querySelectorAll('[data-cascr-filter]').forEach((button) => {
                const value = button.dataset.cascrFilter;
                const count = counts[value] || 0;

                button.textContent = `${button.dataset.cascrLabel} (${count})`;
                button.hidden = value !== 'all' && count === 0;
            });

            if (this.active !== 'all' && !counts[this.active]) {
                this.active = 'all';
            }

            this.apply();
        }
    }

    /**
     * The checklist, the re-check and everything that hangs off a stored run.
     */
    class Dashboard {
        constructor() {
            this.list = document.getElementById('cascr-tasks-list');
            this.done = document.getElementById('cascr-tasks-done');
            this.empty = document.getElementById('cascr-tasks-empty');
            this.open = document.getElementById('cascr-open');
            this.filters = new Filters();

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
         * Checks one task again and swaps what the answer changed.
         */
        async #recheck(button) {
            const id = button.dataset.cascrRecheck;
            const caption = button.textContent;

            button.disabled = true;
            button.textContent = i18n.taskChecking;

            let data;
            try {
                data = await Api.recheck(id);
            } catch (error) {
                notify(error.message || i18n.error, 'error');
                button.disabled = false;
                button.textContent = caption;
                return;
            }

            state.priorities = data.priorities || [];

            this.#updateGrade(data.summary);
            this.#updateRow(id, data.result);

            const passed = data.result.status === STATUS.pass;

            if (passed) {
                this.#addResolved(id, data.result.summary);
            }

            this.#renderTasks();

            const message = passed
                ? `${i18n.taskResolved}: ${data.result.summary}`
                : `${i18n.taskRemains} ${data.result.summary}`;

            announce(`${message} ${i18n.grade}: ${data.summary.grade}.`);
        }

        /**
         * Mutes a task until its finding says something else.
         *
         * The new short list depends on the mute, so this is the one action
         * that goes back to the server for the whole page.
         */
        async #later(button) {
            button.disabled = true;

            try {
                await Api.setIgnore(button.dataset.cascrLater, true);
                window.location.reload();
            } catch (error) {
                notify(error.message || i18n.error, 'error');
                button.disabled = false;
            }
        }

        async #mute(button) {
            const row = button.closest('[data-cascr-row]');
            if (!row) {
                return;
            }

            const muted = row.dataset.cascrStatus === 'ignored';

            button.disabled = true;

            try {
                const response = await Api.setIgnore(button.dataset.cascrMute, !muted);
                const status = response.ignored ? 'ignored' : row.dataset.cascrReal;

                row.dataset.cascrStatus = status;
                row.className = `cascr-result cascr-result--${status}`;
                button.textContent = response.ignored ? i18n.unmute : i18n.mute;

                const note = row.querySelector('[data-cascr-muted-note]');
                if (note) {
                    note.hidden = !response.ignored;
                }

                this.filters.refresh();
                announce(response.ignored ? i18n.muted : i18n.unmuted);
            } catch (error) {
                notify(error.message || i18n.error, 'error');
            } finally {
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
                    priorities: state.priorities,
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

        #updateGrade(summary) {
            const card = document.querySelector('[data-cascr-card]');
            if (card) {
                card.className = `cascr-score__card cascr-score__card--${String(summary.grade).toLowerCase()}`;
            }

            const set = (selector, value) => {
                const node = document.querySelector(selector);
                if (node) {
                    node.textContent = value;
                }
            };

            set('[data-cascr-letter]', summary.grade);
            set('[data-cascr-grade-label]', summary.label || (config.grades || {})[summary.grade] || '');
            set('[data-cascr-risk]', `${summary.risk}%`);
            set('[data-cascr-verdict]', summary.verdict || '');
            set('[data-cascr-today]', summary.today || '');

            // A grade that no longer comes from one pass has to say so right
            // away, not after the next reload.
            const note = document.querySelector('[data-cascr-partial]');
            if (note) {
                note.textContent = summary.note || '';
                note.hidden = !summary.note;
            }
        }

        /**
         * Brings the row in the full list in line with the fresh result.
         */
        #updateRow(id, result) {
            const row = document.querySelector(`[data-cascr-row="${CSS.escape(id)}"]`);
            if (!row) {
                return;
            }

            row.dataset.cascrReal = result.status;

            if (row.dataset.cascrStatus !== 'ignored') {
                row.dataset.cascrStatus = result.status;
                row.className = `cascr-result cascr-result--${result.status}`;
            }

            const badge = row.querySelector('[data-cascr-status-label]');
            if (badge) {
                badge.className = `cascr-status cascr-status--${result.status}`;
                badge.textContent = statusLabel(result.status);
            }

            const summary = row.querySelector('[data-cascr-summary]');
            if (summary) {
                summary.textContent = result.summary;
            }

            const items = row.querySelector('[data-cascr-items]');
            const itemsHeading = row.querySelector('[data-cascr-items-heading]');
            if (items) {
                items.textContent = '';
                (result.items || []).forEach((item) => items.appendChild(el('li', null, item)));
                items.hidden = !(result.items || []).length;
                if (itemsHeading) {
                    itemsHeading.hidden = items.hidden;
                }
            }

            const fix = row.querySelector('[data-cascr-fix]');
            const fixHeading = row.querySelector('[data-cascr-fix-heading]');
            if (fix) {
                fix.textContent = result.fix || '';
                fix.hidden = !result.fix;
                if (fixHeading) {
                    fixHeading.hidden = fix.hidden;
                }
            }

            this.filters.refresh();
        }

        #addResolved(id, summary) {
            if (!this.done) {
                return;
            }

            const entry = el('li', 'cascr-task__resolved');
            entry.appendChild(el('span', 'cascr-status cascr-status--pass', i18n.taskResolved));
            entry.appendChild(el('span', 'cascr-task__label', (tests[id] || {}).label || id));
            entry.appendChild(el('span', 'cascr-task__text', summary));

            this.done.appendChild(entry);
        }

        /**
         * Redraws the five open tasks from the answer of the re-check.
         */
        #renderTasks() {
            if (!this.list) {
                return;
            }

            this.list.textContent = '';
            state.priorities.forEach((task) => {
                this.list.appendChild(this.#buildTask(task));
                this.#closeOpenEntry(task.id);
            });

            if (this.empty) {
                this.empty.hidden = state.priorities.length > 0;
                if (!state.priorities.length) {
                    this.empty.textContent = i18n.nothingLeft;
                }
            }
        }

        /**
         * The same card CASCR_Admin_Dashboard::render_task() prints.
         */
        #buildTask(task) {
            const entry = el('li', `cascr-task cascr-task--${task.severity}`);
            entry.dataset.cascrTask = task.id;

            const head = el('div', 'cascr-task__head');
            head.appendChild(el('span', 'cascr-task__label', task.label));
            head.appendChild(el('span', `cascr-badge cascr-badge--${task.severity}`, severities[task.severity] || task.severity));
            entry.appendChild(head);

            const summary = el('p', 'cascr-task__summary', task.summary);
            summary.dataset.cascrTaskSummary = '';
            entry.appendChild(summary);

            if (task.fix) {
                entry.appendChild(el('p', 'cascr-task__fix', task.fix));
            }

            if (task.link && task.link.url) {
                const helper = el('a', 'cascr-result__helper', task.link.label);
                helper.href = task.link.url;
                helper.target = '_blank';
                helper.rel = 'noopener noreferrer';
                entry.appendChild(helper);
            }

            const actions = el('div', 'cascr-task__actions');

            const done = el('button', 'button button-primary', i18n.taskDone);
            done.type = 'button';
            done.dataset.cascrRecheck = task.id;
            actions.appendChild(done);

            const later = el('button', 'button button-link cascr-task__later', i18n.taskLater);
            later.type = 'button';
            later.dataset.cascrLater = task.id;
            actions.appendChild(later);

            const doc = el('a', 'cascr-result__link', i18n.documentation);
            doc.href = `#cascr-doc-${task.id}`;
            doc.dataset.cascrDoc = task.id;
            actions.appendChild(doc);

            entry.appendChild(actions);

            return entry;
        }

        /**
         * A finding that moved up into the short list must not stay below it.
         */
        #closeOpenEntry(id) {
            const entry = document.querySelector(`[data-cascr-open="${CSS.escape(id)}"]`);

            if (!entry || entry.hidden) {
                return;
            }

            entry.hidden = true;

            const counter = document.querySelector('[data-cascr-open-count]');
            const left = document.querySelectorAll('[data-cascr-open]:not([hidden])').length;

            if (counter) {
                counter.textContent = sprintf(i18n.stillOpen, left);
            }

            if (this.open && left === 0) {
                this.open.hidden = true;
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
