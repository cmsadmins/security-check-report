/**
 * CMS ADMINS Security Check Report
 *
 * The browser runs the checks and draws the result. It does not decide what
 * anything means: the status, the score, the grade and the ordering all come
 * from PHP, so a report generated over WP-CLI says exactly the same thing.
 */
(() => {
    'use strict';

    const config = window.cascr || {};
    const i18n = config.i18n || {};
    const tests = config.tests || {};
    const categories = config.categories || {};

    const STATUS = {
        pass: 'pass',
        warn: 'warn',
        fail: 'fail',
        inconclusive: 'inconclusive',
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

        static saveReport(results) {
            return Api.request('/report', {
                method: 'POST',
                body: JSON.stringify({ results }),
            });
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

        async run({ onProgress, onResult }) {
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
                    onResult(id, result);
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
     * Turns a finished run into text, JSON and CSV.
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

    /**
     * Draws the report.
     */
    class ReportView {
        #results = {};
        #summary = null;
        #filter = 'all';

        constructor(nodes) {
            this.nodes = nodes;
        }

        setData(results, summary) {
            this.#results = results;
            this.#summary = summary;
        }

        render() {
            this.#renderScore();
            this.#renderPriorities();
            this.#renderDiff();
            this.#renderResults();
            this.#renderExport();
        }

        #renderScore() {
            const target = this.nodes.score;
            target.textContent = '';

            if (!this.#summary) {
                return;
            }

            const grade = this.#summary.grade;
            const counts = this.#summary.counts;

            const card = el('div', `cascr-score__card cascr-score__card--${grade.toLowerCase()}`);

            const badge = el('div', 'cascr-score__grade');
            badge.appendChild(el('span', 'cascr-score__letter', grade));
            badge.appendChild(el('span', 'cascr-score__label', (config.grades || {})[grade] || ''));
            card.appendChild(badge);

            const meta = el('div', 'cascr-score__meta');

            const risk = el('div', 'cascr-score__risk');
            risk.appendChild(el('span', 'cascr-score__risk-value', `${this.#summary.risk}%`));
            risk.appendChild(el('span', 'cascr-score__risk-label', i18n.riskScore));
            meta.appendChild(risk);

            const stats = el('div', 'cascr-score__stats');
            [
                ['fail', counts.fail, i18n.statusFail],
                ['warn', counts.warn, i18n.statusWarn],
                ['pass', counts.pass, i18n.statusPass],
                ['inconclusive', counts.inconclusive, i18n.statusUnknown],
                ['ignored', counts.ignored, i18n.statusIgnored],
            ].forEach(([key, value, label]) => {
                if (!value) {
                    return;
                }
                const stat = el('span', `cascr-stat cascr-stat--${key}`);
                stat.appendChild(el('strong', null, value));
                stat.appendChild(el('span', null, ` ${label}`));
                stats.appendChild(stat);
            });

            meta.appendChild(stats);
            card.appendChild(meta);
            target.appendChild(card);

            if (this.#summary.verdict) {
                const verdict = el('p', 'cascr-score__verdict', this.#summary.verdict);
                target.appendChild(verdict);
            }
        }

        #renderPriorities() {
            const target = this.nodes.priorities;
            target.textContent = '';

            if (!this.#summary) {
                return;
            }

            const priorities = this.#summary.priorities || [];

            target.appendChild(el('h2', 'cascr-section__title', i18n.nextActions));

            if (!priorities.length) {
                target.appendChild(el('p', 'cascr-empty', i18n.nothingToDo));
                return;
            }

            target.appendChild(el('p', 'cascr-section__lead', i18n.todoIntro));

            const list = el('ol', 'cascr-priorities__list');

            priorities.forEach((item) => {
                const entry = el('li', `cascr-priority cascr-priority--${item.severity}`);

                const head = el('div', 'cascr-priority__head');
                head.appendChild(el('span', 'cascr-priority__label', item.label));
                head.appendChild(el('span', `cascr-badge cascr-badge--${item.severity}`, statusLabel(item.status)));
                entry.appendChild(head);

                entry.appendChild(el('p', 'cascr-priority__summary', item.summary));

                if (item.fix) {
                    entry.appendChild(el('p', 'cascr-priority__fix', item.fix));
                }

                if (item.link && item.link.url) {
                    const helper = el('a', 'cascr-result__helper', item.link.label);
                    helper.href = item.link.url;
                    helper.target = '_blank';
                    helper.rel = 'noopener noreferrer';
                    entry.appendChild(helper);
                }

                const link = el('a', 'cascr-priority__link', i18n.documentation);
                link.href = `#cascr-doc-${item.id}`;
                link.addEventListener('click', () => openDoc(item.id));
                entry.appendChild(link);

                list.appendChild(entry);
            });

            target.appendChild(list);
        }

        #renderDiff() {
            const target = this.nodes.diff;
            target.textContent = '';

            const diff = this.#summary && this.#summary.diff;

            if (!diff) {
                return;
            }

            target.appendChild(el('h2', 'cascr-section__title', i18n.sinceLastRun));

            const groups = [
                ['broken', diff.broken, i18n.newIssues],
                ['fixed', diff.fixed, i18n.fixedIssues],
                ['changed', diff.changed, i18n.changedIssues],
            ].filter(([, ids]) => ids && ids.length);

            if (!groups.length) {
                target.appendChild(el('p', 'cascr-empty', i18n.noChange));
                return;
            }

            const wrap = el('div', 'cascr-diff__groups');

            groups.forEach(([key, ids, label]) => {
                const group = el('div', `cascr-diff__group cascr-diff__group--${key}`);
                group.appendChild(el('h3', 'cascr-diff__title', `${ids.length} ${label}`));

                const list = el('ul', 'cascr-diff__list');
                ids.forEach((id) => {
                    list.appendChild(el('li', null, (tests[id] || {}).label || id));
                });

                group.appendChild(list);
                wrap.appendChild(group);
            });

            target.appendChild(wrap);
        }

        #renderResults() {
            const target = this.nodes.results;
            target.textContent = '';

            target.appendChild(el('h2', 'cascr-section__title', i18n.results));
            target.appendChild(this.#buildFilters());

            const list = el('div', 'cascr-results__list');

            Object.keys(categories).forEach((category) => {
                const ids = Object.keys(this.#results).filter((id) => {
                    const test = tests[id] || {};
                    return test.category === category && this.#matchesFilter(this.#results[id]);
                });

                if (!ids.length) {
                    return;
                }

                const group = el('div', 'cascr-results__group');
                group.appendChild(el('h3', 'cascr-results__group-title', categories[category]));

                ids.forEach((id) => group.appendChild(this.#buildRow(id)));

                list.appendChild(group);
            });

            if (!list.childNodes.length) {
                list.appendChild(el('p', 'cascr-empty', i18n.nothingToDo));
            }

            target.appendChild(list);
        }

        #buildFilters() {
            const bar = el('div', 'cascr-filters');

            // Counted from what is on screen rather than from the stored run,
            // so muting a finding updates the chips immediately.
            const counts = { total: 0, pass: 0, warn: 0, fail: 0, inconclusive: 0, ignored: 0 };

            Object.keys(this.#results).forEach((id) => {
                const result = this.#results[id];
                counts.total += 1;
                if (result.ignored) {
                    counts.ignored += 1;
                } else {
                    counts[result.status] += 1;
                }
            });

            const options = [
                ['all', i18n.filterAll, counts.total],
                [STATUS.fail, i18n.statusFail, counts.fail],
                [STATUS.warn, i18n.statusWarn, counts.warn],
                [STATUS.pass, i18n.statusPass, counts.pass],
                [STATUS.inconclusive, i18n.statusUnknown, counts.inconclusive],
                ['ignored', i18n.statusIgnored, counts.ignored],
            ];

            options.forEach(([value, label, count]) => {
                if (value !== 'all' && !count) {
                    return;
                }

                const button = el('button', 'cascr-filter');
                button.type = 'button';
                button.textContent = `${label} (${count || 0})`;
                button.setAttribute('aria-pressed', String(this.#filter === value));

                if (this.#filter === value) {
                    button.classList.add('is-active');
                }

                button.addEventListener('click', () => {
                    this.#filter = value;
                    this.#renderResults();
                });

                bar.appendChild(button);
            });

            return bar;
        }

        #matchesFilter(result) {
            if (this.#filter === 'all') {
                return true;
            }
            if (this.#filter === 'ignored') {
                return Boolean(result.ignored);
            }
            return !result.ignored && result.status === this.#filter;
        }

        #buildRow(id) {
            const result = this.#results[id];
            const test = tests[id] || {};
            const status = result.ignored ? 'ignored' : result.status;

            const row = el('details', `cascr-result cascr-result--${status}`);
            row.id = `cascr-result-${id}`;

            const summary = el('summary', 'cascr-result__summary');
            summary.appendChild(el('span', `cascr-status cascr-status--${status}`, statusLabel(result.status)));
            summary.appendChild(el('span', 'cascr-result__label', test.label || id));
            summary.appendChild(el('span', 'cascr-result__text', result.summary));
            row.appendChild(summary);

            const body = el('div', 'cascr-result__body');

            if (result.items && result.items.length) {
                body.appendChild(el('h4', 'cascr-result__heading', i18n.details));
                const list = el('ul', 'cascr-result__items');
                result.items.forEach((item) => list.appendChild(el('li', null, item)));
                body.appendChild(list);
            }

            if (result.fix) {
                body.appendChild(el('h4', 'cascr-result__heading', i18n.recommendation));
                body.appendChild(el('p', 'cascr-result__fix', result.fix));
            }

            const actions = el('div', 'cascr-result__actions');

            if (result.link && result.link.url) {
                const helper = el('a', 'cascr-result__helper', result.link.label);
                helper.href = result.link.url;
                helper.target = '_blank';
                helper.rel = 'noopener noreferrer';
                body.appendChild(helper);
            }

            const docLink = el('a', 'cascr-result__link', i18n.documentation);
            docLink.href = `#cascr-doc-${id}`;
            docLink.addEventListener('click', () => openDoc(id));
            actions.appendChild(docLink);

            if (result.status === STATUS.fail || result.status === STATUS.warn || result.ignored) {
                const mute = el('button', 'button button-link cascr-result__mute', result.ignored ? i18n.unmute : i18n.mute);
                mute.type = 'button';
                mute.addEventListener('click', async () => {
                    mute.disabled = true;
                    try {
                        const response = await Api.setIgnore(id, !result.ignored);
                        result.ignored = Boolean(response.ignored);
                        this.#renderResults();
                        announce(result.ignored ? i18n.muted : i18n.unmuted);
                    } finally {
                        mute.disabled = false;
                    }
                });
                actions.appendChild(mute);
            }

            if (result.ignored) {
                actions.appendChild(el('span', 'cascr-result__muted-note', i18n.muted));
            }

            body.appendChild(actions);
            row.appendChild(body);

            return row;
        }

        #renderExport() {
            const target = this.nodes.export;
            target.textContent = '';

            if (!this.#summary) {
                return;
            }

            target.appendChild(el('h2', 'cascr-section__title', i18n.exportTitle));

            const exporter = new Exporter(this.#results, this.#summary);
            const row = el('div', 'cascr-export__row');

            const buttons = [
                [i18n.exportText, () => Exporter.download(exporter.text(), `${exporter.filename}.txt`, 'text/plain')],
                [i18n.exportJson, () => Exporter.download(exporter.json(), `${exporter.filename}.json`, 'application/json')],
                [i18n.exportCsv, () => Exporter.download(exporter.csv(), `${exporter.filename}.csv`, 'text/csv')],
                [i18n.copyReport, async () => {
                    const ok = await copyText(exporter.text());
                    announce(ok ? i18n.copied : i18n.copyFailed);
                    notify(ok ? i18n.copied : i18n.copyFailed, ok ? 'success' : 'error');
                }],
            ];

            buttons.forEach(([label, handler]) => {
                const button = el('button', 'button');
                button.type = 'button';
                button.textContent = label;
                button.addEventListener('click', handler);
                row.appendChild(button);
            });

            target.appendChild(row);
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
     * Wires the page together.
     */
    /**
     * Wires the page together and keeps the three steps in sync.
     */
    class App {
        constructor() {
            this.nodes = {
                consent: document.getElementById('cascr-consent'),
                run: document.getElementById('cascr-run'),
                launchHint: document.getElementById('cascr-launch-hint'),
                progress: document.getElementById('cascr-progress'),
                progressBar: document.getElementById('cascr-progress-bar'),
                progressLabel: document.getElementById('cascr-progress-label'),
                resultPanel: document.getElementById('cascr-result-panel'),
                findingsPanel: document.getElementById('cascr-findings-panel'),
                waiting2: document.getElementById('cascr-waiting-2'),
                waiting3: document.getElementById('cascr-waiting-3'),
                steps: [
                    document.getElementById('cascr-step-1'),
                    document.getElementById('cascr-step-2'),
                    document.getElementById('cascr-step-3'),
                ],
                score: document.getElementById('cascr-score'),
                priorities: document.getElementById('cascr-priorities'),
                diff: document.getElementById('cascr-diff'),
                results: document.getElementById('cascr-results'),
                export: document.getElementById('cascr-export'),
            };

            if (!this.nodes.run) {
                return;
            }

            this.view = new ReportView(this.nodes);
            new DocSearch();

            this.nodes.consent.addEventListener('change', (event) => {
                const ready = event.target.checked;
                this.nodes.run.disabled = !ready;
                if (this.nodes.launchHint) {
                    this.nodes.launchHint.hidden = ready;
                }
            });

            this.nodes.run.addEventListener('click', () => this.start());
        }

        /**
         * Marks a step as upcoming, current or done.
         */
        #setStep(index, state) {
            const step = this.nodes.steps[index];
            if (!step) {
                return;
            }
            step.classList.remove('is-upcoming', 'is-current', 'is-done');
            step.classList.add(state);
        }

        async start() {
            const ids = Object.keys(tests);

            this.nodes.run.disabled = true;
            this.nodes.progress.hidden = false;
            if (this.nodes.launchHint) {
                this.nodes.launchHint.hidden = true;
            }
            this.setProgress(0, ids.length, '');

            const runner = new TestRunner(ids, config.concurrency);

            const results = await runner.run({
                onProgress: (done, total, id) => this.setProgress(done, total, id),
                onResult: () => {},
            });

            let summary = null;
            try {
                const saved = await Api.saveReport(results);
                summary = saved.summary;
            } catch (error) {
                notify(i18n.error, 'error');
            }

            this.nodes.progress.hidden = true;
            this.nodes.run.disabled = false;
            this.nodes.run.textContent = i18n.runAgain;

            if (!summary) {
                return;
            }

            this.view.setData(results, summary);
            this.view.render();

            this.#setStep(0, 'is-done');
            this.#setStep(1, 'is-current');
            this.#setStep(2, 'is-current');

            [this.nodes.waiting2, this.nodes.waiting3].forEach((n) => {
                if (n) {
                    n.hidden = true;
                }
            });
            [this.nodes.resultPanel, this.nodes.findingsPanel].forEach((n) => {
                if (n) {
                    n.hidden = false;
                }
            });

            // The result sits below the fold on most screens, and a report you
            // have to go looking for is a report that gets missed.
            const target = this.nodes.steps[1];
            if (target) {
                target.scrollIntoView({
                    behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
                    block: 'start',
                });
            }

            announce(`${i18n.scanFinished} ${i18n.grade}: ${summary.grade}. ${summary.verdict || ''}`);
        }

        setProgress(done, total, id) {
            const percent = total ? Math.round((done / total) * 100) : 0;
            this.nodes.progressBar.style.width = `${percent}%`;

            const label = id && tests[id] ? tests[id].label : '';
            this.nodes.progressLabel.textContent = label
                ? `${sprintf(i18n.progress, done, total)}: ${label}`
                : sprintf(i18n.progress, done, total);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => new App());
    } else {
        new App();
    }
})();
