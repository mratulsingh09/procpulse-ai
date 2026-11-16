/**
 * ProcPulse AI — Telemetry & Anomaly Profiler Frontend Engine
 * Real-time Chart.js streaming, auto-reconnect WebSocket client, and DOM renderer.
 */

(function () {
    "use strict";

    // State
    const MAX_POINTS = 60;
    let ws = null;
    let reconnectAttempts = 0;
    let charts = {};
    let allProcesses = [];
    let selectedProcessId = null;
    let recordedAnomalies = [];
    const KPI_HISTORY_LIMIT = 24;
    const kpiHistory = {
        cpu: [],
        memory: [],
        disk: [],
        network: [],
    };

    // DOM Elements
    const elements = {
        reconnectBanner: document.getElementById("reconnect-banner"),
        streamPulse: document.getElementById("stream-pulse"),
        streamStatusIndicator: document.getElementById("stream-status-indicator"),
        streamStatusText: document.getElementById("stream-status-text"),
        healthScoreVal: document.getElementById("health-score-val"),
        healthStatusText: document.getElementById("health-status-text"),
        agentCpu: document.getElementById("agent-cpu"),
        agentRss: document.getElementById("agent-rss"),
        valCpu: document.getElementById("val-cpu"),
        barCpu: document.getElementById("bar-cpu"),
        valLoad: document.getElementById("val-load"),
        cpuCoreCount: document.getElementById("cpu-core-count"),
        valMem: document.getElementById("val-mem"),
        barMem: document.getElementById("bar-mem"),
        memUsageAbs: document.getElementById("mem-usage-abs"),
        valSwap: document.getElementById("val-swap"),
        valDisk: document.getElementById("val-disk"),
        diskRead: document.getElementById("disk-read"),
        diskWrite: document.getElementById("disk-write"),
        valNet: document.getElementById("val-net"),
        netRecv: document.getElementById("net-recv"),
        netSent: document.getElementById("net-sent"),
        procsTbody: document.getElementById("procs-tbody"),
        procSearch: document.getElementById("proc-search"),
        procSort: document.getElementById("proc-sort"),
        procResultCount: document.getElementById("proc-result-count"),
        processDetailPanel: document.getElementById("process-detail-panel"),
        anomalyFeed: document.getElementById("anomaly-feed"),
        anomalyCountBadge: document.getElementById("anomaly-count-badge"),
        suspiciousContainer: document.getElementById("suspicious-container"),
        suspiciousContent: document.getElementById("suspicious-content"),
    };

    /**
     * Initialize Chart.js streaming charts
     */
    function initCharts() {
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { intersect: false, mode: "index" },
            scales: {
                x: {
                    display: true,
                    grid: { color: "rgba(35, 57, 83, 0.09)" },
                    ticks: { color: "#78879b", font: { size: 10 }, maxTicksLimit: 8 },
                },
                y: {
                    display: true,
                    grid: { color: "rgba(35, 57, 83, 0.09)" },
                    ticks: { color: "#78879b", font: { size: 10 } },
                    beginAtZero: true,
                },
            },
            plugins: {
                legend: {
                    labels: { color: "#526277", font: { size: 10 }, boxWidth: 10, usePointStyle: true, pointStyle: "line" },
                },
            },
        };

        // 1. CPU & Load Chart
        const cpuCtx = document.getElementById("chart-cpu").getContext("2d");
        charts.cpu = new Chart(cpuCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "CPU Total (%)",
                        borderColor: "#147d73",
                        backgroundColor: "rgba(20, 125, 115, 0.12)",
                        data: [],
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 0,
                        fill: true,
                    },
                    {
                        label: "Load (1m)",
                        borderColor: "#e5b467",
                        borderDash: [4, 4],
                        data: [],
                        borderWidth: 1.5,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                ],
            },
            options: {
                ...commonOptions,
                scales: {
                    ...commonOptions.scales,
                    y: { ...commonOptions.scales.y, max: 100 },
                },
            },
        });

        // 2. Memory & Swap Chart
        const memCtx = document.getElementById("chart-mem").getContext("2d");
        charts.mem = new Chart(memCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "RAM (%)",
                        borderColor: "#536bb6",
                        backgroundColor: "rgba(83, 107, 182, 0.12)",
                        data: [],
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 0,
                        fill: true,
                    },
                    {
                        label: "Swap (%)",
                        borderColor: "#8a78c7",
                        data: [],
                        borderWidth: 1.5,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                ],
            },
            options: {
                ...commonOptions,
                scales: {
                    ...commonOptions.scales,
                    y: { ...commonOptions.scales.y, max: 100 },
                },
            },
        });

        // 3. Disk & Network I/O Chart
        const ioCtx = document.getElementById("chart-io").getContext("2d");
        charts.io = new Chart(ioCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Disk I/O (MB/s)",
                        borderColor: "#a76b21",
                        data: [],
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "Network (MB/s)",
                        borderColor: "#6959b6",
                        data: [],
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                ],
            },
            options: commonOptions,
        });
    }

    /**
     * Push a new telemetry point onto a chart
     */
    function appendChartPoint(chart, label, dataArray) {
        chart.data.labels.push(label);
        dataArray.forEach((val, idx) => {
            if (chart.data.datasets[idx]) {
                chart.data.datasets[idx].data.push(val);
            }
        });
        if (chart.data.labels.length > MAX_POINTS) {
            chart.data.labels.shift();
            chart.data.datasets.forEach((ds) => ds.data.shift());
        }
        chart.update("none");
    }

    function updateKpiSparkline(metric, value) {
        if (!Number.isFinite(value)) return;

        const history = kpiHistory[metric];
        history.push(value);
        if (history.length > KPI_HISTORY_LIMIT) history.shift();

        const min = Math.min(...history);
        const range = Math.max(...history) - min || 1;
        const points = history.map((point, index) => {
            const x = history.length === 1 ? 0 : (index / (history.length - 1)) * 100;
            const y = 26 - ((point - min) / range) * 20;
            return `${x.toFixed(1)} ${y.toFixed(1)}`;
        });
        const line = `M ${points[0]} ${points.length === 1 ? `L 100 ${points[0].split(" ")[1]}` : points.slice(1).map((point) => `L ${point}`).join(" ")}`;

        document.getElementById(`trend-${metric}`).setAttribute("d", line);
        document.getElementById(`area-${metric}`).setAttribute("d", `${line} L 100 30 L 0 30 Z`);
    }

    /**
     * Render the Process Table
     */
    function renderProcesses() {
        const query = (elements.procSearch.value || "").trim().toLowerCase();
        const filtered = allProcesses.filter(
            (p) =>
                p.name.toLowerCase().includes(query) ||
                p.pid.toString().includes(query) ||
                (p.cmdline && p.cmdline.toLowerCase().includes(query))
        );
        const sortField = elements.procSort.value;
        filtered.sort((a, b) => Number(b[sortField] || 0) - Number(a[sortField] || 0));
        if (selectedProcessId !== null && !filtered.some((p) => p.pid === selectedProcessId)) {
            selectedProcessId = null;
        }
        elements.procResultCount.innerText = query
            ? `${filtered.length} of ${allProcesses.length} shown`
            : `${allProcesses.length} monitored`;

        if (filtered.length === 0) {
            elements.procsTbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No matching processes.</td></tr>`;
            renderProcessDetails();
            return;
        }

        const rows = filtered
            .map((p) => {
                const memMb = (p.memory_rss / (1024 * 1024)).toFixed(1);
                const cpuPercent = Number(p.cpu_percent) || 0;
                const memPercent = Number(p.memory_percent) || 0;
                const cpuLevel = cpuPercent >= 80 ? "usage-critical" : cpuPercent >= 50 ? "usage-elevated" : "";
                const statusClass =
                    p.state === "running"
                        ? "status-running"
                        : p.state === "zombie"
                        ? "status-zombie"
                        : "status-sleeping";

                return `
                <tr class="process-row${p.pid === selectedProcessId ? " selected" : ""}" data-pid="${p.pid}" tabindex="0" aria-selected="${p.pid === selectedProcessId}">
                    <td class="process-pid mono">${p.pid}</td>
                    <td class="process-name-cell"><span class="process-avatar">${escapeHtml((p.name || "?").charAt(0).toUpperCase())}</span><strong>${escapeHtml(p.name)}</strong></td>
                    <td class="usage-cell">
                        <span class="usage-value mono">${cpuPercent.toFixed(1)}%</span>
                        <span class="usage-track" aria-hidden="true"><span class="usage-fill ${cpuLevel}" style="width: ${Math.min(100, Math.max(0, cpuPercent))}%"></span></span>
                    </td>
                    <td class="usage-cell">
                        <span class="usage-value mono">${memPercent.toFixed(1)}%</span>
                        <span class="usage-track" aria-hidden="true"><span class="usage-fill usage-memory" style="width: ${Math.min(100, Math.max(0, memPercent))}%"></span></span>
                    </td>
                    <td class="mono">${memMb} MB</td>
                    <td class="mono">${p.num_threads}</td>
                    <td class="mono">${p.num_fds}</td>
                    <td><span class="status-badge ${statusClass}">${escapeHtml(p.state)}</span></td>
                </tr>
            `;
            })
            .join("");

        elements.procsTbody.innerHTML = rows;
        renderProcessDetails();
    }

    function renderProcessDetails() {
        const process = allProcesses.find((p) => p.pid === selectedProcessId);
        if (!process) {
            elements.processDetailPanel.hidden = true;
            elements.processDetailPanel.innerHTML = "";
            return;
        }

        const command = (process.cmdline || process.name || "").replace(/\0/g, " ").trim();
        const memoryMb = (process.memory_rss / (1024 * 1024)).toFixed(1);
        elements.processDetailPanel.hidden = false;
        elements.processDetailPanel.innerHTML = `
            <div class="process-detail-heading">
                <div class="process-detail-identity">
                    <span class="process-detail-avatar">${escapeHtml((process.name || "?").charAt(0).toUpperCase())}</span>
                    <div>
                        <span class="process-detail-eyebrow">PROCESS INSPECTOR</span>
                        <h3>${escapeHtml(process.name)}</h3>
                        <span class="process-detail-pid">PID ${process.pid}</span>
                    </div>
                </div>
                <button class="process-detail-close" type="button" aria-label="Close process details">×</button>
            </div>
            <dl class="process-detail-stats">
                <div><dt>CPU usage</dt><dd>${Number(process.cpu_percent).toFixed(1)}%</dd></div>
                <div><dt>Memory</dt><dd>${Number(process.memory_percent).toFixed(1)}%</dd></div>
                <div><dt>Resident memory</dt><dd>${memoryMb} MB</dd></div>
                <div><dt>Threads</dt><dd>${process.num_threads}</dd></div>
                <div><dt>Open descriptors</dt><dd>${process.num_fds}</dd></div>
                <div><dt>State</dt><dd>${escapeHtml(process.state)}</dd></div>
            </dl>
            <div class="process-command">
                <span>COMMAND LINE</span>
                <code>${escapeHtml(command || "Command line unavailable")}</code>
            </div>
        `;
    }

    function toggleProcessDetails(row) {
        const pid = Number(row.dataset.pid);
        selectedProcessId = selectedProcessId === pid ? null : pid;
        renderProcesses();
        if (selectedProcessId !== null) {
            elements.procsTbody.querySelector(`[data-pid="${selectedProcessId}"]`)?.focus();
        }
    }

    /**
     * Render an anomaly item to the feed
     */
    function prependAnomaly(anomaly) {
        if (!anomaly) return;

        // Check duplicate
        if (recordedAnomalies.some((a) => a.timestamp === anomaly.timestamp && a.metric === anomaly.metric)) {
            return;
        }
        recordedAnomalies.unshift(anomaly);
        elements.anomalyCountBadge.innerText = `${recordedAnomalies.length} Events`;

        const tagClass =
            anomaly.severity === "high"
                ? "tag-high"
                : anomaly.severity === "medium"
                ? "tag-medium"
                : "tag-low";

        const dt = new Date(anomaly.timestamp * 1000);
        const timeStr = dt.toTimeString().split(" ")[0];

        const item = document.createElement("div");
        item.className = `anomaly-item ${anomaly.severity}`;
        item.innerHTML = `
            <div class="anomaly-header">
                <div>
                    <span class="anomaly-tag ${tagClass}">${anomaly.severity}</span>
                    <strong style="margin-left: 8px; text-transform: uppercase;">${escapeHtml(anomaly.metric)}</strong>
                </div>
                <span class="mono" style="color: var(--text-muted); font-size: 11px;">${timeStr}</span>
            </div>
            <div class="anomaly-text">${escapeHtml(anomaly.explanation)}</div>
        `;

        if (elements.anomalyFeed.children.length > 0 && elements.anomalyFeed.children[0].innerText.includes("Baseline warm-up")) {
            elements.anomalyFeed.innerHTML = "";
        }
        elements.anomalyFeed.insertBefore(item, elements.anomalyFeed.firstChild);
    }

    /**
     * Update DOM with telemetry snapshot
     */
    function updateTelemetry(payload) {
        const sys = payload.system;
        if (!sys) return;

        const timeLabel = new Date(sys.timestamp * 1000).toTimeString().split(" ")[0];

        // 1. Health Score & Status
        const score = payload.health_score ?? 100.0;
        const status = payload.health_status ?? "healthy";
        elements.healthScoreVal.innerText = score.toFixed(1);
        elements.healthScoreVal.className = `health-val ${status}`;
        elements.healthStatusText.innerText = status.toUpperCase();
        const healthContainer = elements.healthScoreVal.closest(".health-score-container");
        healthContainer.dataset.status = status;
        healthContainer.style.setProperty("--health-progress", Math.max(0, Math.min(100, score)));
        elements.healthStatusText.style.color = "var(--health-color)";

        // 2. Self Overhead
        const overhead = payload.overhead;
        if (overhead) {
            elements.agentCpu.innerText = `${overhead.cpu_percent.toFixed(1)}%`;
            elements.agentRss.innerText = `${overhead.memory_rss_mb.toFixed(0)} MB`;
        }

        // 3. Top Ribbon
        elements.valCpu.innerText = `${sys.cpu_percent.toFixed(1)}%`;
        elements.barCpu.style.width = `${Math.min(100, sys.cpu_percent)}%`;
        updateKpiSparkline("cpu", sys.cpu_percent);
        elements.valLoad.innerText = `${sys.load_1m.toFixed(2)}, ${sys.load_5m.toFixed(2)}, ${sys.load_15m.toFixed(2)}`;
        if (sys.cpu_per_core && sys.cpu_per_core.length > 0) {
            elements.cpuCoreCount.innerText = `${sys.cpu_per_core.length} Cores`;
        }

        const memUsedGb = (sys.mem_used / (1024 ** 3)).toFixed(1);
        const memTotalGb = (sys.mem_total / (1024 ** 3)).toFixed(1);
        elements.valMem.innerText = `${sys.mem_percent.toFixed(1)}%`;
        elements.barMem.style.width = `${Math.min(100, sys.mem_percent)}%`;
        elements.memUsageAbs.innerText = `${memUsedGb} / ${memTotalGb} GB`;
        elements.valSwap.innerText = `${sys.swap_percent.toFixed(1)}%`;
        updateKpiSparkline("memory", sys.mem_percent);

        const diskMb = ((sys.disk_read_bytes_sec + sys.disk_write_bytes_sec) / (1024 * 1024)).toFixed(1);
        elements.valDisk.innerHTML = `${diskMb} <span class="value-unit">MB/s</span>`;
        elements.diskRead.innerText = (sys.disk_read_bytes_sec / (1024 * 1024)).toFixed(1);
        elements.diskWrite.innerText = (sys.disk_write_bytes_sec / (1024 * 1024)).toFixed(1);
        updateKpiSparkline("disk", Number(diskMb));

        const netMb = ((sys.net_recv_bytes_sec + sys.net_sent_bytes_sec) / (1024 * 1024)).toFixed(1);
        elements.valNet.innerHTML = `${netMb} <span class="value-unit">MB/s</span>`;
        elements.netRecv.innerText = (sys.net_recv_bytes_sec / (1024 * 1024)).toFixed(1);
        elements.netSent.innerText = (sys.net_sent_bytes_sec / (1024 * 1024)).toFixed(1);
        updateKpiSparkline("network", Number(netMb));

        // 4. Update Charts
        if (charts.cpu) {
            appendChartPoint(charts.cpu, timeLabel, [sys.cpu_percent, sys.load_1m]);
        }
        if (charts.mem) {
            appendChartPoint(charts.mem, timeLabel, [sys.mem_percent, sys.swap_percent]);
        }
        if (charts.io) {
            appendChartPoint(charts.io, timeLabel, [parseFloat(diskMb), parseFloat(netMb)]);
        }

        // 5. Update Processes
        if (payload.top_processes) {
            allProcesses = payload.top_processes;
            renderProcesses();
        }

        // 6. Update Anomalies
        if (payload.latest_anomalies && Array.isArray(payload.latest_anomalies)) {
            payload.latest_anomalies.forEach((a) => prependAnomaly(a));
        }

        // 7. Suspicious Processes
        if (payload.suspicious && payload.suspicious.length > 0) {
            elements.suspiciousContainer.classList.add("active");
            elements.suspiciousContent.innerHTML = payload.suspicious
                .map((s) => `• <strong>PID ${s.pid} (${escapeHtml(s.name)}):</strong> ${escapeHtml(s.reason)}`)
                .join("<br>");
        } else {
            elements.suspiciousContainer.classList.remove("active");
        }
    }

    /**
     * Connect WebSocket with auto-reconnect
     */
    function connectWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/live`;

        ws = new WebSocket(wsUrl);

        ws.onopen = function () {
            reconnectAttempts = 0;
            elements.reconnectBanner.style.display = "none";
            elements.streamStatusIndicator.classList.remove("disconnected");
            elements.streamStatusText.innerText = "Live telemetry";
            elements.streamPulse.style.backgroundColor = "var(--accent-emerald)";
            elements.streamPulse.style.boxShadow = "0 0 12px var(--accent-emerald)";
        };

        ws.onmessage = function (event) {
            try {
                const data = JSON.parse(event.data);
                updateTelemetry(data);
            } catch (err) {
                console.error("Error parsing WebSocket payload:", err);
            }
        };

        ws.onclose = function () {
            elements.reconnectBanner.style.display = "block";
            elements.streamStatusIndicator.classList.add("disconnected");
            elements.streamStatusText.innerText = "Reconnecting to telemetry";
            elements.streamPulse.style.backgroundColor = "var(--accent-rose)";
            elements.streamPulse.style.boxShadow = "0 0 12px var(--accent-rose)";

            reconnectAttempts++;
            const delay = Math.min(10000, 1000 * Math.pow(1.5, reconnectAttempts));
            setTimeout(connectWebSocket, delay);
        };

        ws.onerror = function (err) {
            console.warn("WebSocket error:", err);
            ws.close();
        };
    }

    /**
     * Preload historical telemetry from REST API
     */
    async function preloadHistory() {
        try {
            const resp = await fetch("/api/metrics?limit=30");
            if (resp.ok) {
                const metrics = await resp.json();
                metrics.forEach((sys) => {
                    const timeLabel = new Date(sys.timestamp * 1000).toTimeString().split(" ")[0];
                    const diskMb = ((sys.disk_read_bytes_sec + sys.disk_write_bytes_sec) / (1024 * 1024)).toFixed(1);
                    const netMb = ((sys.net_recv_bytes_sec + sys.net_sent_bytes_sec) / (1024 * 1024)).toFixed(1);

                    if (charts.cpu) appendChartPoint(charts.cpu, timeLabel, [sys.cpu_percent, sys.load_1m]);
                    if (charts.mem) appendChartPoint(charts.mem, timeLabel, [sys.mem_percent, sys.swap_percent]);
                    if (charts.io) appendChartPoint(charts.io, timeLabel, [parseFloat(diskMb), parseFloat(netMb)]);
                });
            }

            const anomResp = await fetch("/api/anomalies?limit=15");
            if (anomResp.ok) {
                const anoms = await anomResp.json();
                // Prepend oldest first so latest ends up at top
                anoms.reverse().forEach((a) => prependAnomaly(a));
            }
        } catch (e) {
            console.warn("Could not preload history:", e);
        }
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Attach search listener
    if (elements.procSearch) {
        elements.procSearch.addEventListener("input", renderProcesses);
    }
    if (elements.procSort) {
        elements.procSort.addEventListener("change", renderProcesses);
    }
    if (elements.procsTbody) {
        elements.procsTbody.addEventListener("click", (event) => {
            const row = event.target.closest("tr[data-pid]");
            if (row) toggleProcessDetails(row);
        });
        elements.procsTbody.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            const row = event.target.closest("tr[data-pid]");
            if (row) {
                event.preventDefault();
                toggleProcessDetails(row);
            }
        });
    }
    if (elements.processDetailPanel) {
        elements.processDetailPanel.addEventListener("click", (event) => {
            if (!event.target.closest(".process-detail-close")) return;
            selectedProcessId = null;
            renderProcesses();
        });
    }

    // Start
    initCharts();
    preloadHistory();
    connectWebSocket();
})();
