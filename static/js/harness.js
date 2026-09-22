// Harness API Helper
const HarnessAPI = {
    async getStatus() {
        const r = await apiRequest('/harness/status');
        return r.json();
    },
    async getConfig() {
        const r = await apiRequest('/harness/config');
        return r.json();
    },
    async saveConfig(config) {
        const r = await apiRequest('/harness/config', {
            method: 'PUT', body: JSON.stringify({ config })
        });
        return r.json();
    },
    async getTimeline(opts = {}) {
        const params = new URLSearchParams(opts);
        const r = await apiRequest(`/harness/timeline?${params}`);
        return r.json();
    },
    async logAction(action, category, details) {
        const r = await apiRequest('/harness/timeline', {
            method: 'POST',
            body: JSON.stringify({ action, category, details })
        });
        return r.json();
    },
    async getModelsStatus() {
        const r = await apiRequest('/harness/models/status');
        return r.json();
    },
    async fingerprintModel(model, target) {
        const r = await apiRequest('/harness/models/fingerprint', {
            method: 'POST',
            body: JSON.stringify({ model, target })
        });
        return r.json();
    },
    async getCorpusStatus() {
        const r = await apiRequest('/harness/api-testing/corpus');
        return r.json();
    },
    async buildCorpus() {
        const r = await apiRequest('/harness/api-testing/corpus/build', { method: 'POST' });
        return r.json();
    },
    async runFuzz(host, endpoint) {
        const r = await apiRequest('/harness/api-testing/fuzz', {
            method: 'POST',
            body: JSON.stringify({ host, endpoint })
        });
        return r.json();
    },
    async runAuthTest(host) {
        const r = await apiRequest('/harness/api-testing/auth-test', {
            method: 'POST',
            body: JSON.stringify({ host })
        });
        return r.json();
    },
    async getResults() {
        const r = await apiRequest('/harness/api-testing/results');
        return r.json();
    },
    async getResultFile(name) {
        const r = await apiRequest(`/harness/api-testing/results/${name}`);
        return r.json();
    },
    async runEgressProbe() {
        const r = await apiRequest('/harness/network/probe', { method: 'POST' });
        return r.json();
    },
    async runLateralProbe() {
        const r = await apiRequest('/harness/network/lateral', { method: 'POST' });
        return r.json();
    },
    async getContainerStatus() {
        const r = await apiRequest('/harness/containers/status');
        return r.json();
    },
    async buildContainers() {
        const r = await apiRequest('/harness/containers/build', { method: 'POST' });
        return r.json();
    },
    async getTasks() {
        const r = await apiRequest('/harness/tasks');
        return r.json();
    },
    async getTask(id) {
        const r = await apiRequest(`/harness/tasks/${id}`);
        return r.json();
    },
    async getChecklist() {
        const r = await apiRequest('/harness/checklist');
        return r.json();
    },
    async saveChecklist(items) {
        const r = await apiRequest('/harness/checklist', {
            method: 'PUT',
            body: JSON.stringify({ items })
        });
        return r.json();
    },
};

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function harnessNav() {
    return `
    <header class="header">
        <nav class="nav">
            <a href="/harness" class="logo">AI Test Harness</a>
            <ul class="nav-links">
                <li><a href="/harness">Dashboard</a></li>
                <li><a href="/harness/config">Configure</a></li>
                <li><a href="/harness/models">Model Lab</a></li>
                <li><a href="/harness/api-testing">API Testing</a></li>
                <li><a href="/harness/network">Network</a></li>
                <li><a href="/harness/containers">Containers</a></li>
                <li><a href="/harness/evidence">Evidence</a></li>
                <li><a href="/harness/checklist">Checklist</a></li>
            </ul>
            <div class="user-menu">
                <a href="/dashboard" class="btn btn-secondary btn-sm">Back to VulnMS</a>
                <button class="btn btn-secondary btn-sm" onclick="logout()">Logout</button>
            </div>
        </nav>
    </header>`;
}

function taskStatusBadge(status) {
    const cls = status === 'completed' ? 'badge-low'
        : status === 'running' ? 'badge-info'
        : status === 'timeout' ? 'badge-medium'
        : 'badge-critical';
    return `<span class="badge ${cls}">${status}</span>`;
}

async function pollTask(taskId, statusEl, outputEl) {
    const poll = async () => {
        try {
            const data = await HarnessAPI.getTask(taskId);
            const t = data.task;
            if (statusEl) statusEl.innerHTML = taskStatusBadge(t.status);
            if (outputEl && t.output) outputEl.textContent = t.output;
            if (t.status === 'running') setTimeout(poll, 2000);
        } catch (e) { /* stop polling */ }
    };
    poll();
}
