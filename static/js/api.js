// API Helper Functions for Vulnerability Management System

const API_BASE = '/api';

// Auth helpers
function getAccessToken() {
    return localStorage.getItem('access_token');
}

function getUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

function isAuthenticated() {
    return !!getAccessToken();
}

function logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

// Check auth and redirect if needed
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/login';
        return false;
    }
    return true;
}

// API request helper with auth
async function apiRequest(endpoint, options = {}) {
    const token = getAccessToken();

    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });

    // Handle 401 Unauthorized
    if (response.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }

    return response;
}

// Vulnerability API
const VulnerabilityAPI = {
    async list(filters = {}) {
        const params = new URLSearchParams();
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                params.append(key, value);
            }
        });

        const response = await apiRequest(`/vulnerabilities?${params}`);
        return await response.json();
    },

    async get(id) {
        const response = await apiRequest(`/vulnerabilities/${id}`);
        return await response.json();
    },

    async update(id, data) {
        const response = await apiRequest(`/vulnerabilities/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
        return await response.json();
    },

    async delete(id) {
        const response = await apiRequest(`/vulnerabilities/${id}`, {
            method: 'DELETE'
        });
        return await response.json();
    },

    async getStats() {
        const response = await apiRequest('/vulnerabilities/stats');
        return await response.json();
    }
};

// Jira API
const JiraAPI = {
    async createTicket(vulnId) {
        const response = await apiRequest(`/jira/create/${vulnId}`, {
            method: 'POST'
        });
        return await response.json();
    },

    async syncTicket(ticketId) {
        const response = await apiRequest(`/jira/sync/${ticketId}`, {
            method: 'POST'
        });
        return await response.json();
    },

    async addComment(ticketId, comment) {
        const response = await apiRequest(`/jira/comment/${ticketId}`, {
            method: 'POST',
            body: JSON.stringify({ comment })
        });
        return await response.json();
    },

    async bulkCreate(vulnerabilityIds) {
        const response = await apiRequest('/jira/bulk-create', {
            method: 'POST',
            body: JSON.stringify({ vulnerability_ids: vulnerabilityIds })
        });
        return await response.json();
    },

    async listTickets(filters = {}) {
        const params = new URLSearchParams(filters);
        const response = await apiRequest(`/jira/tickets?${params}`);
        return await response.json();
    }
};

// Reports API
const ReportsAPI = {
    async getSummary() {
        const response = await apiRequest('/reports/summary');
        return await response.json();
    },

    async getTrends(days = 90) {
        const response = await apiRequest(`/reports/trends?days=${days}`);
        return await response.json();
    },

    async getByTeam() {
        const response = await apiRequest('/reports/by-team');
        return await response.json();
    },

    async getAging() {
        const response = await apiRequest('/reports/aging');
        return await response.json();
    },

    async getCIOReport() {
        const response = await apiRequest('/reports/cio');
        return await response.json();
    },

    async exportCSV(filters = {}) {
        const params = new URLSearchParams(filters);
        const token = getAccessToken();

        window.open(`${API_BASE}/reports/export/csv?${params}`, '_blank');
    }
};

// Import API
const ImportAPI = {
    async importFile(source, file) {
        const formData = new FormData();
        formData.append('file', file);

        const token = getAccessToken();
        const response = await fetch(`${API_BASE}/import/${source}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });

        return await response.json();
    },

    async listSources() {
        const response = await apiRequest('/import/sources');
        return await response.json();
    }
};

// UI Helper functions
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;

    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);

        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function getSeverityBadgeClass(severity) {
    const map = {
        'Critical': 'badge-critical',
        'High': 'badge-high',
        'Medium': 'badge-medium',
        'Low': 'badge-low',
        'Informational': 'badge-info'
    };
    return map[severity] || 'badge-info';
}

function getStatusBadgeClass(status) {
    const map = {
        'open': 'badge-open',
        'in-progress': 'badge-in-progress',
        'resolved': 'badge-resolved',
        'risk-accepted': 'badge-risk-accepted',
        'false-positive': 'badge-false-positive',
        'delayed': 'badge-medium',
        'poamd': 'badge-info'
    };
    return map[status] || 'badge-info';
}

function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<div class="spinner"></div>';
    }
}

function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '';
    }
}
