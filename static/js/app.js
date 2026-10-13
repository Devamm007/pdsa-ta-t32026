// ==========================================================================
// DSA Challenge Arena - Frontend Controller v2.3
// ==========================================================================

const state = {
    user: null,
    token: null,
    leaderboard: [],
    googleClientId: null,
    activeTab: 'leaderboard',
    activeSubtab: 'getting-started',
    adminEmails: ['shahdevam49@gmail.com', '24f2000828@ds.study.iitm.ac.in']
};

// --------------------------------------------------------------------------
// Initialization
// --------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initMobileNav();
    initPlaybookSubtabs();
    initBackfillSubtabs();
    initChecklistAndNotes();
    await checkConfig();
    await initAuth();
    loadLeaderboard();
    initScheduleTimer();
    initEventListeners();
});

// --------------------------------------------------------------------------
// Tab Navigation & Mobile Menu
// --------------------------------------------------------------------------
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            switchTab(tabId);
        });
    });
}

function switchTab(tabId) {
    state.activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${tabId}`));

    // Close mobile nav drawer if open
    const navTabs = document.getElementById('main-nav-tabs');
    const toggleBtn = document.getElementById('mobile-nav-toggle');
    if (navTabs && navTabs.classList.contains('mobile-open')) {
        navTabs.classList.remove('mobile-open');
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fa-solid fa-bars"></i>';
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    }

    if (tabId === 'leaderboard') loadLeaderboard();
    if (tabId === 'submit') checkMySyncedRepo();
}

function initMobileNav() {
    const toggleBtn = document.getElementById('mobile-nav-toggle');
    const navTabs = document.getElementById('main-nav-tabs');
    if (!toggleBtn || !navTabs) return;

    toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = navTabs.classList.toggle('mobile-open');
        toggleBtn.innerHTML = isOpen ? '<i class="fa-solid fa-xmark"></i>' : '<i class="fa-solid fa-bars"></i>';
        toggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    // Close when clicking outside
    document.addEventListener('click', (e) => {
        if (navTabs.classList.contains('mobile-open') && !navTabs.contains(e.target) && !toggleBtn.contains(e.target)) {
            navTabs.classList.remove('mobile-open');
            toggleBtn.innerHTML = '<i class="fa-solid fa-bars"></i>';
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && navTabs.classList.contains('mobile-open')) {
            navTabs.classList.remove('mobile-open');
            toggleBtn.innerHTML = '<i class="fa-solid fa-bars"></i>';
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    });
}

function initPlaybookSubtabs() {
    const pillButtons = document.querySelectorAll('.playbook-nav .pill-btn');
    pillButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const subtabId = btn.dataset.subtab;
            state.activeSubtab = subtabId;
            pillButtons.forEach(b => b.classList.toggle('active', b.dataset.subtab === subtabId));
            document.querySelectorAll('.playbook-section').forEach(sec => {
                sec.classList.toggle('active', sec.id === `subtab-${subtabId}`);
                sec.classList.toggle('hidden', sec.id !== `subtab-${subtabId}`);
            });
        });
    });
}

function initBackfillSubtabs() {
    const pillButtons = document.querySelectorAll('.backfill-nav .pill-btn');
    pillButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const subtabId = btn.dataset.subtab;
            if (!subtabId) return;
            pillButtons.forEach(b => b.classList.toggle('active', b.dataset.subtab === subtabId));
            document.querySelectorAll('.backfill-section').forEach(sec => {
                const isMatch = sec.id === `subtab-backfill-${subtabId}`;
                sec.classList.toggle('active', isMatch);
                sec.classList.toggle('hidden', !isMatch);
            });
        });
    });
}

// --------------------------------------------------------------------------
// Authentication (Google OAuth Only)
// --------------------------------------------------------------------------
async function checkConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();
        state.googleClientId = data.google_client_id;
        if (data.admin_emails) {
            state.adminEmails = data.admin_emails;
        }

        if (data.is_google_configured) {
            const tryInitGoogle = () => {
                if (window.google && window.google.accounts) {
                    setupGoogleButton(data.google_client_id);
                } else {
                    setTimeout(tryInitGoogle, 200);
                }
            };
            tryInitGoogle();
        } else {
            const notice = document.getElementById('oauth-notice');
            if (notice && !state.user) {
                notice.classList.remove('hidden');
            }
        }
    } catch (e) {
        console.error('Failed to fetch config:', e);
    }
}

async function initAuth() {
    const savedToken = localStorage.getItem('dsa_session_token');
    if (savedToken) {
        state.token = savedToken;
        try {
            const res = await fetch('/api/auth/me', {
                headers: { 'Authorization': `Bearer ${savedToken}` }
            });
            const data = await res.json();
            if (data.authenticated && data.user) {
                state.user = data.user;
                renderUserSession();
                loadUserStepsAndNotes();
                return;
            }
        } catch (e) {
            console.warn('Saved session token expired or invalid:', e);
        }
    }
    // If invalid or none
    state.user = null;
    state.token = null;
    localStorage.removeItem('dsa_session_token');
    renderUserSession();
}

function setupGoogleButton(clientId) {
    if (!window.google || !clientId) return;

    window.google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleCredentialResponse,
        auto_select: false
    });

    const btnContainer = document.getElementById('google-btn-container');
    if (btnContainer) {
        window.google.accounts.id.renderButton(btnContainer, {
            theme: 'filled_black',
            size: 'medium',
            shape: 'pill'
        });
    }
}

window.handleGoogleCredentialResponse = async function(response) {
    try {
        const res = await fetch('/api/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential: response.credential })
        });
        const data = await res.json();
        if (res.ok && data.success && data.token) {
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem('dsa_session_token', data.token);
            renderUserSession();
            loadUserStepsAndNotes();
            showToast(`Welcome, ${escapeHtml(state.user.name)}! 🎉`);
        } else {
            showToast(data.detail || 'Google sign-in failed. Please try again.', true);
        }
    } catch (e) {
        console.error('Google OAuth error:', e);
        showToast('Google OAuth verification error. Please try again.', true);
    }
};

function renderUserSession() {
    const loggedOutView = document.getElementById('logged-out-view');
    const loggedInView = document.getElementById('logged-in-view');
    const submitWarning = document.getElementById('submit-auth-warning');
    const submitBtn = document.getElementById('submit-btn');
    const adminBadge = document.getElementById('admin-badge');

    if (state.user) {
        loggedOutView.classList.add('hidden');
        loggedInView.classList.remove('hidden');

        document.getElementById('user-name').textContent = state.user.name;
        document.getElementById('user-email').textContent = state.user.email;
        const avatarSrc = state.user.picture || `https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(state.user.email)}`;
        document.getElementById('user-avatar').src = avatarSrc;

        const isAdmin = state.user.is_admin || state.adminEmails.includes(state.user.email.toLowerCase());
        if (adminBadge) {
            adminBadge.classList.toggle('hidden', !isAdmin);
        }
        const adminRefreshBtn = document.getElementById('admin-trigger-refresh-btn');
        if (adminRefreshBtn) {
            adminRefreshBtn.classList.toggle('hidden', !isAdmin);
        }

        if (submitWarning) submitWarning.classList.add('hidden');
        if (submitBtn) submitBtn.disabled = false;
    } else {
        loggedOutView.classList.remove('hidden');
        loggedInView.classList.add('hidden');

        const adminRefreshBtn = document.getElementById('admin-trigger-refresh-btn');
        if (adminRefreshBtn) adminRefreshBtn.classList.add('hidden');

        if (submitWarning) submitWarning.classList.remove('hidden');
        if (submitBtn) submitBtn.disabled = true;
    }

    checkMySyncedRepo();
}

// Logout handler
document.getElementById('logout-btn')?.addEventListener('click', async () => {
    try {
        // Also clear the server-side cookie
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {
        // Continue with local logout even if server call fails
    }
    state.user = null;
    state.token = null;
    localStorage.removeItem('dsa_session_token');
    // Cancel Google One Tap if loaded
    if (window.google && window.google.accounts) {
        window.google.accounts.id.disableAutoSelect();
    }
    renderUserSession();
    loadLeaderboard();
    showToast('Signed out successfully.');
});

// --------------------------------------------------------------------------
// Leaderboard Management
// --------------------------------------------------------------------------
async function loadLeaderboard() {
    const tbody = document.getElementById('leaderboard-tbody');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4"><div class="spinner"></div> Loading leaderboard...</td></tr>`;

    try {
        const res = await fetch('/api/leaderboard');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        state.leaderboard = data.leaderboard || [];
        renderLeaderboard(state.leaderboard);
        updateHeaderStats(state.leaderboard);
    } catch (err) {
        console.error('Leaderboard fetch error:', err);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="color:var(--accent-rose);">Failed to load leaderboard data. Please refresh.</td></tr>`;
    }
}

function updateHeaderStats(items) {
    if (!items || items.length === 0) {
        document.getElementById('stat-total-repos').textContent = '0';
        document.getElementById('stat-top-streak').textContent = '0d';
        document.getElementById('stat-top-score').textContent = '0.00';
        return;
    }
    const rankedItems = items.filter(i => (i.problems || 0) > 0);
    document.getElementById('stat-total-repos').textContent = items.length;

    const maxDays = rankedItems.length > 0 ? Math.max(...rankedItems.map(i => i.active_days || 0), 0) : 0;
    document.getElementById('stat-top-streak').textContent = `${maxDays}d`;

    const topScore = rankedItems.length > 0 ? Math.max(...rankedItems.map(i => i.score || 0), 0) : 0;
    document.getElementById('stat-top-score').textContent = topScore.toFixed(2);
}

function renderLeaderboard(items) {
    const tbody = document.getElementById('leaderboard-tbody');
    if (!items || items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4">No repositories analyzed yet. Be the first — submit yours above!</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map((item, index) => {
        const isUnranked = !item.problems || item.problems === 0 || item.score === 0;

        let medal = `<span class="rank-badge rank-other">${item.rank}</span>`;
        if (isUnranked) {
            medal = `<span class="rank-badge rank-unranked" title="Unranked - 0 verified code solutions in repository">—</span>`;
        } else if (item.rank === 1) {
            medal = `<span class="rank-badge rank-1" title="Gold - 1st Place">🥇</span>`;
        } else if (item.rank === 2) {
            medal = `<span class="rank-badge rank-2" title="Silver - 2nd Place">🥈</span>`;
        } else if (item.rank === 3) {
            medal = `<span class="rank-badge rank-3" title="Bronze - 3rd Place">🥉</span>`;
        }

        const totalProblems = item.problems || 0;
        const easyCount = item.easy_count || 0;
        const medCount = item.medium_count || 0;
        const hardCount = item.hard_count || 0;

        let problemCell = '';
        if (isUnranked) {
            problemCell = `
                <div class="problem-breakdown">
                    <span class="problems-total text-muted" title="0 verified DSA problem solutions">0</span>
                    <span class="badge-none" title="No verified DSA code files found (.py, .cpp, .java, etc.)">No Code</span>
                </div>
            `;
        } else {
            const easyBadge = easyCount > 0 ? `<span class="badge-easy" title="${easyCount} Easy">${easyCount}E</span>` : '';
            const medBadge = medCount > 0 ? `<span class="badge-medium" title="${medCount} Medium">${medCount}M</span>` : '';
            const hardBadge = hardCount > 0 ? `<span class="badge-hard" title="${hardCount} Hard">${hardCount}H</span>` : '';
            problemCell = `
                <div class="problem-breakdown">
                    <span class="problems-total" title="Total unique problems">${totalProblems}</span>
                    <div class="difficulty-badges">${easyBadge}${medBadge}${hardBadge}</div>
                </div>
            `;
        }

        // Format last updated
        let updatedStr = '';
        if (item.updated_at) {
            try {
                const d = new Date(item.updated_at + 'Z');
                updatedStr = `<div class="updated-at">Updated ${formatRelativeTime(d)}</div>`;
            } catch(e) {}
        }

        // Topics - show first 2
        const topics = (item.topics_covered && item.topics_covered !== 'None') 
            ? item.topics_covered.split(',').slice(0, 2).map(t => t.trim()) 
            : [];
        const topicTags = topics.length > 0 
            ? topics.map(t => `<span class="pill-tag">${escapeHtml(t)}</span>`).join('') 
            : `<span class="pill-tag text-muted">Uncategorized</span>`;

        let langCell = '';
        if (isUnranked || !item.languages || item.languages === 'None') {
            langCell = `
                <div class="lang-topics">
                    <span class="lang-tag text-muted"><i class="fa-solid fa-ban" style="font-size:0.7rem;"></i> No Code</span>
                    <div class="topic-tags">${topicTags}</div>
                </div>
            `;
        } else {
            langCell = `
                <div class="lang-topics">
                    <span class="lang-tag"><i class="fa-solid fa-code" style="font-size:0.7rem;"></i> ${escapeHtml(item.languages)}</span>
                    <div class="topic-tags">${topicTags}</div>
                </div>
            `;
        }

        const isOwnerOrAdmin = state.user && (
            (item.submitted_by_email && state.user.email.toLowerCase() === item.submitted_by_email.toLowerCase()) ||
            state.user.is_admin ||
            state.adminEmails.includes(state.user.email.toLowerCase())
        );

        const scoreBadge = isUnranked 
            ? `<span class="score-badge score-zero" title="Unranked: 0 points">0.00</span>` 
            : `<span class="score-badge">${item.score.toFixed(2)}</span>`;

        const rowClass = isUnranked ? 'zero-score-row' : (item.rank <= 3 ? 'top-rank-row' : '');

        return `
            <tr class="${rowClass}">
                <td>${medal}</td>
                <td>
                    <a href="${escapeHtml(item.repo_url)}" target="_blank" rel="noopener noreferrer" class="repo-link">
                        <i class="fa-brands fa-github"></i>
                        <span>${escapeHtml(item.repo_name)}</span>
                    </a>
                    ${updatedStr}
                </td>
                <td>
                    <span style="font-weight:600;">${escapeHtml(item.submitted_by)}</span>
                </td>
                <td>${problemCell}</td>
                <td><strong>${item.active_days}</strong> <span style="color:var(--text-muted); font-size:0.8rem;">days</span></td>
                <td>${langCell}</td>
                <td class="text-right">${scoreBadge}</td>
                <td class="text-center" style="white-space:nowrap;">
                    <button class="btn btn-outline btn-sm inspect-btn" data-id="${item.id}" title="View detailed breakdown">
                        <i class="fa-solid fa-chart-bar"></i>
                    </button>
                    ${isOwnerOrAdmin ? `
                        <button class="btn btn-icon btn-unsync-row" data-id="${item.id}" data-name="${escapeHtml(item.repo_name)}" title="Unsync repository from leaderboard" aria-label="Unsync repository">
                            <i class="fa-solid fa-trash-can" style="color:var(--accent-rose);"></i>
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    }).join('');

    // Attach inspect click listeners
    document.querySelectorAll('.inspect-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = parseInt(btn.dataset.id, 10);
            const found = state.leaderboard.find(item => item.id === id);
            if (found) {
                openBreakdownModal(found);
            }
        });
    });

    // Attach unsync click listeners
    document.querySelectorAll('.btn-unsync-row').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const repoId = parseInt(btn.dataset.id, 10);
            const repoName = btn.dataset.name;
            confirmUnsyncRepo(repoId, repoName);
        });
    });
}

function formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
}

function openBreakdownModal(item) {
    const modal = document.getElementById('breakdown-modal');
    document.getElementById('modal-repo-name').textContent = item.repo_name;
    document.getElementById('modal-repo-url').textContent = item.repo_url;

    const breakdown = item.breakdown || {};
    const multipliers = breakdown.multipliers || {};
    const problemSample = breakdown.problem_sample || [];

    const easyCount = item.easy_count || 0;
    const medCount = item.medium_count || 0;
    const hardCount = item.hard_count || 0;
    const isUnranked = !item.problems || item.problems === 0 || item.score === 0;

    const isOwnerOrAdmin = state.user && (
        (item.submitted_by_email && state.user.email.toLowerCase() === item.submitted_by_email.toLowerCase()) ||
        state.user.is_admin ||
        state.adminEmails.includes(state.user.email.toLowerCase())
    );

    const unrankedBanner = isUnranked ? `
        <div class="modal-unranked-notice">
            <i class="fa-solid fa-triangle-exclamation" style="font-size:1.3rem; margin-top:2px; flex-shrink:0;"></i>
            <div>
                <strong>Unranked Repository (0 Points):</strong> No verified DSA code solutions (.py, .cpp, .java, etc.) were found in this repository.
                Repositories containing only automated README.md templates or empty commits do not qualify for leaderboard points.
                To appear on the active leaderboard, commit your solution code files to GitHub and re-submit!
            </div>
        </div>
    ` : '';

    const content = document.getElementById('modal-body-content');
    content.innerHTML = `
        ${unrankedBanner}

        <div class="modal-stat-grid">
            <div class="modal-stat-box">
                <div class="val">${item.score.toFixed(2)}</div>
                <div class="lbl">Holistic Score</div>
            </div>
            <div class="modal-stat-box">
                <div class="val">${breakdown.consistency_score != null ? breakdown.consistency_score : '0.00'}</div>
                <div class="lbl">Consistency Pts</div>
            </div>
            <div class="modal-stat-box">
                <div class="val">${breakdown.raw_difficulty_points != null ? breakdown.raw_difficulty_points : '0.00'}</div>
                <div class="lbl">Difficulty Pts</div>
            </div>
        </div>

        <div class="modal-diff-row">
            <div class="modal-diff-box easy">
                <span class="diff-num">${easyCount}</span>
                <span class="diff-lbl">Easy</span>
            </div>
            <div class="modal-diff-box medium">
                <span class="diff-num">${medCount}</span>
                <span class="diff-lbl">Medium</span>
            </div>
            <div class="modal-diff-box hard">
                <span class="diff-num">${hardCount}</span>
                <span class="diff-lbl">Hard</span>
            </div>
            <div class="modal-diff-box">
                <span class="diff-num">${item.active_days || 0}</span>
                <span class="diff-lbl">Active Days</span>
            </div>
        </div>

        <div class="modal-multipliers">
            <h4><i class="fa-solid fa-calculator"></i> Score Multipliers</h4>
            <div class="multiplier-grid">
                <div class="mult-item">
                    <span class="mult-label">Active Days</span>
                    <span class="mult-val">${multipliers.active_day_multiplier || '1.00'}x</span>
                </div>
                <div class="mult-item">
                    <span class="mult-label">Breadth</span>
                    <span class="mult-val">${multipliers.breadth_multiplier || '1.00'}x</span>
                </div>
                <div class="mult-item">
                    <span class="mult-label">Topics (≥3)</span>
                    <span class="mult-val">${multipliers.topic_bonus || '1.00'}x</span>
                </div>
                <div class="mult-item">
                    <span class="mult-label">README Docs</span>
                    <span class="mult-val">${multipliers.doc_bonus || '1.00'}x</span>
                </div>
                <div class="mult-item">
                    <span class="mult-label">Polyglot</span>
                    <span class="mult-val">${multipliers.polyglot_bonus || '1.00'}x</span>
                </div>
            </div>
        </div>

        <div class="modal-problems">
            <h4><i class="fa-solid fa-code"></i> Detected Problems (${item.problems || 0} total)</h4>
            <div class="modal-problems-list">
                ${problemSample.length > 0 ? problemSample.map(p => `
                    <div class="problem-chip">
                        <div class="problem-chip-header">
                            <span class="problem-chip-name">${escapeHtml(p.name)}</span>
                            <span class="badge-${(p.difficulty || 'medium').toLowerCase()}">${p.difficulty || 'Medium'}</span>
                        </div>
                        <div class="problem-chip-meta">
                            <span><i class="fa-solid fa-tag"></i> ${escapeHtml(p.topic || 'General DSA')}</span>
                            <span><i class="fa-solid fa-stopwatch"></i> ${escapeHtml(p.time_complexity || 'O(N)')}</span>
                            <span><i class="fa-solid fa-memory"></i> ${escapeHtml(p.space_complexity || 'O(1)')}</span>
                            ${p.source === 'catalog' ? '<span class="src-indexed"><i class="fa-solid fa-bolt"></i> Indexed</span>' : '<span class="src-heuristic"><i class="fa-solid fa-brain"></i> Analyzed</span>'}
                        </div>
                    </div>
                `).join('') : `
                    <div class="problem-chip">
                        <span>${isUnranked ? 'No verified DSA solution code files detected' : `${easyCount} Easy + ${medCount} Medium + ${hardCount} Hard problems`}</span>
                    </div>
                `}
            </div>
            ${problemSample.length > 0 && item.problems > problemSample.length ? `
                <p class="modal-more-hint"><i class="fa-solid fa-ellipsis"></i> Showing ${problemSample.length} of ${item.problems} detected problems</p>
            ` : ''}
        </div>

        ${isOwnerOrAdmin ? `
            <div class="modal-footer-actions">
                <span class="modal-footer-hint"><i class="fa-solid fa-circle-info"></i> Soft-delete removes this repository from the live leaderboard while preserving historical stats. Re-sync anytime.</span>
                <button type="button" class="btn btn-danger-soft" id="modal-unsync-btn" data-id="${item.id}" data-name="${escapeHtml(item.repo_name)}">
                    <i class="fa-solid fa-trash-can"></i> Unsync / Remove Repository
                </button>
            </div>
        ` : ''}
    `;

    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';

    if (isOwnerOrAdmin) {
        document.getElementById('modal-unsync-btn')?.addEventListener('click', () => {
            confirmUnsyncRepo(item.id, item.repo_name);
        });
    }
}

document.getElementById('modal-close-btn')?.addEventListener('click', closeModal);
document.getElementById('breakdown-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'breakdown-modal') closeModal();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

function closeModal() {
    document.getElementById('breakdown-modal').classList.add('hidden');
    document.body.style.overflow = '';
}

// --------------------------------------------------------------------------
// Repository Unsync / Soft-Delete Handlers
// --------------------------------------------------------------------------
async function confirmUnsyncRepo(repoId, repoName) {
    if (!state.user || !state.token) {
        showToast('Please sign in with Google to manage your repositories.', true);
        return;
    }
    const message = `Are you sure you want to unsync and remove "${repoName}" from the leaderboard?\n\n• Your repository will be immediately removed from active rankings.\n• Historical commit stats are safely preserved.\n• You can re-sync anytime by submitting the repository URL again.`;
    if (!confirm(message)) return;

    try {
        const res = await fetch(`/api/submissions/${repoId}/unsync`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || 'Repository successfully unsynced.');
            closeModal();
            await loadLeaderboard();
            await checkMySyncedRepo();
        } else {
            showToast(data.detail || 'Failed to unsync repository.', true);
        }
    } catch (err) {
        console.error('Unsync error:', err);
        showToast('Network error while unsyncing repository.', true);
    }
}

async function checkMySyncedRepo() {
    const container = document.getElementById('active-repo-container');
    if (!container) return;

    if (!state.user || !state.token) {
        container.classList.add('hidden');
        container.innerHTML = '';
        return;
    }

    try {
        const res = await fetch('/api/user/my-repo', {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        if (!res.ok) {
            container.classList.add('hidden');
            return;
        }
        const data = await res.json();
        if (!data.has_repo || !data.repo) {
            container.classList.add('hidden');
            container.innerHTML = '';
            return;
        }

        const repo = data.repo;
        container.innerHTML = `
            <div class="active-repo-banner">
                <div class="active-repo-info">
                    <div class="active-repo-header">
                        <span class="active-repo-badge"><i class="fa-solid fa-circle-check"></i> Synced to Leaderboard</span>
                        <span class="active-repo-name">
                            <a href="${escapeHtml(repo.repo_url)}" target="_blank" rel="noopener noreferrer">
                                <i class="fa-brands fa-github"></i> ${escapeHtml(repo.repo_name)}
                            </a>
                        </span>
                    </div>
                    <div class="active-repo-stats">
                        <span><i class="fa-solid fa-trophy" style="color:var(--accent-amber);"></i> Score: <strong>${repo.score.toFixed(2)}</strong></span>
                        <span><i class="fa-solid fa-code" style="color:var(--accent-cyan);"></i> Solves: <strong>${repo.problems}</strong></span>
                        <span><i class="fa-solid fa-fire" style="color:var(--accent-rose);"></i> Active Days: <strong>${repo.active_days}</strong></span>
                        <span><span class="badge-easy">${repo.easy_count}E</span> <span class="badge-medium">${repo.medium_count}M</span> <span class="badge-hard">${repo.hard_count}H</span></span>
                    </div>
                </div>
                <div class="active-repo-actions">
                    <button type="button" class="btn-unsync-banner" id="banner-unsync-btn" data-id="${repo.id}" data-name="${escapeHtml(repo.repo_name)}" title="Unsync repository">
                        <i class="fa-solid fa-trash-can"></i> Unsync / Remove Repo
                    </button>
                </div>
            </div>
        `;
        container.classList.remove('hidden');

        document.getElementById('banner-unsync-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            confirmUnsyncRepo(repo.id, repo.repo_name);
        });
    } catch (err) {
        console.error('Error checking synced repo:', err);
        container.classList.add('hidden');
    }
}

// Search filter
document.getElementById('leaderboard-search')?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    if (!query) {
        renderLeaderboard(state.leaderboard);
        return;
    }
    const filtered = state.leaderboard.filter(item =>
        item.repo_name.toLowerCase().includes(query) ||
        item.submitted_by.toLowerCase().includes(query) ||
        (item.languages && item.languages.toLowerCase().includes(query)) ||
        (item.topics_covered && item.topics_covered.toLowerCase().includes(query))
    );
    renderLeaderboard(filtered);
});

document.getElementById('refresh-leaderboard-btn')?.addEventListener('click', () => {
    loadLeaderboard();
    showToast('Leaderboard refreshed');
});

// --------------------------------------------------------------------------
// Repo Submission Handler
// --------------------------------------------------------------------------
function initEventListeners() {
    const submitForm = document.getElementById('repo-submit-form');
    if (submitForm) {
        submitForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!state.user || !state.token) {
                showToast('Google OAuth sign-in is mandatory to submit!', true);
                return;
            }

            const input = document.getElementById('repo-url-input');
            const repoUrl = input.value.trim();
            const submitBtn = document.getElementById('submit-btn');
            const resultCard = document.getElementById('submit-result-card');

            if (!repoUrl.startsWith('https://github.com/')) {
                showToast('Please enter a valid GitHub repository URL', true);
                return;
            }

            const btnText = submitBtn.querySelector('.btn-text');
            const btnLoader = submitBtn.querySelector('.btn-loader');

            submitBtn.disabled = true;
            btnText.classList.add('hidden');
            btnLoader.classList.remove('hidden');
            resultCard.classList.add('hidden');

            try {
                const res = await fetch('/api/submit', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${state.token}`
                    },
                    body: JSON.stringify({ repo_url: repoUrl })
                });

                const data = await res.json();
                if (res.ok && data.success) {
                    showToast(data.message);
                    const stats = data.stats;
                    resultCard.className = 'result-card';
                    resultCard.innerHTML = `
                        <h4><i class="fa-solid fa-circle-check" style="color:var(--accent-emerald);"></i> Analysis Complete!</h4>
                        <p style="margin-top:6px; font-weight:600;">${escapeHtml(stats.name)}</p>
                        <div class="result-stats-grid">
                            <div class="result-stat">
                                <div class="result-stat-val">${stats.score.toFixed(2)}</div>
                                <div class="result-stat-lbl">Holistic Score</div>
                            </div>
                            <div class="result-stat">
                                <div class="result-stat-val">${stats.problems}</div>
                                <div class="result-stat-lbl">Problems</div>
                            </div>
                            <div class="result-stat">
                                <div class="result-stat-val">${stats.active_days}</div>
                                <div class="result-stat-lbl">Active Days</div>
                            </div>
                        </div>
                        <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap;">
                            <span class="badge-easy">${stats.easy_count} Easy</span>
                            <span class="badge-medium">${stats.medium_count} Medium</span>
                            <span class="badge-hard">${stats.hard_count} Hard</span>
                        </div>
                        <p style="margin-top:8px; font-size:0.8rem; color:var(--text-muted);">
                            <i class="fa-solid fa-globe"></i> ${escapeHtml(stats.languages)} &nbsp;|&nbsp;
                            <i class="fa-solid fa-tags"></i> ${escapeHtml(stats.topics_covered)}
                        </p>
                    `;
                    resultCard.classList.remove('hidden');
                    input.value = '';
                    loadLeaderboard();
                    checkMySyncedRepo();
                } else {
                    const errMsg = data.detail || 'Could not analyze repository. Check that the repository is public.';
                    resultCard.className = 'result-card error';
                    resultCard.innerHTML = `
                        <h4><i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-rose);"></i> Analysis Failed</h4>
                        <p style="margin-top:4px;">${escapeHtml(errMsg)}</p>
                    `;
                    resultCard.classList.remove('hidden');
                    showToast(errMsg, true);
                }
            } catch (err) {
                console.error('Submit error:', err);
                showToast('Network error while analyzing repository. Please try again.', true);
            } finally {
                submitBtn.disabled = false;
                btnText.classList.remove('hidden');
                btnLoader.classList.add('hidden');
            }
        });
    }

    // Admin manual trigger refresh button
    document.getElementById('admin-trigger-refresh-btn')?.addEventListener('click', async () => {
        if (!state.token) {
            showToast('Admin authorization required', true);
            return;
        }
        const btn = document.getElementById('admin-trigger-refresh-btn');
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Refreshing All...`;
        showToast('Incremental refresh started for all repos...');

        try {
            const res = await fetch('/api/admin/trigger-refresh', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const data = await res.json();
            if (res.ok && data.success) {
                showToast(data.message);
                loadLeaderboard();
                initScheduleTimer();
            } else {
                showToast(data.detail || 'Failed to refresh repos', true);
            }
        } catch (e) {
            showToast('Network error during manual refresh', true);
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-bolt"></i> Run Refresh Now`;
        }
    });
}

// --------------------------------------------------------------------------
// 24-Hour Schedule Status & Countdown Timer (7:00 PM IST)
// --------------------------------------------------------------------------
let scheduleInterval = null;
async function initScheduleTimer() {
    try {
        const res = await fetch('/api/schedule/status');
        if (!res.ok) return;
        const data = await res.json();
        let remainingSeconds = data.seconds_remaining;

        if (scheduleInterval) clearInterval(scheduleInterval);

        const updateDisplay = () => {
            const badge = document.getElementById('schedule-countdown');
            if (!badge) return;

            if (remainingSeconds <= 0) {
                badge.textContent = 'Syncing now (7:00 PM IST)...';
                setTimeout(initScheduleTimer, 15000);
                return;
            }

            const h = Math.floor(remainingSeconds / 3600);
            const m = Math.floor((remainingSeconds % 3600) / 60);
            const s = Math.floor(remainingSeconds % 60);
            const pad = n => String(n).padStart(2, '0');
            badge.innerHTML = `<i class="fa-solid fa-clock"></i> Next Refresh: <strong>${h}h ${pad(m)}m ${pad(s)}s</strong>`;
            remainingSeconds--;
        };

        updateDisplay();
        scheduleInterval = setInterval(updateDisplay, 1000);
    } catch (e) {
        console.warn('Could not fetch schedule status:', e);
    }
}

// --------------------------------------------------------------------------
// Steps & Notes Journal Management
// --------------------------------------------------------------------------
function initChecklistAndNotes() {
    const checkboxes = document.querySelectorAll('#checklist-items input[type="checkbox"]');

    // Load local checklist state
    const savedChecks = JSON.parse(localStorage.getItem('dsa_checklist_state') || '[]');
    checkboxes.forEach((cb, idx) => {
        if (savedChecks[idx] !== undefined) {
            cb.checked = savedChecks[idx];
            cb.closest('.check-item').classList.toggle('completed', cb.checked);
        }
        cb.addEventListener('change', () => {
            cb.closest('.check-item').classList.toggle('completed', cb.checked);
            updateChecklistProgress();
            saveLocalChecklist();
        });
    });
    updateChecklistProgress();

    // Load local notes
    const textarea = document.getElementById('user-notes-textarea');
    const savedNotes = localStorage.getItem('dsa_user_notes');
    if (savedNotes && textarea) {
        textarea.value = savedNotes;
    }

    if (textarea) {
        textarea.addEventListener('input', () => {
            localStorage.setItem('dsa_user_notes', textarea.value);
            const status = document.getElementById('save-status');
            if (status) {
                status.textContent = 'Unsaved changes';
                status.style.color = 'var(--accent-amber)';
            }
        });
    }

    document.getElementById('save-notes-btn')?.addEventListener('click', saveUserStepsAndNotes);
}

function updateChecklistProgress() {
    const checkboxes = document.querySelectorAll('#checklist-items input[type="checkbox"]');
    const total = checkboxes.length;
    const completed = Array.from(checkboxes).filter(c => c.checked).length;
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

    const bar = document.getElementById('checklist-progress-bar');
    const text = document.getElementById('checklist-progress-text');
    if (bar) bar.style.width = `${pct}%`;
    if (text) text.textContent = `${completed} / ${total} Completed (${pct}%)`;
}

function saveLocalChecklist() {
    const checkboxes = document.querySelectorAll('#checklist-items input[type="checkbox"]');
    const states = Array.from(checkboxes).map(c => c.checked);
    localStorage.setItem('dsa_checklist_state', JSON.stringify(states));
}

async function loadUserStepsAndNotes() {
    if (!state.token) return;
    try {
        const res = await fetch('/api/user/steps', {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (res.ok) {
            const data = await res.json();
            if (data.notes) {
                const textarea = document.getElementById('user-notes-textarea');
                if (textarea) textarea.value = data.notes;
                localStorage.setItem('dsa_user_notes', data.notes);
            }
            if (data.steps && Array.isArray(data.steps) && data.steps.length > 0) {
                const checkboxes = document.querySelectorAll('#checklist-items input[type="checkbox"]');
                checkboxes.forEach((cb, idx) => {
                    if (data.steps[idx] !== undefined) {
                        cb.checked = data.steps[idx];
                        cb.closest('.check-item').classList.toggle('completed', cb.checked);
                    }
                });
                updateChecklistProgress();
                saveLocalChecklist();
            }
            const status = document.getElementById('save-status');
            if (status) {
                status.textContent = 'Synced with cloud';
                status.style.color = 'var(--accent-emerald)';
            }
        }
    } catch (e) {
        console.warn('Error fetching cloud steps:', e);
    }
}

async function saveUserStepsAndNotes() {
    const textarea = document.getElementById('user-notes-textarea');
    const checkboxes = document.querySelectorAll('#checklist-items input[type="checkbox"]');
    const steps = Array.from(checkboxes).map(c => c.checked);
    const notes = textarea ? textarea.value : '';

    saveLocalChecklist();
    if (textarea) localStorage.setItem('dsa_user_notes', notes);

    if (!state.token || !state.user) {
        showToast('Saved locally! Sign in with Google to sync across devices.');
        return;
    }

    const btn = document.getElementById('save-notes-btn');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/user/steps', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify({
                steps_json: JSON.stringify(steps),
                notes_markdown: notes
            })
        });
        if (res.ok) {
            showToast('Notes & steps synced to your profile!');
            const status = document.getElementById('save-status');
            if (status) {
                status.textContent = 'Saved & synced';
                status.style.color = 'var(--accent-emerald)';
            }
        } else {
            const data = await res.json();
            showToast(data.detail || 'Failed to save to cloud', true);
        }
    } catch (e) {
        showToast('Network error while saving notes', true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// --------------------------------------------------------------------------
// UI Helpers
// --------------------------------------------------------------------------
function showToast(message, isError = false) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
    toast.innerHTML = `
        <i class="fa-solid ${isError ? 'fa-circle-xmark' : 'fa-circle-check'}"></i>
        <span>${escapeHtml(message)}</span>
    `;
    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => toast.classList.add('toast-visible'));

    setTimeout(() => {
        toast.classList.remove('toast-visible');
        setTimeout(() => toast.remove(), 350);
    }, 3800);
}

function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
