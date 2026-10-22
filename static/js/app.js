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
    if (tabId === 'submit') {
        checkMySyncedRepo();
        checkActiveUserJob();
    }
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
    checkActiveUserJob();
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

    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4"><div class="spinner"></div> Loading leaderboard...</td></tr>`;

    try {
        const res = await fetch('/api/leaderboard');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        state.leaderboard = data.leaderboard || [];
        renderLeaderboard(state.leaderboard);
        updateHeaderStats(state.leaderboard);
    } catch (err) {
        console.error('Leaderboard fetch error:', err);
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color:var(--accent-rose);">Failed to load leaderboard data. Please refresh.</td></tr>`;
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
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4">No repositories analyzed yet. Be the first — submit yours above!</td></tr>`;
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
                <td>${problemCell}</td>
                <td><strong>${item.active_days}</strong> <span style="color:var(--text-muted); font-size:0.8rem;">days</span></td>
                <td class="text-right">${scoreBadge}</td>
                <td class="text-center" style="white-space:nowrap;">
                    <button class="btn btn-outline btn-sm inspect-btn" data-id="${item.id}" title="View detailed breakdown & score calculation">
                        <i class="fa-solid fa-chart-bar"></i> Details
                    </button>
                    ${isOwnerOrAdmin ? `
                        <button class="btn btn-icon btn-refresh-row" data-id="${item.id}" data-url="${escapeHtml(item.repo_url)}" data-name="${escapeHtml(item.repo_name)}" title="Refresh repo commits & rank" aria-label="Refresh repo">
                            <i class="fa-solid fa-arrows-rotate" style="color:var(--accent-cyan);"></i>
                        </button>
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

    // Attach row refresh click listeners
    document.querySelectorAll('.btn-refresh-row').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!state.token) {
                showToast('Please sign in with Google to refresh', true);
                return;
            }
            const repoId = parseInt(btn.dataset.id, 10);
            const repoUrl = btn.dataset.url;
            const repoName = btn.dataset.name;
            const origHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i>`;
            showToast(`Refreshing '${repoName}'...`);
            try {
                const res = await fetch(`/api/submissions/${repoId}/refresh`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${state.token}`
                    }
                });
                const data = await res.json();
                if (data.success && data.job_id) {
                    pollJobProgress(data.job_id, repoUrl);
                } else {
                    showToast(data.detail || 'Refresh request failed', true);
                    btn.disabled = false;
                    btn.innerHTML = origHtml;
                }
            } catch (err) {
                showToast('Network error during refresh', true);
                btn.disabled = false;
                btn.innerHTML = origHtml;
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

function normalizeListString(val) {
    if (!val || val === 'None') return [];
    if (Array.isArray(val)) return val.map(s => String(s).trim()).filter(Boolean);
    let str = String(val).trim();
    let parts = str.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length > 1 && parts.every(p => p.length === 1)) {
        return [parts.join('')];
    }
    if (str.includes(', ,')) {
        str = str.replace(/,\s*,/g, ',');
        parts = str.split(',').map(s => s.trim()).filter(Boolean);
    }
    return parts;
}

function openBreakdownModal(item) {
    const modal = document.getElementById('breakdown-modal');
    document.getElementById('modal-repo-name').textContent = item.repo_name;
    document.getElementById('modal-repo-url').innerHTML = `
        <a href="${escapeHtml(item.repo_url)}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-cyan); text-decoration:none;">
            <i class="fa-brands fa-github"></i> ${escapeHtml(item.repo_url)} <i class="fa-solid fa-arrow-up-right-from-square" style="font-size:0.75rem;"></i>
        </a>
    `;

    const breakdown = item.breakdown || {};
    const multipliers = breakdown.multipliers || {};
    const calcSteps = breakdown.calculation_steps || {};
    const problemSample = breakdown.problem_sample || [];

    const easyCount = item.easy_count || 0;
    const medCount = item.medium_count || 0;
    const hardCount = item.hard_count || 0;
    const totalProblems = item.problems || 0;
    const activeDays = item.active_days || 0;
    const isUnranked = !totalProblems || totalProblems === 0 || item.score === 0;

    const languages = normalizeListString(item.languages);
    const topics = normalizeListString(item.topics_covered);

    // Math calculation values
    const easyPts = easyCount * 1.0;
    const medPts = medCount * 2.5;
    const hardPts = hardCount * 5.0;
    const diffPoints = Number(calcSteps.difficulty_points != null ? calcSteps.difficulty_points : (easyPts + medPts + hardPts)).toFixed(2);
    const consistencyBase = Number(calcSteps.consistency_base != null ? calcSteps.consistency_base : (breakdown.consistency_score != null ? breakdown.consistency_score : 0.0)).toFixed(2);

    const activeDayMult = Number(multipliers.active_day_multiplier || (1.0 + Math.min(0.40, activeDays * 0.03))).toFixed(2);
    const breadthMult = Number(multipliers.breadth_multiplier || (1.0 + Math.min(0.30, totalProblems * 0.015))).toFixed(2);
    const topicMult = Number(multipliers.topic_bonus || (topics.length >= 3 ? 1.06 : 1.00)).toFixed(2);
    const docMult = Number(multipliers.doc_bonus || 1.00).toFixed(2);
    const polyglotMult = Number(multipliers.polyglot_bonus || (languages.length > 1 ? 1.05 : 1.00)).toFixed(2);

    const weightedConsistency = Number(0.50 * parseFloat(consistencyBase) * parseFloat(activeDayMult)).toFixed(2);
    const weightedDiff = Number(0.50 * parseFloat(diffPoints)).toFixed(2);
    const rawComposite = Number(parseFloat(weightedConsistency) + parseFloat(weightedDiff)).toFixed(2);
    const totalMultiplier = (parseFloat(breadthMult) * parseFloat(topicMult) * parseFloat(docMult) * parseFloat(polyglotMult)).toFixed(2);

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

    let updatedStr = 'recently';
    if (item.updated_at) {
        try {
            const d = new Date(item.updated_at + 'Z');
            updatedStr = formatRelativeTime(d);
        } catch(e) {}
    }

    const content = document.getElementById('modal-body-content');
    content.innerHTML = `
        ${unrankedBanner}

        <!-- Header Metadata Badges -->
        <div class="modal-header-meta">
            <span class="meta-pill rank-pill"><i class="fa-solid fa-trophy"></i> Rank #${item.rank}</span>
            <span class="meta-pill"><i class="fa-solid fa-user-check"></i> Submitter: <strong>${escapeHtml(item.submitted_by || 'Anonymous')}</strong></span>
            <span class="meta-pill"><i class="fa-solid fa-calendar-days"></i> ${activeDays} Active Day${activeDays === 1 ? '' : 's'}</span>
            <span class="meta-pill text-muted"><i class="fa-solid fa-clock-rotate-left"></i> Updated ${updatedStr}</span>
        </div>

        <!-- Transparent Mathematical Scoring Walkthrough (Front & Center) -->
        <div class="modal-section-card" style="margin-top: 14px; border-color: rgba(99, 102, 241, 0.4); background: rgba(99, 102, 241, 0.04);">
            <div class="modal-section-title" style="font-size: 1rem; color: #a5b4fc;">
                <i class="fa-solid fa-calculator" style="color:var(--accent-primary);"></i> How Holistic Score (${item.score.toFixed(2)}) is Calculated
            </div>
            
            <div class="master-formula-box">
                <div class="master-formula-title"><i class="fa-solid fa-square-root-variable"></i> Master Holistic Ranking Formula</div>
                <div style="font-weight:600; color:#fff; margin-bottom:6px;">
                    Final Score = [ (0.50 × Consistency Base × Active Days Mult) + (0.50 × Difficulty Pts) ] × Breadth × Topics × Docs × Polyglot
                </div>
                <div style="color: #38bdf8; font-weight:700; word-break: break-all;">
                    Plugged-In Values: [ (0.50 × ${consistencyBase} × ${activeDayMult}) + (0.50 × ${diffPoints}) ] × ${breadthMult} × ${topicMult} × ${docMult} × ${polyglotMult} = <span style="color:#34d399; font-size:0.95rem;">${item.score.toFixed(2)} pts</span>
                </div>
            </div>

            <div class="formula-step-grid">
                <div class="formula-step-card">
                    <span class="formula-step-num">Step 1 • Problem Difficulty (50% Base Weight)</span>
                    <span class="formula-step-title">Problem Points Sum</span>
                    <div class="formula-step-calc">
                        (${easyCount} Easy × 1.0) + (${medCount} Medium × 2.5) + (${hardCount} Hard × 5.0) = ${diffPoints} pts
                    </div>
                    <div class="formula-step-note">
                        Difficulty weights: Easy = 1.0 pt, Medium = 2.5 pts, Hard = 5.0 pts.<br>
                        <strong>50% Base Weight:</strong> 0.50 × ${diffPoints} = <span style="color:#fde047; font-weight:700;">${weightedDiff} pts</span>.
                    </div>
                </div>

                <div class="formula-step-card">
                    <span class="formula-step-num">Step 2 • Commit Consistency (50% Base Weight)</span>
                    <span class="formula-step-title">Anti-Burst Daily Streaks</span>
                    <div class="formula-step-calc">
                        0.50 × ${consistencyBase} (Base) × ${activeDayMult}x (${activeDays} Active Days) = ${weightedConsistency} pts
                    </div>
                    <div class="formula-step-note">
                        Points/day are damped with <code>(Daily Pts)^0.72</code> (capped at 25/day) to prevent 1-day spam bursts.<br>
                        <strong>Active Days Multiplier:</strong> 1.0 + min(0.40, ${activeDays} × 0.03) = <strong>${activeDayMult}x</strong>.
                    </div>
                </div>

                <div class="formula-step-card">
                    <span class="formula-step-num">Step 3 • Balanced Base Composite</span>
                    <span class="formula-step-title">50% Consistency + 50% Difficulty</span>
                    <div class="formula-step-calc">
                        ${weightedConsistency} (Consistency) + ${weightedDiff} (Difficulty) = ${rawComposite} pts
                    </div>
                    <div class="formula-step-note">
                        Equally balances steady daily problem-solving habits with the difficulty of questions solved.
                    </div>
                </div>

                <div class="formula-step-card">
                    <span class="formula-step-num">Step 4 • Applied Multipliers</span>
                    <span class="formula-step-title">Diversity &amp; Documentation Bonuses</span>
                    <div class="formula-step-calc">
                        Breadth (${breadthMult}x) × Topics (${topicMult}x) × Docs (${docMult}x) × Polyglot (${polyglotMult}x) = ${totalMultiplier}x
                    </div>
                    <div class="formula-step-note">
                        • <strong>Breadth:</strong> ${breadthMult}x (+1.5% per unique problem up to +30%)<br>
                        • <strong>Topics:</strong> ${topicMult}x (${topics.length >= 3 ? '✓ +6% bonus for ≥3 topics' : 'Need ≥3 topics for +6%'})<br>
                        • <strong>README:</strong> ${docMult}x (${parseFloat(docMult) > 1.0 ? '✓ +4% bonus for docs' : 'No docs'})<br>
                        • <strong>Polyglot:</strong> ${polyglotMult}x (${languages.length > 1 ? '✓ +5% bonus' : 'Single language'})
                    </div>
                </div>
            </div>

            <div class="final-calc-banner">
                <div>
                    <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:2px;">Final Calibrated Score Result</div>
                    <div class="final-calc-eq">
                        ${rawComposite} (Base) × ${breadthMult} (Breadth) × ${topicMult} (Topics) × ${docMult} (Docs) × ${polyglotMult} (Polyglot) =
                    </div>
                </div>
                <div class="final-calc-result">${item.score.toFixed(2)} pts</div>
            </div>
        </div>

        <!-- High-level Overview Score Cards -->
        <div class="modal-overview-grid">
            <div class="overview-stat-box highlight-score">
                <div class="val">${item.score.toFixed(2)}</div>
                <div class="lbl">Final Holistic Score</div>
            </div>
            <div class="overview-stat-box">
                <div class="val">${diffPoints}</div>
                <div class="lbl">Problem Difficulty Pts</div>
            </div>
            <div class="overview-stat-box">
                <div class="val">${consistencyBase}</div>
                <div class="lbl">Consistency Base Pts</div>
            </div>
            <div class="overview-stat-box">
                <div class="val">${totalMultiplier}x</div>
                <div class="lbl">Quality Multiplier</div>
            </div>
        </div>

        <!-- Difficulty Breakdown Row -->
        <div class="modal-diff-row">
            <div class="modal-diff-box easy">
                <span class="diff-num">${easyCount}</span>
                <span class="diff-lbl">Easy (${easyPts.toFixed(1)} pts)</span>
            </div>
            <div class="modal-diff-box medium">
                <span class="diff-num">${medCount}</span>
                <span class="diff-lbl">Medium (${medPts.toFixed(1)} pts)</span>
            </div>
            <div class="modal-diff-box hard">
                <span class="diff-num">${hardCount}</span>
                <span class="diff-lbl">Hard (${hardPts.toFixed(1)} pts)</span>
            </div>
            <div class="modal-diff-box">
                <span class="diff-num">${totalProblems}</span>
                <span class="diff-lbl">Total Solved</span>
            </div>
        </div>

        <!-- Tech Stack & DSA Topics Section -->
        <div class="modal-section-card">
            <div class="modal-section-title">
                <i class="fa-solid fa-code" style="color:var(--accent-cyan);"></i> Tech Stack &amp; Topics Covered
            </div>
            <div style="display:flex; flex-direction:column; gap:10px;">
                <div>
                    <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px; font-weight:700;">Languages Detected</div>
                    <div class="pill-group">
                        ${languages.length > 0 ? languages.map(l => `
                            <span class="lang-pill"><i class="fa-solid fa-terminal" style="font-size:0.7rem;"></i> ${escapeHtml(l)}</span>
                        `).join('') : '<span class="text-muted" style="font-size:0.8rem;">No code files found</span>'}
                    </div>
                </div>
                <div>
                    <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px; font-weight:700;">DSA Topics Covered (${topics.length})</div>
                    <div class="pill-group">
                        ${topics.length > 0 ? topics.map(t => `
                            <span class="topic-pill"><i class="fa-solid fa-layer-group" style="font-size:0.7rem;"></i> ${escapeHtml(t)}</span>
                        `).join('') : '<span class="text-muted" style="font-size:0.8rem;">General DSA</span>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- Detected Problems Directory -->
        <div class="modal-section-card">
            <div class="modal-section-title">
                <i class="fa-solid fa-list-check" style="color:var(--accent-emerald);"></i> Detected Problems (${totalProblems} total)
            </div>

            <div class="problem-toolbar">
                <input type="text"
                       class="problem-search-input"
                       id="modal-problem-search"
                       placeholder="Search problems by title or topic..."
                       autocomplete="off"
                       spellcheck="false">
                <div class="diff-filters">
                    <button type="button" class="diff-filter-btn active" data-filter="all">All (${totalProblems})</button>
                    <button type="button" class="diff-filter-btn" data-filter="easy">Easy (${easyCount})</button>
                    <button type="button" class="diff-filter-btn" data-filter="medium">Medium (${medCount})</button>
                    <button type="button" class="diff-filter-btn" data-filter="hard">Hard (${hardCount})</button>
                </div>
            </div>

            <div class="modal-problems-scroll">
                <div class="problem-grid-list" id="modal-problems-list">
                    <!-- Populated dynamically -->
                </div>
            </div>
        </div>

        <!-- Footer Actions -->
        <div class="modal-footer-actions">
            <div>
                ${isOwnerOrAdmin ? `
                    <span class="modal-footer-hint"><i class="fa-solid fa-shield-halved"></i> Owner/Admin controls: refresh stats or unsync repository.</span>
                ` : `
                    <span class="modal-footer-hint"><i class="fa-solid fa-circle-info"></i> All problem detection fingerprints are verified against AST &amp; catalog signatures.</span>
                `}
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
                ${isOwnerOrAdmin ? `
                    <button type="button" class="btn btn-outline btn-sm" id="modal-refresh-btn" data-id="${item.id}" data-url="${escapeHtml(item.repo_url)}">
                        <i class="fa-solid fa-arrows-rotate" style="color:var(--accent-cyan);"></i> Refresh Commits
                    </button>
                    <button type="button" class="btn btn-danger-soft" id="modal-unsync-btn" data-id="${item.id}" data-name="${escapeHtml(item.repo_name)}">
                        <i class="fa-solid fa-trash-can"></i> Unsync
                    </button>
                ` : ''}
                <button type="button" class="btn btn-outline btn-sm" onclick="closeModal()">
                    Close
                </button>
            </div>
        </div>
    `;

    // Render problems into grid
    function renderProblems(filterDiff = 'all', searchQuery = '') {
        const listEl = document.getElementById('modal-problems-list');
        if (!listEl) return;

        let filtered = problemSample;
        if (filterDiff !== 'all') {
            filtered = filtered.filter(p => (p.difficulty || 'medium').toLowerCase() === filterDiff.toLowerCase());
        }
        if (searchQuery.trim()) {
            const q = searchQuery.toLowerCase().trim();
            filtered = filtered.filter(p => 
                (p.name || '').toLowerCase().includes(q) ||
                (p.slug || '').toLowerCase().includes(q) ||
                (p.topic || '').toLowerCase().includes(q)
            );
        }

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="grid-column: 1 / -1; text-align:center; padding: 24px; color:var(--text-muted); font-size:0.82rem;">
                    <i class="fa-solid fa-magnifying-glass" style="font-size:1.2rem; margin-bottom:6px; display:block;"></i>
                    No problems match the current filter or search criteria.
                </div>
            `;
            return;
        }

        listEl.innerHTML = filtered.map(p => {
            const diffClass = (p.difficulty || 'medium').toLowerCase();
            return `
                <div class="problem-card">
                    <div class="problem-card-header">
                        <span class="problem-card-title" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</span>
                        <span class="badge-${diffClass}">${escapeHtml(p.difficulty || 'Medium')}</span>
                    </div>
                    <div class="problem-card-meta">
                        <span><i class="fa-solid fa-tag"></i> ${escapeHtml(p.topic || 'General DSA')}</span>
                        <span><i class="fa-solid fa-stopwatch"></i> ${escapeHtml(p.time_complexity || 'O(N)')}</span>
                        <span><i class="fa-solid fa-memory"></i> ${escapeHtml(p.space_complexity || 'O(1)')}</span>
                        ${p.source === 'catalog' ? '<span class="src-indexed"><i class="fa-solid fa-bolt"></i> Indexed</span>' : '<span class="src-heuristic"><i class="fa-solid fa-brain"></i> Analyzed</span>'}
                    </div>
                </div>
            `;
        }).join('');
    }

    renderProblems();

    // Attach search and filter events
    let currentFilter = 'all';
    let currentSearch = '';

    const searchInput = document.getElementById('modal-problem-search');
    searchInput?.addEventListener('input', (e) => {
        currentSearch = e.target.value;
        renderProblems(currentFilter, currentSearch);
    });

    document.querySelectorAll('.diff-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.diff-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            renderProblems(currentFilter, currentSearch);
        });
    });

    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';

    // Owner / Admin action buttons in modal
    if (isOwnerOrAdmin) {
        document.getElementById('modal-unsync-btn')?.addEventListener('click', () => {
            confirmUnsyncRepo(item.id, item.repo_name);
        });

        document.getElementById('modal-refresh-btn')?.addEventListener('click', async (e) => {
            const btn = e.currentTarget;
            const origHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Refreshing...`;
            try {
                const res = await fetch(`/api/submissions/${item.id}/refresh`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${state.token}` }
                });
                const data = await res.json();
                if (res.ok) {
                    showToast('Refresh initiated! Polling for updated stats...');
                    pollJobProgress(data.job_id, async () => {
                        await loadLeaderboard();
                        closeModal();
                        showToast('Repository refresh complete! Updated score reflected.');
                    });
                } else {
                    showToast(data.detail || 'Failed to refresh repository', true);
                    btn.disabled = false;
                    btn.innerHTML = origHtml;
                }
            } catch (err) {
                console.error('Refresh error:', err);
                showToast('Network error while refreshing repository', true);
                btn.disabled = false;
                btn.innerHTML = origHtml;
            }
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
                <div class="active-repo-actions" style="display:flex; gap:0.5rem; align-items:center;">
                    <button type="button" class="btn btn-secondary btn-sm" id="banner-refresh-btn" data-id="${repo.id}" data-name="${escapeHtml(repo.repo_name)}" title="Refresh repository commits and score">
                        <i class="fa-solid fa-arrows-rotate"></i> Refresh Commits
                    </button>
                    <button type="button" class="btn-unsync-banner" id="banner-unsync-btn" data-id="${repo.id}" data-name="${escapeHtml(repo.repo_name)}" title="Unsync repository">
                        <i class="fa-solid fa-trash-can"></i> Unsync / Remove Repo
                    </button>
                </div>
            </div>
        `;
        container.classList.remove('hidden');

        document.getElementById('banner-refresh-btn')?.addEventListener('click', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('banner-refresh-btn');
            if (!btn) return;
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Refreshing...`;
            showToast('Refreshing repository commits and score...');
            try {
                const res = await fetch('/api/user/refresh-repo', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${state.token}`
                    }
                });
                const data = await res.json();
                if (data.success && data.job_id) {
                    pollJobProgress(data.job_id, repo.repo_url);
                } else {
                    showToast(data.detail || 'Refresh failed', true);
                    btn.disabled = false;
                    btn.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Refresh Commits`;
                }
            } catch (err) {
                showToast('Network error during refresh', true);
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Refresh Commits`;
            }
        });

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
// Background Analysis Job Polling & UI Renderers
// --------------------------------------------------------------------------
let currentJobPollInterval = null;

function renderJobProgress(stage, percent, repoUrl) {
    const resultCard = document.getElementById('submit-result-card');
    if (!resultCard) return;
    const cleanName = repoUrl ? repoUrl.replace('https://github.com/', '') : 'Repository';
    resultCard.className = 'result-card processing';
    resultCard.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between;">
            <h4 style="color:var(--accent-cyan); display:flex; align-items:center; gap:8px;">
                <i class="fa-solid fa-circle-notch fa-spin"></i> Background Deep Analysis
            </h4>
            <span style="font-family:var(--font-mono); font-size:0.82rem; font-weight:700; color:var(--accent-cyan);">${percent}%</span>
        </div>
        <p style="margin-top:6px; font-weight:600; font-size:0.86rem; color:var(--text-primary);">${escapeHtml(cleanName)}</p>
        <div class="progress-track">
            <div class="progress-fill" style="width:${Math.max(8, percent)}%;"></div>
        </div>
        <div class="progress-meta">
            <span><i class="fa-solid fa-gear fa-spin" style="font-size:0.75rem; margin-right:4px;"></i> ${escapeHtml(stage || 'Processing in background...')}</span>
            <span>Running on worker</span>
        </div>
    `;
    resultCard.classList.remove('hidden');
}

function renderJobResult(stats) {
    const resultCard = document.getElementById('submit-result-card');
    if (!resultCard) return;
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
}

function renderJobError(errMsg) {
    const resultCard = document.getElementById('submit-result-card');
    if (!resultCard) return;
    resultCard.className = 'result-card error';
    resultCard.innerHTML = `
        <h4><i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-rose);"></i> Analysis Failed</h4>
        <p style="margin-top:4px;">${escapeHtml(errMsg || 'An error occurred during repository analysis.')}</p>
    `;
    resultCard.classList.remove('hidden');
}

function setSubmitButtonState(isBusy) {
    const submitBtn = document.getElementById('submit-btn');
    if (!submitBtn) return;
    const btnText = submitBtn.querySelector('.btn-text');
    const btnLoader = submitBtn.querySelector('.btn-loader');
    submitBtn.disabled = isBusy;
    if (isBusy) {
        btnText?.classList.add('hidden');
        btnLoader?.classList.remove('hidden');
    } else {
        btnText?.classList.remove('hidden');
        btnLoader?.classList.add('hidden');
    }
}

async function pollAnalysisJob(jobId, repoUrl) {
    if (currentJobPollInterval) {
        clearInterval(currentJobPollInterval);
        currentJobPollInterval = null;
    }

    setSubmitButtonState(true);
    renderJobProgress('Analyzing repository in background...', 15, repoUrl);

    let attempts = 0;
    const maxAttempts = 150; // 150 * 2s = 5 minutes polling max

    currentJobPollInterval = setInterval(async () => {
        attempts++;
        try {
            const res = await fetch(`/api/jobs/${jobId}`);
            if (!res.ok) {
                if (attempts >= maxAttempts) {
                    clearInterval(currentJobPollInterval);
                    currentJobPollInterval = null;
                    setSubmitButtonState(false);
                    renderJobError('Polling timed out. The analysis is continuing on the server; please refresh in a moment.');
                }
                return;
            }

            const data = await res.json();
            if (data.status === 'completed') {
                clearInterval(currentJobPollInterval);
                currentJobPollInterval = null;
                setSubmitButtonState(false);
                showToast('Holistic analysis complete!');
                renderJobResult(data.stats);
                const input = document.getElementById('repo-url-input');
                if (input) input.value = '';
                loadLeaderboard();
                checkMySyncedRepo();
            } else if (data.status === 'failed') {
                clearInterval(currentJobPollInterval);
                currentJobPollInterval = null;
                setSubmitButtonState(false);
                const errMsg = data.error || 'Repository analysis failed.';
                renderJobError(errMsg);
                showToast(errMsg, true);
            } else {
                // queued or analyzing
                const percent = Math.min(95, Math.max(10, data.progress_percent || 15));
                const stage = data.progress_stage || 'Processing repository in background...';
                renderJobProgress(stage, percent, data.repo_url || repoUrl);
            }
        } catch (e) {
            console.warn('Job poll error:', e);
        }

        if (attempts >= maxAttempts) {
            clearInterval(currentJobPollInterval);
            currentJobPollInterval = null;
            setSubmitButtonState(false);
        }
    }, 2000);
}

async function checkActiveUserJob() {
    if (!state.user || !state.token) return;
    try {
        const res = await fetch('/api/user/active-job', {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (!res.ok) return;
        const data = await res.json();
        if (data.has_active_job && data.job) {
            pollAnalysisJob(data.job.job_id, data.job.repo_url);
        }
    } catch (e) {
        console.warn('Active job check warning:', e);
    }
}

// --------------------------------------------------------------------------
// Repo Submission Handler & Event Listeners
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

            if (!repoUrl.startsWith('https://github.com/')) {
                showToast('Please enter a valid GitHub repository URL', true);
                return;
            }

            setSubmitButtonState(true);
            renderJobProgress('Connecting to worker & queueing analysis...', 10, repoUrl);

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
                if (res.ok && data.success && data.job_id) {
                    showToast(data.message || 'Analysis queued in background!');
                    pollAnalysisJob(data.job_id, repoUrl);
                } else {
                    setSubmitButtonState(false);
                    const errMsg = data.detail || 'Could not queue repository for analysis.';
                    renderJobError(errMsg);
                    showToast(errMsg, true);
                }
            } catch (err) {
                console.error('Submit error:', err);
                setSubmitButtonState(false);
                renderJobError('Network error connecting to analysis server.');
                showToast('Network error while analyzing repository. Please try again.', true);
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
        showToast('Incremental refresh started in background for all repositories...');

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
                showToast(data.detail || 'Failed to trigger refresh', true);
            }
        } catch (e) {
            showToast('Network error during refresh trigger', true);
        } finally {
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-bolt"></i> Run Refresh Now`;
            }, 3000);
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
