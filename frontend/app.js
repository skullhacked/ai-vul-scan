/**
 * AI Vulnerability Scanner - Frontend Application
 * Complete application with authentication, routing, and scanning
 */

const API_BASE = window.location.origin;
let authToken = localStorage.getItem('authToken');
let currentUser = null;
let currentScanId = null;
let wsConnection = null;
let radarAnimation = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupAuthListeners();
    setupNavigation();
    setupScanListeners();
    initializeRadar();
    updateDashboardStats();
});

// ==================== AUTHENTICATION ====================

function checkAuth() {
    if (authToken) {
        verifyToken();
    } else {
        showPage('loginPage');
    }
}

async function verifyToken() {
    try {
        const response = await fetch(`${API_BASE}/api/auth/me`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            currentUser = await response.json();
            showPage('dashboardPage');
            updateNavUser();
        } else {
            logout();
        }
    } catch (error) {
        console.error('Token verification failed:', error);
        logout();
    }
}

function setupAuthListeners() {
    // Tab switching
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            switchAuthTab(tabName);
        });
    });
    
    // Login
    const loginBtn = document.getElementById('loginBtn');
    const loginPassword = document.getElementById('loginPassword');
    if (loginBtn) loginBtn.addEventListener('click', handleLogin);
    if (loginPassword) loginPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });
    
    // Signup
    const signupBtn = document.getElementById('signupBtn');
    const signupPassword = document.getElementById('signupPassword');
    if (signupBtn) signupBtn.addEventListener('click', handleSignup);
    if (signupPassword) signupPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSignup();
    });
    
    // Forgot Password
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const backToLoginLink = document.getElementById('backToLoginLink');
    const sendResetBtn = document.getElementById('sendResetBtn');
    if (forgotPasswordLink) forgotPasswordLink.addEventListener('click', (e) => {
        e.preventDefault();
        showForgotPasswordForm();
    });
    if (backToLoginLink) backToLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        switchAuthTab('login');
    });
    if (sendResetBtn) sendResetBtn.addEventListener('click', handleForgotPassword);
    
    // Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
}

function switchAuthTab(tab) {
    // Update tabs
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    const tabElement = document.querySelector(`[data-tab="${tab}"]`);
    if (tabElement) tabElement.classList.add('active');
    
    // Hide forgot password form
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    if (forgotPasswordForm) forgotPasswordForm.style.display = 'none';
    
    // Show/hide forms - only one visible at a time
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    
    if (tab === 'login') {
        if (loginForm) {
            loginForm.style.display = 'block';
            loginForm.classList.add('active');
        }
        if (signupForm) {
            signupForm.style.display = 'none';
            signupForm.classList.remove('active');
        }
    } else {
        if (signupForm) {
            signupForm.style.display = 'block';
            signupForm.classList.add('active');
        }
        if (loginForm) {
            loginForm.style.display = 'none';
            loginForm.classList.remove('active');
        }
    }
    
    // Clear errors and inputs
    const loginError = document.getElementById('loginError');
    const signupError = document.getElementById('signupError');
    const signupSuccess = document.getElementById('signupSuccess');
    if (loginError) loginError.style.display = 'none';
    if (signupError) signupError.style.display = 'none';
    if (signupSuccess) signupSuccess.style.display = 'none';
    
    const loginUsername = document.getElementById('loginUsername');
    const loginPassword = document.getElementById('loginPassword');
    const signupUsername = document.getElementById('signupUsername');
    const signupEmail = document.getElementById('signupEmail');
    const signupPassword = document.getElementById('signupPassword');
    
    if (loginUsername) loginUsername.value = '';
    if (loginPassword) loginPassword.value = '';
    if (signupUsername) signupUsername.value = '';
    if (signupEmail) signupEmail.value = '';
    if (signupPassword) signupPassword.value = '';
}

function showForgotPasswordForm() {
    // Hide all other forms
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    
    if (loginForm) loginForm.style.display = 'none';
    if (signupForm) signupForm.style.display = 'none';
    if (forgotPasswordForm) {
        forgotPasswordForm.style.display = 'block';
        forgotPasswordForm.classList.add('active');
    }
    
    // Hide tabs
    document.querySelectorAll('.auth-tab').forEach(t => t.style.display = 'none');
}

async function handleForgotPassword() {
    const emailInput = document.getElementById('forgotPasswordEmail');
    if (!emailInput) return;
    
    const email = emailInput.value.trim();
    const errorDiv = document.getElementById('forgotPasswordError');
    const successDiv = document.getElementById('forgotPasswordSuccess');
    
    if (!email) {
        if (errorDiv) showError(errorDiv, 'Please enter your email address');
        return;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        if (errorDiv) showError(errorDiv, 'Please enter a valid email address');
        return;
    }
    
    if (errorDiv) errorDiv.style.display = 'none';
    if (successDiv) successDiv.style.display = 'none';
    
    try {
        // For now, just show a message (implement actual password reset later)
        if (successDiv) {
            showSuccess(successDiv, 'Password reset link sent! Please check your email. (Feature coming soon)');
        }
    } catch (error) {
        console.error('Forgot password error:', error);
        if (errorDiv) showError(errorDiv, 'Error sending reset link. Please try again.');
    }
}

async function handleLogin() {
    const usernameInput = document.getElementById('loginUsername');
    const passwordInput = document.getElementById('loginPassword');
    
    if (!usernameInput || !passwordInput) {
        console.error('Login form elements not found');
        return;
    }
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const errorDiv = document.getElementById('loginError');
    
    if (!username || !password) {
        if (errorDiv) showError(errorDiv, 'Please enter username and password');
        return;
    }
    
    if (errorDiv) errorDiv.style.display = 'none';
    
    try {
        const response = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.access_token;
            localStorage.setItem('authToken', authToken);
            currentUser = data.user;
            showPage('dashboardPage');
            updateNavUser();
        } else {
            showError(errorDiv, data.detail || 'Login failed');
        }
    } catch (error) {
        showError(errorDiv, 'Connection error. Please try again.');
    }
}

async function handleSignup() {
    const usernameInput = document.getElementById('signupUsername');
    const emailInput = document.getElementById('signupEmail');
    const passwordInput = document.getElementById('signupPassword');
    
    if (!usernameInput || !emailInput || !passwordInput) {
        console.error('Signup form elements not found');
        return;
    }
    
    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const errorDiv = document.getElementById('signupError');
    const successDiv = document.getElementById('signupSuccess');
    
    // Hide previous messages
    if (errorDiv) errorDiv.style.display = 'none';
    if (successDiv) successDiv.style.display = 'none';
    
    if (!username || !email || !password) {
        if (errorDiv) showError(errorDiv, 'Please fill in all required fields');
        return;
    }
    
    if (password.length < 6) {
        if (errorDiv) showError(errorDiv, 'Password must be at least 6 characters');
        return;
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        if (errorDiv) showError(errorDiv, 'Please enter a valid email address');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/auth/signup`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ 
                username: username, 
                email: email, 
                password: password
            })
        });
        
        // Check if response is ok before parsing JSON
        if (!response.ok) {
            let errorMsg = 'Signup failed. Please try again.';
            try {
                const errorData = await response.json();
                errorMsg = errorData.detail || errorData.message || errorMsg;
            } catch (e) {
                // If response is not JSON, use status text
                errorMsg = `Server error: ${response.status} ${response.statusText}`;
            }
            showError(errorDiv, errorMsg);
            return;
        }
        
        const data = await response.json();
        if (successDiv) {
            showSuccess(successDiv, 'Account created successfully! Redirecting to login...');
        }
        setTimeout(() => {
            switchAuthTab('login');
            const loginUsername = document.getElementById('loginUsername');
            if (loginUsername) loginUsername.value = username;
        }, 2000);
    } catch (error) {
        console.error('Signup error:', error);
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            showError(errorDiv, 'Cannot connect to server. Please ensure the server is running on http://127.0.0.1:8000');
        } else {
            showError(errorDiv, `Connection error: ${error.message}`);
        }
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showPage('loginPage');
    document.getElementById('navbar').style.display = 'none';
}

function showError(element, message) {
    element.textContent = message;
    element.style.display = 'block';
}

function showSuccess(element, message) {
    element.textContent = message;
    element.style.display = 'block';
    element.style.color = 'var(--accent-green)';
}

// ==================== NAVIGATION ====================

function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.dataset.page;
            if (page === 'dashboard') {
                showPage('dashboardPage');
            } else if (page === 'about') {
                showPage('aboutPage');
            }
        });
    });
    
    // Dashboard section tabs
    document.querySelectorAll('.dashboard-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const section = e.currentTarget.dataset.section;
            switchDashboardSection(section);
        });
    });
}

function switchDashboardSection(sectionName) {
    // Remove active class from all tabs and sections
    document.querySelectorAll('.dashboard-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.dashboard-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Add active class to selected tab and section
    const activeTab = document.querySelector(`[data-section="${sectionName}"]`);
    const activeSection = document.getElementById(`${sectionName}Section`);
    
    if (activeTab) activeTab.classList.add('active');
    if (activeSection) activeSection.classList.add('active');
    
    // Load section-specific data
    if (sectionName === 'history') {
        loadScanHistory();
    }
}

function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    // Show/hide navbar
    if (pageId === 'dashboardPage' || pageId === 'aboutPage') {
        document.getElementById('navbar').style.display = 'block';
    } else {
        document.getElementById('navbar').style.display = 'none';
    }
}

function updateNavUser() {
    if (currentUser) {
        document.getElementById('userName').textContent = currentUser.username || currentUser.email;
    }
}

// ==================== SCANNING ====================

function setupScanListeners() {
    const targetInput = document.getElementById('targetInput');
    const authorizationCheck = document.getElementById('authorizationCheck');
    const startScanBtn = document.getElementById('startScanBtn');
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    
    if (targetInput) targetInput.addEventListener('input', updateButtonState);
    if (authorizationCheck) authorizationCheck.addEventListener('change', updateButtonState);
    if (startScanBtn) startScanBtn.addEventListener('click', startScan);
    if (downloadReportBtn) downloadReportBtn.addEventListener('click', downloadReport);
}

function updateButtonState() {
    const targetInput = document.getElementById('targetInput');
    const authorizationCheck = document.getElementById('authorizationCheck');
    const startScanBtn = document.getElementById('startScanBtn');
    
    if (!targetInput || !authorizationCheck || !startScanBtn) return;
    
    const hasTarget = targetInput.value.trim().length > 0;
    const isAuthorized = authorizationCheck.checked;
    startScanBtn.disabled = !(hasTarget && isAuthorized);
}

async function startScan() {
    const targetInput = document.getElementById('targetInput');
    if (!targetInput || !authToken) return;
    
    const target = targetInput.value.trim();
    if (!target) return;

    // Reset UI
    resetUI();
    updateStatus('scanning', 'SCANNING');
    const progressPanel = document.getElementById('progressPanel');
    const resultsPanel = document.getElementById('resultsPanel');
    if (progressPanel) progressPanel.style.display = 'block';
    if (resultsPanel) resultsPanel.style.display = 'none';

    try {
        const response = await fetch(`${API_BASE}/api/scan/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                target: target,
                authorized: true
            })
        });

        if (!response.ok) {
            if (response.status === 401) {
                logout();
                throw new Error('Session expired. Please login again.');
            }
            throw new Error('Failed to start scan');
        }

        const data = await response.json();
        currentScanId = data.scan_id;

        // Connect WebSocket
        connectWebSocket(currentScanId);

        // Start polling for status
        pollScanStatus();

    } catch (error) {
        console.error('Scan error:', error);
        updateStatus('error', 'ERROR');
        alert(`Error: ${error.message}`);
    }
}

function connectWebSocket(scanId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${scanId}`;
    
    wsConnection = new WebSocket(wsUrl);

    wsConnection.onopen = () => {
        console.log('WebSocket connected');
        // Send a ping to keep connection alive
        wsConnection.send(JSON.stringify({ type: 'ping' }));
    };

    wsConnection.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            console.log('WebSocket message:', data);
            handleWebSocketMessage(data);
        } catch (error) {
            console.error('WebSocket message parse error:', error);
        }
    };

    wsConnection.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    wsConnection.onclose = () => {
        console.log('WebSocket closed');
        // Try to reconnect if scan is still running
        if (currentScanId) {
            setTimeout(() => {
                console.log('Attempting to reconnect WebSocket...');
                connectWebSocket(currentScanId);
            }, 2000);
        }
    };
}

function handleWebSocketMessage(data) {
    console.log('Handling WebSocket message:', data.type, data);
    switch (data.type) {
        case 'connected':
            console.log('WebSocket connected successfully');
            break;
        case 'progress':
            const progress = data.progress || 0;
            const stage = data.stage || 'processing';
            const message = data.message || '';
            console.log(`Progress: ${progress}% - ${stage} - ${message}`);
            updateProgress(progress, stage, message);
            break;
        case 'completed':
            console.log('Scan completed via WebSocket');
            if (pollInterval) clearInterval(pollInterval);
            handleScanComplete(data);
            break;
        case 'error':
            console.error('Scan error:', data.message);
            if (pollInterval) clearInterval(pollInterval);
            handleScanError(data.message || 'Unknown error');
            break;
        case 'pong':
            // Keep-alive response, ignore
            break;
        default:
            console.log('Unknown message type:', data.type, data);
    }
}

let pollInterval = null;
let pollCount = 0;

async function pollScanStatus() {
    if (!currentScanId || !authToken) return;
    
    pollCount = 0;
    const maxPolls = 60; // 2 minutes max
    
    if (pollInterval) clearInterval(pollInterval);
    
    pollInterval = setInterval(async () => {
        pollCount++;
        if (pollCount > maxPolls) {
            clearInterval(pollInterval);
            updateStatus('error', 'TIMEOUT');
            alert('Scan timed out. Please try again.');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/status`, {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
            
            if (response.status === 401) {
                clearInterval(pollInterval);
                logout();
                return;
            }
            
            if (response.ok) {
                const status = await response.json();
                
                // Update progress from status if WebSocket isn't working
                if (status.progress !== undefined && status.progress > 0) {
                    updateProgress(status.progress, status.status, `Status: ${status.status}`);
                }

                if (status.status === 'completed') {
                    clearInterval(pollInterval);
                    loadScanResults();
                } else if (status.status === 'failed') {
                    clearInterval(pollInterval);
                    handleScanError('Scan failed');
                }
            }
        } catch (error) {
            console.error('Status poll error:', error);
            // Don't stop polling on network errors
        }
    }, 2000);
}

function updateProgress(percent, stage, message) {
    const progressCircle = document.getElementById('progressCircle');
    const progressPercent = document.getElementById('progressPercent');
    const progressStage = document.getElementById('progressStage');
    
    if (progressCircle) {
        const circumference = 2 * Math.PI * 90;
        const offset = circumference - (percent / 100) * circumference;
        progressCircle.style.strokeDashoffset = offset;
    }
    
    if (progressPercent) progressPercent.textContent = `${percent}%`;
    if (progressStage) progressStage.textContent = message || stage || 'Processing...';

    // Update stage indicators
    updateStageIndicators(stage, percent);
    updateRadarAnimation(percent);
}

function updateStageIndicators(stage, progress) {
    const stages = {
        'initializing': 'stage-port',
        'port_scanning': 'stage-port',
        'http_analysis': 'stage-http',
        'tls_analysis': 'stage-tls',
        'owasp_detection': 'stage-owasp',
        'ai_analysis': 'stage-ai',
        'finalizing': 'stage-ai'
    };
    
    // Reset all stages
    document.querySelectorAll('.stage-item').forEach(item => {
        item.classList.remove('active', 'completed', 'failed');
        const status = item.querySelector('.stage-status');
        if (status) status.textContent = 'Pending';
    });
    
    // Activate current stage
    const currentStageId = stages[stage];
    if (currentStageId) {
        const currentStage = document.getElementById(currentStageId);
        if (currentStage) {
            currentStage.classList.add('active');
            const status = currentStage.querySelector('.stage-status');
            if (status) status.textContent = 'Running...';
        }
    }
    
    // Mark completed stages
    const stageOrder = ['port_scanning', 'http_analysis', 'tls_analysis', 'owasp_detection', 'ai_analysis'];
    const currentIndex = stageOrder.indexOf(stage);
    for (let i = 0; i < currentIndex; i++) {
        const completedStageId = stages[stageOrder[i]];
        if (completedStageId) {
            const completedStage = document.getElementById(completedStageId);
            if (completedStage) {
                completedStage.classList.remove('active');
                completedStage.classList.add('completed');
                const status = completedStage.querySelector('.stage-status');
                if (status) status.textContent = 'Complete';
            }
        }
    }
}

async function loadScanResults() {
    if (!currentScanId || !authToken) return;

    try {
        const statusResponse = await fetch(`${API_BASE}/api/scan/${currentScanId}/status`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (statusResponse.status === 401) {
            logout();
            return;
        }
        
        const status = await statusResponse.json();

        const vulnsResponse = await fetch(`${API_BASE}/api/scan/${currentScanId}/vulnerabilities`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (vulnsResponse.status === 401) {
            logout();
            return;
        }
        
        const vulnerabilities = await vulnsResponse.json();

        displayResults(status, vulnerabilities);

    } catch (error) {
        console.error('Load results error:', error);
        alert('Failed to load results');
    }
}

function displayResults(status, vulnerabilities) {
    const riskScore = document.getElementById('riskScore');
    const riskBarFill = document.getElementById('riskBarFill');
    const shieldScore = document.getElementById('shieldScore');
    const summaryText = document.getElementById('summaryText');
    
    const score = Math.round(status.risk_score);
    if (riskScore) riskScore.textContent = score;
    if (riskBarFill) riskBarFill.style.width = `${score}%`;
    if (shieldScore) shieldScore.textContent = score;
    
    // Update summary text
    if (summaryText) {
        if (vulnerabilities.length === 0) {
            summaryText.textContent = 'No vulnerabilities detected. The target appears secure.';
        } else {
            summaryText.textContent = `Found ${vulnerabilities.length} vulnerability/vulnerabilities. Review details below.`;
        }
    }
    
    // Mark all stages as completed
    document.querySelectorAll('.stage-item').forEach(item => {
        item.classList.remove('active');
        item.classList.add('completed');
        const status = item.querySelector('.stage-status');
        if (status) status.textContent = 'Complete';
    });

    updateSeverityChart(vulnerabilities);
    displayVulnerabilities(vulnerabilities);
    updateDashboardStats();

    const progressPanel = document.getElementById('progressPanel');
    const resultsPanel = document.getElementById('resultsPanel');
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    
    if (progressPanel) progressPanel.style.display = 'none';
    if (resultsPanel) resultsPanel.style.display = 'block';
    if (downloadReportBtn) downloadReportBtn.style.display = 'block';
    
    updateStatus('idle', 'COMPLETE');
}

async function updateDashboardStats() {
    if (!authToken) return;
    
    try {
        const response = await fetch(`${API_BASE}/api/scans`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const scans = await response.json();
            const completedScans = scans.filter(s => s.status === 'completed');
            const totalVulns = completedScans.reduce((sum, s) => sum + (s.total_vulnerabilities || 0), 0);
            const avgRisk = completedScans.length > 0 
                ? completedScans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / completedScans.length 
                : 0;
            
            const today = new Date().toISOString().split('T')[0];
            const scansToday = scans.filter(s => s.created_at && s.created_at.startsWith(today)).length;
            
            const totalScansEl = document.getElementById('totalScans');
            const totalVulnsEl = document.getElementById('totalVulns');
            const avgRiskEl = document.getElementById('avgRisk');
            const scansTodayEl = document.getElementById('scansToday');
            
            if (totalScansEl) totalScansEl.textContent = scans.length;
            if (totalVulnsEl) totalVulnsEl.textContent = totalVulns;
            if (avgRiskEl) avgRiskEl.textContent = Math.round(avgRisk);
            if (scansTodayEl) scansTodayEl.textContent = scansToday;
        }
    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

function updateSeverityChart(vulnerabilities) {
    const severityChart = document.getElementById('severityChart');
    if (!severityChart) return;
    
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };

    vulnerabilities.forEach(v => {
        const severity = v.severity.toLowerCase();
        if (counts.hasOwnProperty(severity)) {
            counts[severity]++;
        }
    });

    severityChart.innerHTML = Object.entries(counts)
        .filter(([_, count]) => count > 0)
        .map(([severity, count]) => `
            <div class="severity-item ${severity}">
                <div class="severity-label">${severity.toUpperCase()}</div>
                <div class="severity-count">${count}</div>
            </div>
        `).join('');
}

function displayVulnerabilities(vulnerabilities) {
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    if (!vulnerabilitiesList) return;
    
    if (vulnerabilities.length === 0) {
        vulnerabilitiesList.innerHTML = `
            <div class="vulnerability-card" style="text-align: center; border-left-color: var(--accent-green);">
                <div class="vulnerability-title">No Vulnerabilities Detected</div>
                <div class="vulnerability-description">The target appears to be secure based on this scan.</div>
            </div>
        `;
        return;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    vulnerabilities.sort((a, b) => {
        return (severityOrder[a.severity.toLowerCase()] || 99) - 
               (severityOrder[b.severity.toLowerCase()] || 99);
    });

    vulnerabilitiesList.innerHTML = vulnerabilities.map(v => `
        <div class="vulnerability-card ${v.severity.toLowerCase()}">
            <div class="vulnerability-header">
                <div class="vulnerability-title">${escapeHtml(v.title)}</div>
                <div class="vulnerability-severity ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</div>
            </div>
            ${v.description ? `<div class="vulnerability-description">${escapeHtml(v.description)}</div>` : ''}
            ${v.category ? `<div class="vulnerability-description"><strong>Category:</strong> ${escapeHtml(v.category)}</div>` : ''}
            ${v.recommendation ? `
                <div class="vulnerability-recommendation">
                    <strong>Recommendation:</strong>
                    ${escapeHtml(v.recommendation)}
                </div>
            ` : ''}
            ${v.ai_analysis ? `
                <div class="vulnerability-ai">
                    <strong>AI Analysis:</strong>
                    ${escapeHtml(v.ai_analysis)}
                </div>
            ` : ''}
        </div>
    `).join('');
}

async function downloadReport() {
    if (!currentScanId || !authToken) {
        alert('No scan selected. Please run a scan first.');
        return;
    }
    
    try {
        // Show loading state
        const btn = document.getElementById('downloadReportBtn');
        if (btn) {
            btn.disabled = true;
            btn.querySelector('.button-text').textContent = 'GENERATING...';
        }
        
        // Fetch report from backend
        const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/report`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                logout();
                throw new Error('Session expired. Please login again.');
            }
            throw new Error(`Failed to generate report: ${response.statusText}`);
        }
        
        // Get the report content
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        
        // Create download link
        const link = document.createElement('a');
        link.href = url;
        link.download = `vulnerability_report_${currentScanId}_${new Date().toISOString().split('T')[0]}.html`;
        document.body.appendChild(link);
        link.click();
        
        // Cleanup
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        // Reset button
        if (btn) {
            btn.disabled = false;
            btn.querySelector('.button-text').textContent = 'DOWNLOAD REPORT';
        }
        
    } catch (error) {
        console.error('Download error:', error);
        alert(`Error downloading report: ${error.message}`);
        
        // Reset button
        const btn = document.getElementById('downloadReportBtn');
        if (btn) {
            btn.disabled = false;
            btn.querySelector('.button-text').textContent = 'DOWNLOAD REPORT';
        }
    }
}

function updateStatus(state, text) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    
    if (statusDot) {
        statusDot.className = `status-dot ${state}`;
    }
    if (statusText) {
        statusText.textContent = text;
    }
}

function resetUI() {
    const progressCircle = document.getElementById('progressCircle');
    const progressPercent = document.getElementById('progressPercent');
    const progressStage = document.getElementById('progressStage');
    const riskScore = document.getElementById('riskScore');
    const riskBarFill = document.getElementById('riskBarFill');
    const severityChart = document.getElementById('severityChart');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    
    if (progressCircle) progressCircle.style.strokeDashoffset = 565.48;
    if (progressPercent) progressPercent.textContent = '0%';
    if (progressStage) progressStage.textContent = 'Initializing...';
    if (riskScore) riskScore.textContent = '0';
    if (riskBarFill) riskBarFill.style.width = '0%';
    if (severityChart) severityChart.innerHTML = '';
    if (vulnerabilitiesList) vulnerabilitiesList.innerHTML = '';
}

function handleScanError(message) {
    alert(`Error: ${message}`);
    const progressPanel = document.getElementById('progressPanel');
    if (progressPanel) progressPanel.style.display = 'none';
}

function handleScanComplete(data) {
    loadScanResults();
}

// ==================== RADAR ANIMATION ====================

function initializeRadar() {
    const radarCanvas = document.getElementById('radarCanvas');
    if (!radarCanvas) return;
    
    const ctx = radarCanvas.getContext('2d');
    const centerX = radarCanvas.width / 2;
    const centerY = radarCanvas.height / 2;
    const radius = Math.min(centerX, centerY) - 10;
    let angle = 0;

    function drawRadar() {
        ctx.clearRect(0, 0, radarCanvas.width, radarCanvas.height);

        // Draw grid circles
        for (let i = 1; i <= 3; i++) {
            ctx.strokeStyle = 'rgba(0, 255, 255, 0.2)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.arc(centerX, centerY, (radius / 3) * i, 0, Math.PI * 2);
            ctx.stroke();
        }

        // Draw grid lines
        for (let i = 0; i < 8; i++) {
            const a = (Math.PI * 2 / 8) * i;
            ctx.strokeStyle = 'rgba(0, 255, 255, 0.2)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.lineTo(
                centerX + Math.cos(a) * radius,
                centerY + Math.sin(a) * radius
            );
            ctx.stroke();
        }

        // Draw sweep line
        ctx.strokeStyle = '#00ffff';
        ctx.lineWidth = 2;
        ctx.shadowBlur = 10;
        ctx.shadowColor = '#00ffff';
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(
            centerX + Math.cos(angle) * radius,
            centerY + Math.sin(angle) * radius
        );
        ctx.stroke();

        // Draw sweep arc
        ctx.strokeStyle = 'rgba(0, 255, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, angle - 0.3, angle);
        ctx.stroke();

        angle += 0.05;
        if (angle > Math.PI * 2) angle = 0;
    }

    function animate() {
        drawRadar();
        radarAnimation = requestAnimationFrame(animate);
    }

    animate();
}

function updateRadarAnimation(progress) {
    // Radar animation continues automatically
}

// ==================== UTILITIES ====================

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Make viewHistoryScan available globally
window.viewHistoryScan = viewHistoryScan;
