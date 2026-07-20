/* ===== AI Code Security Scanner — Content Script ===== */

(function () {
  'use strict';

  const BUTTON_ID = 'ai-security-scanner-btn';
  const PANEL_ID = 'ai-security-scanner-panel';
  let injected = false;

  // ── Detect GitHub Repo Page ──
  function getRepoInfo() {
    const url = window.location.href;
    const match = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) return null;

    const owner = match[1];
    const repo = match[2];
    const skip = ['settings', 'notifications', 'explore', 'topics', 'trending', 'collections'];
    if (skip.includes(owner)) return null;

    return { owner, repo, branch: guessBranch() };
  }

  function guessBranch() {
    const match = window.location.href.match(/\/tree\/([^/]+)/);
    return match ? match[1] : 'main';
  }

  // ── Inject Scan Button ──
  function injectUI() {
    if (injected) return;
    const repoInfo = getRepoInfo();
    if (!repoInfo) return;

    injected = true;

    // Find a good insertion point in the GitHub UI
    const actionsBar =
      document.querySelector('.file-navigation') ||
      document.querySelector('.d-flex') ||
      document.querySelector('[data-testid="repository-content"]') ||
      document.querySelector('.Box-header');

    if (!actionsBar) return;

    // Create the scan button
    const btnContainer = document.createElement('div');
    btnContainer.id = BUTTON_ID;
    btnContainer.className = 'ai-scanner-btn-container';
    btnContainer.innerHTML = `
      <button class="ai-scanner-btn" id="ai-scanner-trigger" title="Scan this repository for security issues">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <span>Scan for Secrets</span>
      </button>
    `;

    actionsBar.style.position = 'relative';
    actionsBar.appendChild(btnContainer);

    // Create the results panel
    const panel = document.createElement('div');
    panel.id = PANEL_ID;
    panel.className = 'ai-scanner-panel';
    panel.innerHTML = `
      <div class="ai-scanner-panel-header">
        <div class="ai-scanner-panel-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>Security Scan Results</span>
        </div>
        <button class="ai-scanner-close" id="ai-scanner-close" title="Close">&times;</button>
      </div>
      <div class="ai-scanner-panel-progress" id="ai-scanner-progress">
        <div class="ai-scanner-spinner"></div>
        <span>Scanning repository files...</span>
      </div>
      <div class="ai-scanner-panel-body" id="ai-scanner-results" style="display:none"></div>
    `;

    document.body.appendChild(panel);

    // Event: trigger scan
    document.getElementById('ai-scanner-trigger').addEventListener('click', () => {
      startScan(repoInfo);
    });

    // Event: close panel
    document.getElementById('ai-scanner-close').addEventListener('click', () => {
      panel.style.display = 'none';
    });
  }

  // ── Run Scan ──
  async function startScan(repoInfo) {
    const panel = document.getElementById(PANEL_ID);
    const progress = document.getElementById('ai-scanner-progress');
    const results = document.getElementById('ai-scanner-results');
    const trigger = document.getElementById('ai-scanner-trigger');

    if (trigger) {
      trigger.classList.add('ai-scanner-btn-scanning');
      trigger.querySelector('span').textContent = 'Scanning...';
    }

    panel.style.display = 'block';
    progress.style.display = 'flex';
    results.style.display = 'none';

    try {
      // Send scan request to background
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { action: 'scan-repo', repo: repoInfo },
          (resp) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(resp);
            }
          }
        );
      });

      if (response.success) {
        renderResults(response.result, repoInfo);
      } else {
        results.innerHTML = `<div class="ai-scanner-error">Scan failed: ${escapeHtml(response.error)}</div>`;
        results.style.display = 'block';
      }
    } catch (err) {
      results.innerHTML = `<div class="ai-scanner-error">Error: ${escapeHtml(err.message)}</div>`;
      results.style.display = 'block';
    }

    progress.style.display = 'none';

    if (trigger) {
      trigger.classList.remove('ai-scanner-btn-scanning');
      trigger.querySelector('span').textContent = 'Rescan';
    }
  }

  // ── Render Results ──
  function renderResults(data, repoInfo) {
    const results = document.getElementById('ai-scanner-results');
    const { findings, counts, score } = data;

    // Score color
    let scoreColor = '#3fb950';
    let scoreLabel = 'Good';
    if (score < 50) {
      scoreColor = '#f85149';
      scoreLabel = 'At Risk';
    } else if (score < 80) {
      scoreColor = '#d29922';
      scoreLabel = 'Needs Work';
    }

    let html = `
      <div class="ai-scanner-score">
        <div class="ai-scanner-score-circle" style="border-color: ${scoreColor}">
          <span>${score}</span>
        </div>
        <div class="ai-scanner-score-text">
          <span class="ai-scanner-score-label" style="color:${scoreColor}">${scoreLabel}</span>
          <span class="ai-scanner-score-desc">Security Score</span>
        </div>
      </div>
      <div class="ai-scanner-severities">
        <span class="ai-sev ai-sev-critical">${counts.critical} Critical</span>
        <span class="ai-sev ai-sev-high">${counts.high} High</span>
        <span class="ai-sev ai-sev-medium">${counts.medium} Medium</span>
        <span class="ai-sev ai-sev-low">${counts.low} Low</span>
      </div>
    `;

    if (findings.length === 0) {
      html += `<div class="ai-scanner-clean">No issues found — this repo looks clean!</div>`;
    } else {
      // Sort by severity
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);

      html += `<div class="ai-scanner-findings">`;
      for (const f of sorted) {
        const lineUrl =
          f.line > 0
            ? `https://github.com/${repoInfo.owner}/${repoInfo.repo}/blob/${repoInfo.branch}/${f.file}#L${f.line}`
            : '';
        html += `
          <div class="ai-finding ai-finding-${f.severity}">
            <div class="ai-finding-head">
              <span class="ai-finding-sev">${f.severity.toUpperCase()}</span>
              <span class="ai-finding-file">${escapeHtml(f.file)}${f.line > 0 ? `:L${f.line}` : ''}</span>
            </div>
            <div class="ai-finding-desc">${escapeHtml(f.description)}</div>
            ${
              f.line > 0
                ? `<a class="ai-finding-link" href="${lineUrl}" target="_blank" rel="noopener">View on GitHub &rarr;</a>`
                : ''
            }
          </div>
        `;
      }
      html += `</div>`;
    }

    results.innerHTML = html;
    results.style.display = 'block';
  }

  // ── Helpers ──
  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // ── Init on Page Load ──
  function init() {
    injected = false;
    // Remove old button if present (page navigation)
    const old = document.getElementById(BUTTON_ID);
    if (old) old.remove();
    const oldPanel = document.getElementById(PANEL_ID);
    if (oldPanel) oldPanel.remove();

    injectUI();
  }

  // ── Watch for SPA navigation ──
  let lastUrl = '';
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      setTimeout(init, 500);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // ── Initial load ──
  lastUrl = window.location.href;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
