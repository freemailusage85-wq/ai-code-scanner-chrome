/* ===== AI Code Security Scanner — Background Service Worker ===== */

'use strict';

// ── Message Router ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scan-repo') {
    handleScanRepo(message.repo, message.tabId)
      .then((result) => sendResponse({ success: true, result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // keep message channel open for async response
  }

  if (message.action === 'get-repo-info') {
    const repo = parseGitHubRepo(message.url || '');
    sendResponse({ repo });
    return false;
  }

  if (message.action === 'scan-complete') {
    // Notify content script to update badge
    if (sender.tab?.id) {
      updateBadge(sender.tab.id, message.result);
    }
    sendResponse({ ok: true });
    return false;
  }
});

// ── Parse GitHub URL ──
function parseGitHubRepo(url) {
  const match = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) return null;
  const owner = match[1];
  const repo = match[2];
  if (['settings', 'notifications', 'explore', 'topics', 'trending', 'collections'].includes(owner)) return null;
  return { owner, repo };
}

// ── Scan Repo (background context) ──
async function handleScanRepo(repo, tabId) {
  if (!repo || !repo.owner || !repo.repo) {
    throw new Error('Invalid repository');
  }

  // Send progress to popup
  chrome.runtime.sendMessage({ action: 'scan-progress', status: 'Fetching file tree...' });

  // Fetch tree
  const treeData = await fetchTree(repo);
  if (!treeData) throw new Error('Could not fetch repository tree');

  const files = treeData.filter((f) => f.type === 'blob' && isScannable(f.path) && f.size < 512000);
  const findings = [];

  // Scan files in batches
  const BATCH = 8;
  for (let i = 0; i < files.length; i += BATCH) {
    const batch = files.slice(i, i + BATCH);
    const results = await Promise.all(
      batch.map(async (file) => {
        try {
          const resp = await fetch(
            `https://api.github.com/repos/${repo.owner}/${repo.repo}/contents/${file.path}`
          );
          if (!resp.ok) return [];
          const data = await resp.json();
          if (data.encoding !== 'base64' || !data.content) return [];
          const content = atob(data.content.replace(/\n/g, ''));
          return scanContent(content, file.path, file.size);
        } catch {
          return [];
        }
      })
    );
    findings.push(...results.flat());

    // Progress update
    const processed = Math.min(i + BATCH, files.length);
    chrome.runtime.sendMessage({
      action: 'scan-progress',
      status: `Scanned ${processed}/${files.length}`,
      progress: processed / files.length,
    });
  }

  return buildResults(findings, files.length);
}

// ── Fetch Tree ──
async function fetchTree(repo) {
  let resp = await fetch(
    `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/main?recursive=1`
  );
  if (resp.status === 404) {
    resp = await fetch(
      `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/master?recursive=1`
    );
  }
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.tree || [];
}

// ── File Type Check ──
function isScannable(path) {
  const ext = path.split('.').pop().toLowerCase();
  const SCANNABLE = new Set([
    'js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'go', 'java', 'php', 'cs',
    'rs', 'swift', 'kt', 'scala', 'lua', 'pl', 'sh', 'bash', 'zsh',
    'yaml', 'yml', 'json', 'toml', 'ini', 'cfg', 'conf', 'env',
    'dockerfile', 'makefile', 'tf', 'hcl', 'sql', 'graphql', 'gql',
    'vue', 'svelte', 'dart', 'r', 'm', 'mm', 'cpp', 'c', 'h', 'hpp',
  ]);
  return SCANNABLE.has(ext);
}

// ── Badge Update ──
function updateBadge(tabId, result) {
  const { counts } = result;
  const total = counts.critical + counts.high;

  if (total > 0) {
    chrome.action.setBadgeText({ text: String(total), tabId });
    chrome.action.setBadgeBackgroundColor(
      { color: counts.critical > 0 ? '#f85149' : '#d29922' },
      tabId
    );
  } else {
    chrome.action.setBadgeText({ text: '✓', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#3fb950' }, tabId);
  }
}

// ── Simplified inline scanner for background (mirrors popup.js) ──
function scanContent(content, filePath, fileSize) {
  const findings = [];

  const patterns = [
    // Secrets
    { p: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi, d: 'Hardcoded API key', s: 'critical', c: 'Secret' },
    { p: /(?:aws[_-]?(?:access[_-]?key|secret[_-]?key))\s*[:=]\s*['"][A-Za-z0-9/+=]{16,}['"]/gi, d: 'AWS credential', s: 'critical', c: 'Secret' },
    { p: /(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{20,}['"]/gi, d: 'Hardcoded token', s: 'critical', c: 'Secret' },
    { p: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/gi, d: 'Hardcoded password', s: 'critical', c: 'Secret' },
    { p: /(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9/+=\-_]{20,}['"]/gi, d: 'Private/secret key', s: 'critical', c: 'Secret' },
    { p: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi, d: 'Embedded private key', s: 'critical', c: 'Secret' },
    { p: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, d: 'GitHub personal access token', s: 'critical', c: 'Secret' },
    { p: /sk[_-](?:live|test)_[A-Za-z0-9]{20,}/g, d: 'Stripe API key', s: 'critical', c: 'Secret' },
    { p: /AKIA[0-9A-Z]{16}/g, d: 'AWS Access Key ID', s: 'critical', c: 'Secret' },
    { p: /xox[bpoas]-[A-Za-z0-9\-]+/g, d: 'Slack token', s: 'critical', c: 'Secret' },
    // Unsafe code
    { p: /\beval\s*\(/gi, d: 'Use of eval()', s: 'high', c: 'Unsafe Code' },
    { p: /\bnew\s+Function\s*\(/gi, d: 'Dynamic code via new Function()', s: 'high', c: 'Unsafe Code' },
    { p: /\bpickle\.loads?\s*\(/gi, d: 'Pickle deserialization', s: 'critical', c: 'Unsafe Code' },
    { p: /\bpickle\.load\s*\(/gi, d: 'Pickle load', s: 'critical', c: 'Unsafe Code' },
    { p: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\+\s*/gi, d: 'SQL injection risk', s: 'high', c: 'Unsafe Code' },
    { p: /\bchild_process\.exec\s*\(/gi, d: 'Shell command execution', s: 'high', c: 'Unsafe Code' },
    { p: /\bos\.system\s*\(/gi, d: 'Shell command via os.system()', s: 'high', c: 'Unsafe Code' },
    { p: /\bexec\s*\(/gi, d: 'Use of exec()', s: 'high', c: 'Unsafe Code' },
    { p: /yaml\.load\s*\((?!.*Loader\s*=)/gi, d: 'yaml.load without safe Loader', s: 'high', c: 'Unsafe Code' },
    { p: /\binnerHTML\s*=/gi, d: 'Direct innerHTML assignment', s: 'medium', c: 'Unsafe Code' },
    { p: /Math\.random\s*\(\)/gi, d: 'Math.random() not cryptographically secure', s: 'medium', c: 'Code Quality' },
    { p: /\bconsole\.(log|debug|info|warn|error)\s*\(/gi, d: 'Console logging', s: 'low', c: 'Code Quality' },
    { p: /\bTODO\b/gi, d: 'Unresolved TODO', s: 'low', c: 'Code Quality' },
    { p: /\bFIXME\b/gi, d: 'Unresolved FIXME', s: 'low', c: 'Code Quality' },
    { p: /\bHACK\b/gi, d: 'HACK comment', s: 'low', c: 'Code Quality' },
  ];

  const lines = content.split('\n');
  const seen = new Set();

  for (const { p, d, s, c } of patterns) {
    p.lastIndex = 0;
    let m;
    while ((m = p.exec(content)) !== null) {
      const ln = content.substring(0, m.index).split('\n').length;
      const line = lines[ln - 1]?.trim() || '';
      if (/^\s*(?:#|\/\/|\/\*|\*)/.test(line)) continue;
      const key = `${s}:${d}:${ln}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ file: filePath, line: ln, severity: s, category: c, description: d, snippet: line.substring(0, 120), size: fileSize });
    }
  }

  return findings;
}

function buildResults(findings, filesScanned) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const deduction = counts.critical * 30 + counts.high * 15 + counts.medium * 5 + counts.low;
  const score = Math.max(0, Math.min(100, 100 - deduction));
  return { findings, counts, score, totalIssues: findings.length, filesScanned };
}

// ── Install Handler ──
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({ scanCount: 0 });
  }
});
