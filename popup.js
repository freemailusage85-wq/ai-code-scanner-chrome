/* ===== AI Code Security Scanner — Popup Logic ===== */

(function () {
  'use strict';

  // ── DOM References ──
  const $ = (sel) => document.querySelector(sel);
  const repoInfo = $('#repo-info');
  const noRepo = $('#no-repo');
  const repoNameEl = $('#repo-name');
  const repoLangEl = $('#repo-lang');
  const repoStarsEl = $('#repo-stars');
  const repoSizeEl = $('#repo-size');
  const scanBtn = $('#scan-btn');
  const scanBtnText = $('#scan-btn-text');
  const progressSection = $('#progress-section');
  const progressBar = $('#progress-bar');
  const progressLabel = $('#progress-label');
  const progressCount = $('#progress-count');
  const resultsSummary = $('#results-summary');
  const scoreRingFill = $('#score-ring-fill');
  const scoreValue = $('#score-value');
  const scoreVerdict = $('#score-verdict');
  const countCritical = $('#count-critical');
  const countHigh = $('#count-high');
  const countMedium = $('#count-medium');
  const countLow = $('#count-low');
  const statFiles = $('#stat-files');
  const statIssues = $('#stat-issues');
  const statElapsed = $('#stat-elapsed');
  const findingsSection = $('#findings-section');
  const findingsList = $('#findings-list');
  const clearBtn = $('#clear-btn');

  let currentRepo = null;
  let isScanning = false;
  let currentFindings = [];
  let currentFilter = 'all';

  // ── Severity Weights for Score ──
  const SEVERITY_WEIGHT = { critical: 30, high: 15, medium: 5, low: 1 };

  // ── Init ──
  async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const repo = parseGitHubRepo(tab?.url || '');

    if (!repo) {
      noRepo.classList.remove('hidden');
      scanBtn.classList.add('hidden');
      return;
    }

    currentRepo = repo;
    noRepo.classList.add('hidden');
    repoInfo.classList.remove('hidden');
    scanBtn.classList.remove('hidden');

    repoNameEl.textContent = `${repo.owner}/${repo.repo}`;
    scanBtn.disabled = false;

    // Fetch repo metadata
    try {
      const resp = await fetch(`https://api.github.com/repos/${repo.owner}/${repo.repo}`);
      if (resp.ok) {
        const data = await resp.json();
        repoLangEl.textContent = data.language || 'Unknown';
        repoStarsEl.textContent = `${formatNumber(data.stargazers_count)} stars`;
        repoSizeEl.textContent = `${Math.round(data.size / 1024)} MB`;
      }
    } catch {
      // silently ignore — metadata is nice-to-have
    }

    // Check for cached results
    const cached = await chrome.storage.local.get(`results:${repo.owner}/${repo.repo}`);
    if (cached[`results:${repo.owner}/${repo.repo}`]) {
      displayResults(cached[`results:${repo.owner}/${repo.repo}`]);
    }
  }

  // ── Parse GitHub URL ──
  function parseGitHubRepo(url) {
    const match = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) return null;
    const owner = match[1];
    const repo = match[2];
    if (['settings', 'notifications', 'explore', 'topics', 'trending', 'collections'].includes(owner)) return null;
    return { owner, repo };
  }

  // ── Scan ──
  scanBtn.addEventListener('click', async () => {
    if (isScanning || !currentRepo) return;
    isScanning = true;

    // UI → scanning state
    scanBtn.classList.add('scanning');
    scanBtn.disabled = true;
    scanBtnText.textContent = 'Scanning...';
    progressSection.classList.remove('hidden');
    resultsSummary.classList.add('hidden');
    findingsSection.classList.add('hidden');
    progressBar.style.width = '0%';

    const startTime = Date.now();

    try {
      const findings = await scanRepo(currentRepo, (processed, total, file) => {
        const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
        progressBar.style.width = `${pct}%`;
        progressLabel.textContent = file ? `Scanning ${truncate(file, 36)}` : 'Scanning files...';
        progressCount.textContent = `${processed} / ${total}`;
      });

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const results = buildResults(findings, elapsed);
      currentFindings = findings;

      // Cache results
      await chrome.storage.local.set({ [`results:${currentRepo.owner}/${currentRepo.repo}`]: results });

      displayResults(results);
    } catch (err) {
      progressLabel.textContent = `Error: ${err.message}`;
      progressCount.textContent = '';
    }

    isScanning = false;
    scanBtn.classList.remove('scanning');
    scanBtn.disabled = false;
    scanBtnText.textContent = 'Rescan Repository';
  });

  // ── Core Scan ──
  async function scanRepo(repo, onProgress) {
    const files = await fetchRepoFiles(repo, onProgress);
    const findings = [];

    const scanFiles = files.filter((f) => isScannable(f.path) && f.size < 512000);
    const BATCH = 6;

    for (let i = 0; i < scanFiles.length; i += BATCH) {
      const batch = scanFiles.slice(i, i + BATCH);
      const results = await Promise.all(
        batch.map(async (file) => {
          try {
            const resp = await fetch(
              `https://api.github.com/repos/${repo.owner}/${repo.repo}/contents/${file.path}`
            );
            if (!resp.ok) return [];

            const data = await resp.json();
            if (data.encoding !== 'base64' || !data.content) return [];

            const content = decodeBase64(data.content);
            const fileFindings = scanContent(content, file.path, file.size);
            onProgress(Math.min(i + BATCH, scanFiles.length), scanFiles.length, file.path);
            return fileFindings;
          } catch {
            return [];
          }
        })
      );
      findings.push(...results.flat());
    }

    onProgress(scanFiles.length, scanFiles.length, 'Done');
    return findings;
  }

  // ── Fetch Repository File Tree ──
  async function fetchRepoFiles(repo, onProgress) {
    onProgress(0, 0, 'Fetching file tree...');
    const resp = await fetch(
      `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/main?recursive=1`
    );

    if (resp.status === 404) {
      // Try master branch
      const resp2 = await fetch(
        `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/master?recursive=1`
      );
      if (!resp2.ok) throw new Error('Could not fetch repo files');
      const data2 = await resp2.json();
      return (data2.tree || []).filter((f) => f.type === 'blob');
    }

    if (!resp.ok) throw new Error(`GitHub API error (${resp.status})`);
    const data = await resp.json();
    return (data.tree || []).filter((f) => f.type === 'blob');
  }

  // ── Decode Base64 Content ──
  function decodeBase64(encoded) {
    try {
      const binary = atob(encoded.replace(/\n/g, ''));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch {
      return '';
    }
  }

  // ── File Type Filtering ──
  function isScannable(path) {
    const ext = path.split('.').pop().toLowerCase();
    const SCANNABLE = new Set([
      'js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'go', 'java', 'php', 'cs',
      'rs', 'swift', 'kt', 'scala', 'lua', 'pl', 'sh', 'bash', 'zsh',
      'yaml', 'yml', 'json', 'toml', 'ini', 'cfg', 'conf', 'env',
      'dockerfile', 'makefile', 'tf', 'hcl', 'sql', 'graphql', 'gql',
      'vue', 'svelte', 'dart', 'r', 'm', 'mm', 'cpp', 'c', 'h', 'hpp',
    ]);
    if (SCANNABLE.has(ext)) return true;
    // Check for special filenames
    const base = path.split('/').pop().toLowerCase();
    return ['dockerfile', 'makefile', '.env', '.env.local', '.env.production', 'rakefile', 'gemfile'].includes(base);
  }

  // ── Content Scanner ──
  function scanContent(content, filePath, fileSize) {
    const findings = [];
    const lines = content.split('\n');
    const ext = filePath.split('.').pop().toLowerCase();
    const base = filePath.split('/').pop().toLowerCase();

    // ─── SECRET PATTERNS ───
    const secretPatterns = [
      {
        pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi,
        desc: 'Hardcoded API key',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[:=]\s*['"][A-Za-z0-9/+=]{16,}['"]/gi,
        desc: 'AWS credential',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{20,}['"]/gi,
        desc: 'Hardcoded token',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/gi,
        desc: 'Hardcoded password',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9/+=\-_]{20,}['"]/gi,
        desc: 'Private/secret key',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
        desc: 'Embedded private key',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
        desc: 'GitHub personal access token',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /sk[_-](?:live|test)_[A-Za-z0-9]{20,}/g,
        desc: 'Stripe API key',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /(?:SG)\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{40,}/g,
        desc: 'SendGrid API key',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /xox[bpoas]-[A-Za-z0-9\-]+/g,
        desc: 'Slack token',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /AKIA[0-9A-Z]{16}/g,
        desc: 'AWS Access Key ID',
        sev: 'critical',
        cat: 'Secret',
      },
      {
        pattern: /['"]?[A-Za-z0-9]{32,}['"]?\s*(?:#.*)?$/gm,
        desc: 'Possible long secret value (32+ chars)',
        sev: 'medium',
        cat: 'Secret',
      },
    ];

    // ─── UNSAFE CODE PATTERNS ───
    const unsafePatterns = [
      {
        pattern: /\beval\s*\(/gi,
        desc: 'Use of eval() — code injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bnew\s+Function\s*\(/gi,
        desc: 'Dynamic code construction via new Function()',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bpickle\.loads?\s*\(/gi,
        desc: 'Pickle deserialization — arbitrary code execution risk',
        sev: 'critical',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bpickle\.load\s*\(/gi,
        desc: 'Pickle load — unsafe deserialization',
        sev: 'critical',
        cat: 'Unsafe Code',
      },
      {
        pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*['"]\s*\+\s*/gi,
        desc: 'SQL injection risk — string concatenation in query',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
        desc: 'SQL injection risk — template literal in query',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /cursor\.execute\s*\(\s*['"].*%s/gi,
        desc: 'SQL injection risk — format string in query',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bchild_process\.exec\s*\(/gi,
        desc: 'Shell command execution — injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bos\.system\s*\(/gi,
        desc: 'Shell command via os.system() — injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bsubprocess\.call\s*\(\s*['"]\s*shell\s*=\s*True/gi,
        desc: 'subprocess with shell=True — injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\binnerHTML\s*=/gi,
        desc: 'Direct innerHTML assignment — XSS risk',
        sev: 'medium',
        cat: 'Unsafe Code',
      },
      {
        pattern: /document\.write\s*\(/gi,
        desc: 'document.write() — XSS risk',
        sev: 'medium',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bexec\s*\(/gi,
        desc: 'Use of exec() — code injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /yaml\.load\s*\((?!.*Loader\s*=)/gi,
        desc: 'yaml.load without safe Loader — deserialization risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /__import__\s*\(/gi,
        desc: 'Dynamic import via __import__() — code injection risk',
        sev: 'high',
        cat: 'Unsafe Code',
      },
      {
        pattern: /\bXMLHttpRequest\b/gi,
        desc: 'Use of XMLHttpRequest (prefer fetch API)',
        sev: 'low',
        cat: 'Code Quality',
      },
      {
        pattern: /Math\.random\s*\(\)/gi,
        desc: 'Math.random() is not cryptographically secure',
        sev: 'medium',
        cat: 'Code Quality',
      },
      {
        pattern: /\bconsole\.(log|debug|info|warn|error)\s*\(/gi,
        desc: 'Console logging in production code',
        sev: 'low',
        cat: 'Code Quality',
      },
      {
        pattern: /\bTODO\b/gi,
        desc: 'Unresolved TODO comment',
        sev: 'low',
        cat: 'Code Quality',
      },
      {
        pattern: /\bFIXME\b/gi,
        desc: 'Unresolved FIXME comment',
        sev: 'low',
        cat: 'Code Quality',
      },
      {
        pattern: /\bHACK\b/gi,
        desc: 'HACK comment — technical debt',
        sev: 'low',
        cat: 'Code Quality',
      },
    ];

    // ─── LANGUAGE-SPECIFIC PATTERNS ───
    const langPatterns = {
      python: [
        {
          pattern: /\bexec\s*\(\s*['"]/gi,
          desc: 'Python exec() with string — code injection',
          sev: 'critical',
          cat: 'Unsafe Code',
        },
        {
          pattern: /\bcompile\s*\(\s*['"]/gi,
          desc: 'Python compile() with string — code injection',
          sev: 'high',
          cat: 'Unsafe Code',
        },
        {
          pattern: /input\s*\(\s*['"]\s*\)/gi,
          desc: 'Unvalidated user input',
          sev: 'medium',
          cat: 'Code Quality',
        },
      ],
      javascript: [
        {
          pattern: /\bdocument\.cookie\s*=/gi,
          desc: 'Direct cookie manipulation — security risk',
          sev: 'medium',
          cat: 'Unsafe Code',
        },
      ],
    };

    const lang = detectLanguage(ext, base);
    const allPatterns = [...secretPatterns, ...unsafePatterns, ...(langPatterns[lang] || [])];

    // ── Run all patterns ──
    const seen = new Set();
    for (const { pattern, desc, sev, cat } of allPatterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNum - 1]?.trim() || '';

        // Skip false positives
        if (isFalsePositive(line, desc)) continue;

        const key = `${sev}:${desc}:${lineNum}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          file: filePath,
          line: lineNum,
          severity: sev,
          category: cat,
          description: desc,
          snippet: truncate(line, 120),
          size: fileSize,
        });
      }
    }

    // ─── FILE SIZE CHECK ───
    if (fileSize > 50000) {
      findings.push({
        file: filePath,
        line: 0,
        severity: 'low',
        category: 'Code Quality',
        description: `Oversized file (${(fileSize / 1024).toFixed(0)} KB)`,
        snippet: `File exceeds 50 KB — consider splitting`,
        size: fileSize,
      });
    }

    // ─── AI SLOP DETECTION ───
    const aiSlopScore = detectAiSlop(content, lines);
    if (aiSlopScore >= 3) {
      findings.push({
        file: filePath,
        line: 0,
        severity: 'low',
        category: 'Code Quality',
        description: 'Possible AI-generated code (low quality markers)',
        snippet: `AI slop score: ${aiSlopScore}/5 markers detected`,
        size: fileSize,
      });
    }

    return findings;
  }

  // ── AI Slop Detector ──
  function detectAiSlop(content, lines) {
    let score = 0;

    // Overly verbose variable names
    if (/const\s+\w+That\w+\s*=/g.test(content)) score++;

    // Generic/placeholder comments
    if (/\/\/\s*(This function|This method|This class|Here we|This code)/i.test(content)) score++;

    // Excessive comments that don't help
    if ((content.match(/\/\/.+/g) || []).length > lines.length * 0.4) score++;

    // TODO-heavy
    const todos = (content.match(/\bTODO\b/gi) || []).length;
    if (todos > 3) score++;

    // Unnecessarily nested logic
    const maxIndent = lines.reduce((max, line) => {
      const indent = line.match(/^\s*/)[0].length;
      return Math.max(max, indent);
    }, 0);
    if (maxIndent > 24) score++;

    return score;
  }

  // ── Language Detection ──
  function detectLanguage(ext, base) {
    const map = {
      py: 'python', pyw: 'python',
      js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
      ts: 'typescript', tsx: 'typescript',
    };
    if (base === 'dockerfile') return 'shell';
    if (base === 'makefile') return 'shell';
    return map[ext] || 'other';
  }

  // ── False Positive Filter ──
  function isFalsePositive(line, desc) {
    // Skip comments and imports in secrets check
    if (desc.includes('secret') || desc.includes('key') || desc.includes('token')) {
      if (/^\s*(?:#|\/\/|\/\*|\*|import|from|require)/.test(line)) return true;
      if (/['"](?:test|example|mock|dummy|placeholder|xxx|your_key_here)['"]/i.test(line)) return true;
      if (/test[_-]?key|example|dummy|placeholder|sample|mock/i.test(line)) return true;
    }
    // Skip typical eval checks in config/webpack files
    if (desc.includes('eval()') && /webpack|config|rollup|vite/i.test(line)) return true;
    // Skip SQL in documentation/comments
    if (/^\s*--|^\s*\/\*|^\s*#|^\s*\/\/|^\s*\*/.test(line)) return true;
    // Skip console in type definitions
    if (desc.includes('Console logging') && /\.d\.ts$/.test(line)) return true;
    return false;
  }

  // ── Build Results ──
  function buildResults(findings, elapsed) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => counts[f.severity]++);

    const totalIssues = findings.length;
    const deduction =
      counts.critical * SEVERITY_WEIGHT.critical +
      counts.high * SEVERITY_WEIGHT.high +
      counts.medium * SEVERITY_WEIGHT.medium +
      counts.low * SEVERITY_WEIGHT.low;
    const score = Math.max(0, Math.min(100, 100 - deduction));

    return { findings, counts, score, totalIssues, elapsed };
  }

  // ── Display Results ──
  function displayResults(results) {
    progressSection.classList.add('hidden');
    resultsSummary.classList.remove('hidden');
    findingsSection.classList.remove('hidden');

    // Score
    const score = results.score;
    scoreValue.textContent = score;

    // Ring animation
    const circumference = 2 * Math.PI * 50; // r=50
    const offset = circumference - (score / 100) * circumference;
    scoreRingFill.style.strokeDashoffset = offset;

    // Score color
    if (score >= 80) {
      scoreRingFill.style.stroke = '#3fb950';
      scoreVerdict.textContent = 'Good';
      scoreVerdict.style.color = '#3fb950';
    } else if (score >= 50) {
      scoreRingFill.style.stroke = '#d29922';
      scoreVerdict.textContent = 'Needs Work';
      scoreVerdict.style.color = '#d29922';
    } else {
      scoreRingFill.style.stroke = '#f85149';
      scoreVerdict.textContent = 'At Risk';
      scoreVerdict.style.color = '#f85149';
    }

    // Severity counts
    countCritical.textContent = results.counts.critical;
    countHigh.textContent = results.counts.high;
    countMedium.textContent = results.counts.medium;
    countLow.textContent = results.counts.low;

    // Stats
    const filesScanned = new Set(results.findings.map((f) => f.file)).size || 1;
    statFiles.textContent = filesScanned;
    statIssues.textContent = results.totalIssues;
    statElapsed.textContent = `${results.elapsed}s`;

    // Render findings
    currentFindings = results.findings;
    currentFilter = 'all';
    renderFindings(results.findings);
    updateFilterButtons();
  }

  // ── Render Findings ──
  function renderFindings(findings) {
    const filtered =
      currentFilter === 'all'
        ? findings
        : findings.filter((f) => f.severity === currentFilter);

    if (filtered.length === 0) {
      findingsList.innerHTML = `<div class="finding-empty">${
        findings.length === 0
          ? 'No issues found — this repo looks clean!'
          : 'No findings match this filter.'
      }</div>`;
      return;
    }

    // Sort: critical first
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    filtered.sort((a, b) => order[a.severity] - order[b.severity]);

    findingsList.innerHTML = filtered
      .map((f) => {
        const repoUrl = currentRepo
          ? `https://github.com/${currentRepo.owner}/${currentRepo.repo}/blob/main/${f.file}`
          : '#';
        const lineUrl = f.line > 0 ? `#L${f.line}` : '';
        return `
        <div class="finding-item" data-severity="${f.severity}">
          <div class="finding-top">
            <span class="finding-severity ${f.severity}">${f.severity}</span>
            <span class="finding-file" title="${escapeHtml(f.file)}">${escapeHtml(f.file)}</span>
          </div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
          ${
            f.line > 0
              ? `<div class="finding-line">Line ${f.line} — <a href="${repoUrl}${lineUrl}" target="_blank" rel="noopener">View on GitHub</a></div>`
              : ''
          }
        </div>`;
      })
      .join('');
  }

  // ── Filter Buttons ──
  document.querySelectorAll('.filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      currentFilter = btn.dataset.severity;
      updateFilterButtons();
      renderFindings(currentFindings);
    });
  });

  function updateFilterButtons() {
    document.querySelectorAll('.filter-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.severity === currentFilter);
    });
  }

  // ── Clear ──
  clearBtn.addEventListener('click', async () => {
    if (currentRepo) {
      await chrome.storage.local.remove(`results:${currentRepo.owner}/${currentRepo.repo}`);
    }
    currentFindings = [];
    resultsSummary.classList.add('hidden');
    findingsSection.classList.add('hidden');
    scanBtnText.textContent = 'Scan Repository';
    progressSection.classList.add('hidden');
  });

  // ── Helpers ──
  function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
  }

  function formatNumber(n) {
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ── Start ──
  init();
})();
