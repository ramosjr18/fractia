/**
 * GitHub REST API v3 client
 * Sin dependencias extra — usa fetch nativo (Node ≥ 18)
 */

export class GitHubClient {
  constructor(token) {
    this.token   = token;
    this.base    = 'https://api.github.com';
    this.headers = {
      'Authorization':        `Bearer ${token}`,
      'Accept':               'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type':         'application/json',
      'User-Agent':           'Fractia-Security-Platform/3.0',
    };
  }

  async _req(method, path, body) {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: this.headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`GitHub API ${method} ${path} → HTTP ${res.status}: ${text.slice(0, 300)}`);
    }
    return text ? JSON.parse(text) : null;
  }

  // ── Repo info ────────────────────────────────────────────────────────────
  async getRepo(owner, repo) {
    return this._req('GET', `/repos/${owner}/${repo}`);
  }

  // ── Pull Requests ─────────────────────────────────────────────────────────
  async getPR(owner, repo, prNumber) {
    return this._req('GET', `/repos/${owner}/${repo}/pulls/${prNumber}`);
  }

  async getPRFiles(owner, repo, prNumber) {
    // Returns up to 3000 files — paginate if needed for large PRs
    const results = [];
    let page = 1;
    while (true) {
      const batch = await this._req('GET', `/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`);
      results.push(...batch);
      if (batch.length < 100) break;
      page++;
    }
    return results;
  }

  async createPR(owner, repo, { title, body, head, base }) {
    return this._req('POST', `/repos/${owner}/${repo}/pulls`, { title, body, head, base });
  }

  // ── PR Reviews ────────────────────────────────────────────────────────────
  /**
   * event: 'APPROVE' | 'REQUEST_CHANGES' | 'COMMENT'
   * comments: [{ path, position, body }]  (inline, optional)
   */
  async createPRReview(owner, repo, prNumber, { body, event, comments = [] }) {
    return this._req('POST', `/repos/${owner}/${repo}/pulls/${prNumber}/reviews`, {
      body,
      event,
      comments,
    });
  }

  // ── File content ──────────────────────────────────────────────────────────
  /** Download a file at a specific git ref (commit sha, branch, tag) */
  async getFileContent(owner, repo, filePath, ref) {
    const data = await this._req('GET', `/repos/${owner}/${repo}/contents/${filePath}?ref=${ref}`);
    if (data.encoding === 'base64') {
      return Buffer.from(data.content, 'base64').toString('utf8');
    }
    if (data.download_url) {
      const raw = await fetch(data.download_url, { headers: { 'User-Agent': 'Fractia/3.0' } });
      return raw.text();
    }
    throw new Error(`Unsupported encoding: ${data.encoding}`);
  }

  // ── Validate token ────────────────────────────────────────────────────────
  async getAuthenticatedUser() {
    return this._req('GET', '/user');
  }
}

// ── Parse "owner/repo" helper ─────────────────────────────────────────────
export function parseRepo(repoStr) {
  const [owner, repo] = (repoStr || '').split('/');
  if (!owner || !repo) throw new Error(`Formato de repo inválido: "${repoStr}". Usa "owner/repo"`);
  return { owner, repo };
}
