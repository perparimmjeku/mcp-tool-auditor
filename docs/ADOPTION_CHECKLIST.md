# Adoption Checklist (things that need your accounts/buttons)

The code/docs/workflows are in place. These remaining steps require your GitHub/PyPI
access — I can't do them for you.

## 1. Publish to PyPI (biggest adoption lever — makes `pip install mcp-tool-auditor` work)

Recommended: **Trusted Publishing** (no API tokens to leak).

1. Create the project on PyPI: https://pypi.org/manage/account/publishing/
   - Project name: `mcp-tool-auditor`
   - Owner: `perparimmjeku` · Repo: `mcp-tool-auditor`
   - Workflow: `publish.yml` · Environment: `pypi`
2. In the repo: **Settings → Environments → New environment → `pypi`**.
3. Cut a release (step 2 below). The `.github/workflows/publish.yml` workflow builds
   and publishes automatically on release.

Once live, the PyPI badge in the README turns green and the GitHub Action's default
`install-spec: mcp-tool-auditor` works without the git-URL override.

## 2. Cut a GitHub Release

1. Tag: `git tag v1.1.0 && git push origin v1.1.0` (or use the Releases UI).
2. **Releases → Draft a new release → tag `v1.1.0`**, title "v1.1.0", paste the
   `CHANGELOG.md` 1.1.0 section as the notes. Publish.

## 3. Repo discoverability (SEO — drives organic stars)

**Settings → General**, and the gear next to "About":
- **Description:** "Behavioral + static security scanner for MCP servers — catches tool poisoning, FSP, rug-pull, and ATPA. OWASP MCP Top 10. SARIF + CI ready."
- **Topics:** `mcp`, `security`, `ai-security`, `llm`, `tool-poisoning`, `owasp`,
  `sarif`, `devsecops`, `model-context-protocol`, `agent-security`, `claude`, `cursor`
- Check **Releases** and **Packages** so they show in the sidebar.

## 4. Optional but high-value

- **Screenshot/GIF** in the README hero (record `mcp-tool-auditor scan import ...`
  with [asciinema](https://asciinema.org) or a terminal screenshot). Visual proof
  is one of the strongest star drivers.
- **PR-FAQ / launch post** on Hacker News / r/netsec / LinkedIn pointing at the
  unique angle: *runtime ATPA detection*, which definition-only scanners miss.
- Pin the repo on your profile.
