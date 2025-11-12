# GitHub Actions Workflows

## WASM Publishing

### publish-wasm.yml

Automatically publishes the `@cartridge/controller-wasm` package to NPM when changes are merged to `main`.

**Trigger:** Pushes to `main` branch that modify:
- `account-wasm/**`
- `account_sdk/**`
- `contracts/**`
- `.github/workflows/publish-wasm.yml`

**Versioning:** The package is published with a version format of `{base-version}-{short-sha}`, for example:
- Base version in package.json: `0.7.14-alpha.3`
- Short SHA: `abc1234`
- Published version: `0.7.14-abc1234`

**NPM Tag:** Published under the `dev` tag, so it won't affect the `latest` tag.

**Installation:**
```bash
# Install the latest dev version
npm install @cartridge/controller-wasm@dev

# Install a specific commit version
npm install @cartridge/controller-wasm@0.7.14-abc1234
```

**Requirements:**
- `NPM_TOKEN` secret must be configured in GitHub repository settings with publish access to `@cartridge/controller-wasm`

**Outputs:**
- Publishes to NPM registry
- Creates a deployment summary with installation instructions

---

## Other Workflows

### release.yml

Manual release workflow triggered via `repository_dispatch` event. Used for stable releases with explicit version numbers and GitHub releases.

### test.yml

Runs automated tests on pull requests and pushes.

### quality.yml

Runs code quality checks (linting, formatting).

### claude.yml

Integration with Claude Code assistant.
