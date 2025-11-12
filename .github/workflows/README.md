# GitHub Actions Workflows

## Release Workflow

### release.yml

Handles both dev and stable WASM package releases to NPM.

#### Dev Publishing (Automatic)

**Trigger:** Pushes to `main` branch that modify:

- `account-wasm/**`
- `account_sdk/**`
- `contracts/**`

**Versioning:** Uses format `{base-version}-{short-sha}`:

- Base version in package.json: `0.7.14-alpha.3`
- Short SHA: `abc1234`
- Published version: `0.7.14-abc1234`

**NPM Tag:** `dev` (doesn't affect `latest`)

**Installation:**

```bash
# Install latest dev version
npm install @cartridge/controller-wasm@dev

# Install specific commit
npm install @cartridge/controller-wasm@0.7.14-abc1234
```

#### Stable Release (Manual)

**Trigger:** `repository_dispatch` event via `release-dispatch.yml`

**Versioning:** Uses explicit version number from dispatch payload

**NPM Tag:** `latest`

**Outputs:**

- NPM package publication
- GitHub release with tarballs
- Deployment summary

**Requirements:**

- `NPM_TOKEN` secret must be configured in repository settings

---

## Other Workflows

### release-dispatch.yml

UI trigger for manual stable releases. Dispatches to the release workflow with specified version number.

### test.yml

Runs automated tests on pull requests and pushes.

### quality.yml

Runs code quality checks (linting, formatting).

### claude.yml

Integration with Claude Code assistant.
