# GitHub Actions Setup for Sunray Server

This document explains how to configure GitHub Actions for Docker builds and CI/CD.

## Overview

The repository includes GitHub Actions workflows that:

1. **Docker Build and Push** (`docker-build.yml`):
   - Builds Docker image on every push/PR
   - Publishes to GitHub Container Registry (ghcr.io)
   - Automatic tagging (branch names, semver, SHA)
   - Docker layer caching for faster builds
   - Build attestation for supply chain security

## Prerequisites

1. **GitHub Repository**: Your repository must be on GitHub
2. **GitHub Packages**: Enabled by default for all repositories
3. **Secrets Configuration**: Required secrets must be set

## Required Secrets

Configure these secrets in your GitHub repository:

### 1. MPY_REPO_GIT_TOKEN

**Purpose**: GitLab access token for cloning the private inouk-sunray-server repository during Docker build.

**How to set**:
1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `MPY_REPO_GIT_TOKEN`
5. Value: Your GitLab token (same as `$MPY_REPO_GIT_TOKEN` used in GitLab CI)
6. Click **Add secret**

**Security Note**: This token is passed as a build argument during Docker image creation. It is NOT embedded in the final image layers.

### 2. GITHUB_TOKEN (Automatic)

**Purpose**: Authenticate to GitHub Container Registry and attest build provenance.

**Configuration**: No action required - automatically provided by GitHub Actions.

## Workflow Triggers

The Docker build workflow runs on:

- **Push to branches**: `main`, `develop`, `release/**`
- **Push tags**: `v*.*.*` (e.g., v1.0.0, v2.1.3)
- **Pull requests**: To `main` or `develop` (build only, no push)
- **Manual trigger**: Via GitHub Actions UI (workflow_dispatch)

## Docker Image Tags

Images are automatically tagged based on the trigger:

| Trigger | Image Tags | Example |
|---------|------------|---------|
| Push to `main` | `latest`, `main`, `main-<sha>` | `ghcr.io/inouk-fr/sunray-server:latest` |
| Push to `develop` | `develop`, `develop-<sha>` | `ghcr.io/inouk-fr/sunray-server:develop` |
| Push tag `v1.2.3` | `v1.2.3`, `1.2`, `1`, `<sha>` | `ghcr.io/inouk-fr/sunray-server:1.2.3` |
| PR #42 | `pr-42` | `ghcr.io/inouk-fr/sunray-server:pr-42` (build only) |

## Using the Docker Images

### Pull from GitHub Container Registry

```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Pull the latest image
docker pull ghcr.io/inouk-fr/sunray-server:latest

# Pull a specific version
docker pull ghcr.io/inouk-fr/sunray-server:1.2.3

# Pull from a specific branch
docker pull ghcr.io/inouk-fr/sunray-server:develop
```

### Run the Container

```bash
# Run with environment variables
docker run -d \
  --name sunray-server \
  -p 8069:8069 \
  -e PGUSER=odoo \
  -e PGPASSWORD=your_password \
  -e PGDATABASE=sunray \
  -e PGHOST=db.example.com \
  -e PGPORT=5432 \
  ghcr.io/inouk-fr/sunray-server:latest
```

## GitHub Container Registry Visibility

By default, packages are **private**. To make them public:

1. Go to your GitHub profile → **Packages**
2. Select the `sunray-server` package
3. Go to **Package settings**
4. Under **Danger Zone**, click **Change visibility**
5. Select **Public** or keep **Private**

## Comparing with GitLab AutoDevOps

| Feature | GitLab AutoDevOps | GitHub Actions |
|---------|-------------------|----------------|
| Docker Build | Automatic (via template) | Custom workflow (more control) |
| Container Registry | GitLab Registry | GitHub Container Registry (ghcr.io) |
| Image Tags | Auto-generated | Customizable via metadata-action |
| Caching | Built-in | GitHub Actions cache (type=gha) |
| Tests | Can be enabled | Can add separate workflow |
| Security Scanning | Built-in (optional) | Can add Trivy/Snyk actions |

## Troubleshooting

### Build fails with "access denied" to GitLab

**Problem**: Docker build cannot clone the GitLab repository.

**Solution**:
1. Verify `MPY_REPO_GIT_TOKEN` secret is set correctly
2. Check token has `read_repository` scope
3. Verify token is not expired

### Cannot push to GitHub Container Registry

**Problem**: Error pushing image after build.

**Solution**:
1. Verify GitHub Packages is enabled
2. Check workflow has `packages: write` permission (already configured)
3. Ensure `GITHUB_TOKEN` has sufficient permissions

### Docker build is slow

**Problem**: Builds take a long time.

**Solution**:
- Caching is enabled by default (`cache-from: type=gha`)
- First build will be slow (no cache)
- Subsequent builds should be faster

## Advanced Configuration

### Adding Tests

Create `.github/workflows/tests.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: |
          # Add your test commands here
          ./bin/test_server.sh
```

### Adding Security Scanning

Add to `docker-build.yml` after build step:

```yaml
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

### Multi-platform Builds

To build for multiple architectures (AMD64, ARM64):

```yaml
      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
          # ... other parameters
```

**Note**: Multi-platform builds are slower. Enable only if needed.

## Migration Checklist from GitLab to GitHub

- [x] Create `.github/workflows/docker-build.yml`
- [ ] Set `MPY_REPO_GIT_TOKEN` secret in GitHub repository settings
- [ ] Push changes to GitHub
- [ ] Verify first workflow run succeeds
- [ ] Pull and test Docker image from ghcr.io
- [ ] Update deployment scripts to use new registry
- [ ] (Optional) Configure package visibility (public/private)
- [ ] (Optional) Add test workflows
- [ ] (Optional) Add security scanning

## Support

For issues or questions:
- GitHub Actions logs: Check **Actions** tab in your repository
- GitHub Container Registry: Check **Packages** in your profile
- Dockerfile issues: See `Dockerfile` comments and `CLAUDE.md`
