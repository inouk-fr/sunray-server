# GitHub Actions & CI/CD

This directory contains GitHub Actions workflows and related documentation for the Sunray Server project.

## 📁 Directory Structure

```
.github/
├── workflows/
│   └── docker-build.yml        # Docker build and push workflow
├── GITHUB_ACTIONS_SETUP.md     # Complete setup guide
├── SECRETS.md                  # Secrets configuration guide
└── README.md                   # This file
```

## 🚀 Quick Start

### For First-Time Setup

1. **Configure Secrets** (Required):
   - Read [SECRETS.md](SECRETS.md) for detailed instructions
   - Add `MPY_REPO_GIT_TOKEN` to repository secrets
   - This allows Docker builds to clone the GitLab repository

2. **Push to Trigger Build**:
   ```bash
   git add .
   git commit -m "Add GitHub Actions workflows"
   git push origin main
   ```

3. **Monitor Build**:
   - Go to **Actions** tab in your GitHub repository
   - Watch the "Docker Build and Push" workflow run
   - First build takes ~10-15 minutes (no cache)

4. **Verify Image**:
   - Go to **Packages** in your GitHub profile
   - Find `sunray-server` package
   - Image should be tagged with branch name and SHA

### For Daily Development

**Pull Request Workflow**:
```bash
git checkout -b feature/my-feature
# Make changes
git commit -m "Add new feature"
git push origin feature/my-feature
# Create PR on GitHub
# Docker build runs automatically (build only, no push)
```

**Merge to Main**:
```bash
# After PR approval and merge
# Workflow automatically builds and pushes to ghcr.io
# Image tagged: latest, main, main-<sha>
```

**Release Workflow**:
```bash
# Create and push version tag
git tag -a v1.2.3 -m "Release version 1.2.3"
git push origin v1.2.3
# Workflow automatically builds and pushes
# Image tagged: v1.2.3, 1.2, 1, latest
```

## 🔄 Workflows

### docker-build.yml

**Purpose**: Build and push Docker images to GitHub Container Registry.

**Triggers**:
- Push to `main`, `develop`, `release/**` branches
- Push version tags (`v*.*.*`)
- Pull requests to `main` or `develop`
- Manual trigger via Actions UI

**Outputs**:
- Docker images at `ghcr.io/<owner>/sunray-server:<tag>`
- Build attestations for supply chain security
- Build cache for faster subsequent builds

**Configuration**:
- See [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md) for details
- Requires `MPY_REPO_GIT_TOKEN` secret

## 📋 Documentation

| File | Purpose | Audience |
|------|---------|----------|
| [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md) | Complete setup and usage guide | DevOps, Admins |
| [SECRETS.md](SECRETS.md) | Step-by-step secrets configuration | First-time setup |
| [workflows/docker-build.yml](workflows/docker-build.yml) | Docker build workflow definition | Developers |

## 🔐 Security

### Secrets Management
- All secrets stored securely in GitHub
- Automatically masked in workflow logs
- Follow least-privilege principle
- See [SECRETS.md](SECRETS.md) for best practices

### Supply Chain Security
- Build attestations generated automatically
- Docker layer scanning available (optional)
- SBOM generation supported (optional)
- Signed container images (optional)

### Recommendations
- Enable Dependabot for dependency updates
- Configure branch protection rules
- Require status checks before merge
- Enable vulnerability scanning

## 🎯 Common Tasks

### View Workflow Runs
1. Go to repository **Actions** tab
2. Select workflow from left sidebar
3. Click on specific run to see details
4. View logs, artifacts, and outputs

### Re-run Failed Workflow
1. Navigate to failed workflow run
2. Click **Re-run jobs** dropdown
3. Select **Re-run failed jobs** or **Re-run all jobs**

### Cancel Running Workflow
1. Navigate to running workflow
2. Click **Cancel workflow** button
3. Confirm cancellation

### Download Build Artifacts
Currently no artifacts, but can be added:
```yaml
- name: Upload build logs
  uses: actions/upload-artifact@v3
  with:
    name: build-logs
    path: build.log
```

### Debug Workflow Issues
1. Check workflow logs in Actions tab
2. Look for red error messages
3. Common issues:
   - Missing secrets → Check [SECRETS.md](SECRETS.md)
   - Syntax errors → Validate YAML syntax
   - Permission errors → Check repository settings

## 🔧 Customization

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
        run: ./bin/test_server.sh
```

### Adding Code Quality Checks
Add to workflow:
```yaml
- name: Run linter
  run: |
    pip install flake8
    flake8 project_addons/
```

### Multi-Platform Builds
Enable in `docker-build.yml`:
```yaml
- name: Set up QEMU
  uses: docker/setup-qemu-action@v3

- name: Build and push
  with:
    platforms: linux/amd64,linux/arm64
```

### Deploy to Staging
Create environment-specific workflow:
```yaml
name: Deploy to Staging
on:
  push:
    branches: [develop]
jobs:
  deploy:
    environment: staging
    steps:
      - name: Deploy
        run: |
          # Deployment commands
```

## 📊 Monitoring

### Build Status Badge
Add to repository README:
```markdown
![Docker Build](https://github.com/OWNER/REPO/actions/workflows/docker-build.yml/badge.svg)
```

### Metrics to Monitor
- Build success rate
- Build duration
- Image size trends
- Vulnerability count
- Cache hit rate

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| Build fails immediately | Check secrets configuration |
| Cannot clone GitLab repo | Verify `MPY_REPO_GIT_TOKEN` is valid |
| Cannot push to registry | Check `packages: write` permission |
| Build is slow | Verify cache is enabled (it is) |
| Workflow doesn't trigger | Check branch name matches trigger rules |

See [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md#troubleshooting) for detailed troubleshooting.

## 🔄 Migration from GitLab

If migrating from GitLab AutoDevOps:

1. **Secrets**: Copy `MPY_REPO_GIT_TOKEN` from GitLab CI/CD variables
2. **Workflows**: GitHub Actions workflows are already configured
3. **Registry**: Images will be at `ghcr.io` instead of GitLab registry
4. **Compatibility**: Both systems can coexist during migration
5. **Testing**: Verify GitHub Actions build succeeds before disabling GitLab CI

**Note**: The repository is already configured for both GitLab and GitHub.

## 📚 Additional Resources

### GitHub Documentation
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [GitHub Packages](https://docs.github.com/en/packages)
- [Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)

### Docker Documentation
- [Build and Push Action](https://github.com/docker/build-push-action)
- [Metadata Action](https://github.com/docker/metadata-action)
- [Setup Buildx Action](https://github.com/docker/setup-buildx-action)

### Project Documentation
- [Main README](../README.md)
- [Dockerfile](../Dockerfile)
- [CLAUDE.md](../CLAUDE.md) - Development guidelines

## 💬 Support

For issues or questions:
- **GitHub Issues**: Report bugs or request features
- **Actions Logs**: Check workflow run logs for errors
- **Documentation**: Review files in this directory
- **Community**: Contribute improvements via pull requests
