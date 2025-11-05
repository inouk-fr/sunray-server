# GitHub Secrets Configuration

This document provides step-by-step instructions for configuring GitHub secrets required for CI/CD workflows.

## Required Secrets

### MPY_REPO_GIT_TOKEN

**Purpose**: GitLab access token for cloning the inouk-sunray-server repository during Docker builds.

**Required Permissions**:
- `read_repository` - Read access to the GitLab repository

**How to Create the Token**:

1. **On GitLab** (https://gitlab.com):
   - Navigate to your profile (top-right avatar)
   - Go to **Preferences** → **Access Tokens**
   - Click **Add new token**
   - Fill in the details:
     - **Name**: `GitHub Actions Docker Build`
     - **Expiration date**: Set appropriate expiration (e.g., 1 year)
     - **Select scopes**: Check `read_repository`
   - Click **Create personal access token**
   - **IMPORTANT**: Copy the token immediately (you won't see it again)

2. **On GitHub** (your repository):
   - Navigate to your repository
   - Go to **Settings** → **Secrets and variables** → **Actions**
   - Click **New repository secret**
   - Fill in:
     - **Name**: `MPY_REPO_GIT_TOKEN`
     - **Secret**: Paste the GitLab token you copied
   - Click **Add secret**

**Security Notes**:
- ⚠️ This token is passed as a Docker build argument
- ⚠️ It is NOT embedded in the final Docker image layers
- ⚠️ The token is only used during the build process
- ✅ GitHub Actions masks secrets in logs automatically
- ✅ Set an expiration date and rotate tokens regularly

**Testing**:
After setting the secret, push a commit to trigger the Docker build workflow and verify it succeeds.

## Automatic Secrets

### GITHUB_TOKEN

**Purpose**:
- Authenticate to GitHub Container Registry (ghcr.io)
- Create build attestations for supply chain security
- Write to GitHub Packages

**Configuration**: No action required - automatically provided by GitHub Actions.

**Permissions** (automatically granted):
- `contents: read` - Read repository contents
- `packages: write` - Push to GitHub Container Registry
- `id-token: write` - Generate attestations

## Optional Secrets (For Advanced Features)

### DOCKER_USERNAME and DOCKER_PASSWORD

**Purpose**: Push images to Docker Hub instead of GitHub Container Registry.

**Only required if**: You want to publish to Docker Hub in addition to or instead of ghcr.io.

**How to set**:
1. Create Docker Hub account at https://hub.docker.com
2. Generate access token at https://hub.docker.com/settings/security
3. Add both secrets to GitHub:
   - `DOCKER_USERNAME`: Your Docker Hub username
   - `DOCKER_PASSWORD`: Your Docker Hub access token

**Workflow modification needed**:
```yaml
- name: Log in to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ secrets.DOCKER_USERNAME }}
    password: ${{ secrets.DOCKER_PASSWORD }}
```

## Secrets Management Best Practices

### Security

1. **Use Least Privilege**: Only grant necessary permissions
2. **Set Expiration**: Always set expiration dates for tokens
3. **Rotate Regularly**: Update tokens before expiration
4. **Audit Access**: Review secret usage in Actions logs
5. **Never Commit**: Never commit secrets to the repository

### Organization Secrets

If managing multiple repositories, consider using **Organization secrets**:

1. Go to your GitHub Organization → **Settings** → **Secrets and variables** → **Actions**
2. Create organization-level secrets
3. Select which repositories can access them

**Benefits**:
- Centralized management
- Consistent across repositories
- Easier rotation
- Better audit trail

### Environment-Specific Secrets

For production/staging environments:

1. Go to repository **Settings** → **Environments**
2. Create environments (e.g., `production`, `staging`)
3. Add environment-specific secrets
4. Configure protection rules (approvals, branch restrictions)

**Workflow usage**:
```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        env:
          PROD_TOKEN: ${{ secrets.PROD_TOKEN }}
```

## Troubleshooting

### "secret not found" Error

**Symptoms**: Workflow fails with error about missing secret.

**Solutions**:
1. Verify secret name matches exactly (case-sensitive)
2. Check secret is set at repository level (not organization)
3. Ensure you have write access to repository settings
4. Check secret hasn't been deleted accidentally

### Build Fails to Clone GitLab Repository

**Symptoms**: Docker build fails with "authentication required" or "access denied" from GitLab.

**Solutions**:
1. Verify `MPY_REPO_GIT_TOKEN` is set correctly
2. Check token has `read_repository` scope
3. Verify token is not expired
4. Test token manually:
   ```bash
   git clone https://dockerfile:YOUR_TOKEN@gitlab.com/cmorisse/inouk-sunray-server.git test-clone
   ```
5. Check GitLab repository is accessible (not deleted/moved)

### Token Visible in Logs

**Symptoms**: You see parts of your token in GitHub Actions logs.

**Solutions**:
- ⚠️ **CRITICAL**: Rotate the token immediately
- ✅ GitHub automatically masks registered secrets
- ⚠️ If passed incorrectly, may not be masked
- ✅ Always use `${{ secrets.NAME }}` syntax
- ❌ Never echo or print secrets directly

### Cannot Push to GitHub Container Registry

**Symptoms**: Build succeeds but push fails with authentication error.

**Solutions**:
1. Verify GitHub Packages is enabled (it is by default)
2. Check workflow has `packages: write` permission
3. Ensure repository is not archived
4. Check you have admin access to repository
5. Verify `GITHUB_TOKEN` has not been customized to remove permissions

## Verification Checklist

After configuring secrets, verify everything works:

- [ ] `MPY_REPO_GIT_TOKEN` is set in GitHub repository settings
- [ ] Token has `read_repository` scope on GitLab
- [ ] Token is not expired
- [ ] Push a commit to trigger workflow
- [ ] Docker build step succeeds (clones GitLab repo)
- [ ] Docker push step succeeds (pushes to ghcr.io)
- [ ] Image appears in GitHub Packages
- [ ] No secrets visible in Actions logs

## Getting Help

If you encounter issues:

1. **Check Actions logs**: Go to **Actions** tab → Select failed run → Review logs
2. **Review workflow file**: Check `.github/workflows/docker-build.yml` syntax
3. **Validate secrets**: Ensure secrets are set correctly
4. **Test manually**: Try building Docker image locally
5. **Consult documentation**: See [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md)

## Related Documentation

- [GitHub Actions Setup Guide](GITHUB_ACTIONS_SETUP.md)
- [GitHub Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Docker Build and Push Action](https://github.com/docker/build-push-action)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
