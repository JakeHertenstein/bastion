# Seed Card Deployment Guide

This guide covers deploying the Seed Card web interface to various platforms.

## 🚀 GitHub Pages (Recommended)

### Prerequisites
- GitHub repository with the Seed Card project
- GitHub Pages enabled in repository settings

### Automatic Deployment

1. **Enable GitHub Pages**:
   ```
   Repository Settings → Pages → Source: GitHub Actions
   ```

2. **Push to main branch**:
   ```bash
   git add docs/web/
   git commit -m "Add web interface"
   git push origin main
   ```

3. **Monitor deployment**:
   - Check Actions tab for deployment status
   - Site will be available at: `https://your-username.github.io/seed-card/`

### Manual Deployment

If you prefer manual control:

```bash
# Enable GitHub Pages
gh repo edit --enable-pages --pages-branch gh-pages

# Deploy manually
cd docs/web
git init
git add .
git commit -m "Initial web deployment"
git branch -M gh-pages
git remote add origin https://github.com/your-username/seed-card.git
git push -u origin gh-pages
```

## 🌐 Custom Domain Setup

### DNS Configuration

1. **Add CNAME record**:
   ```
   Type: CNAME
   Name: seed-card (or subdomain of choice)
   Value: your-username.github.io
   ```

2. **Update GitHub Pages settings**:
   ```
   Repository Settings → Pages → Custom domain: seed-card.yourdomain.com
   ```

3. **Enable HTTPS**:
   - Check "Enforce HTTPS" in Pages settings
   - Wait for SSL certificate provision (~24 hours)

### Example DNS Setup
```
# For subdomain: tools.example.com
CNAME tools your-username.github.io

# For root domain: example.com (requires apex domain setup)
A @ 185.199.108.153
A @ 185.199.109.153
A @ 185.199.110.153
A @ 185.199.111.153
```

## ☁️ Alternative Hosting Platforms

### Netlify

1. **Connect repository**:
   ```
   Build command: (leave blank)
   Publish directory: docs/web
   ```

2. **Configure redirects** (`docs/web/_redirects`):
   ```
   /*    /index.html   200
   ```

3. **Security headers** (`docs/web/_headers`):
   ```
   /*
     Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
     X-Frame-Options: DENY
     X-Content-Type-Options: nosniff
   ```

### Vercel

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Deploy**:
   ```bash
   cd docs/web
   vercel --prod
   ```

3. **Configure** (`vercel.json`):
   ```json
   {
     "routes": [
       { "src": "/(.*)", "dest": "/$1" }
     ],
     "headers": [
       {
         "source": "/(.*)",
         "headers": [
           { "key": "X-Frame-Options", "value": "DENY" },
           { "key": "X-Content-Type-Options", "value": "nosniff" }
         ]
       }
     ]
   }
   ```

### AWS S3 + CloudFront

1. **Create S3 bucket**:
   ```bash
   aws s3 mb s3://seed-card-web
   aws s3 sync docs/web/ s3://seed-card-web --delete
   ```

2. **Configure bucket policy**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "PublicReadGetObject",
         "Effect": "Allow",
         "Principal": "*",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::seed-card-web/*"
       }
     ]
   }
   ```

3. **Create CloudFront distribution**:
   ```bash
   aws cloudfront create-distribution --distribution-config file://distribution-config.json
   ```

## 🔐 Security Hardening

### Content Security Policy

Implement strict CSP headers:

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'none'; img-src 'self' data:; base-uri 'self'; form-action 'none';
```

### Additional Headers

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### HTTPS Enforcement

Always enforce HTTPS in production:

```html
<script>
if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    location.replace('https:' + window.location.href.substring(window.location.protocol.length));
}
</script>
```

## 📊 Analytics & Monitoring

### Privacy-Preserving Analytics

Use privacy-focused analytics that don't track users:

```html
<!-- Simple Analytics (GDPR compliant) -->
<script async defer src="https://scripts.simpleanalyticscdn.com/latest.js"></script>
<noscript><img src="https://queue.simpleanalyticscdn.com/noscript.gif" alt="" referrerpolicy="no-referrer-when-downgrade" /></noscript>
```

### Performance Monitoring

Monitor Core Web Vitals:

```javascript
// Add to app.js
function reportWebVitals() {
    getCLS(console.log);
    getFID(console.log);
    getFCP(console.log);
    getLCP(console.log);
    getTTFB(console.log);
}

// Load web-vitals library
import('https://unpkg.com/web-vitals@3.3.2/dist/web-vitals.js')
    .then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
        getCLS(console.log);
        getFID(console.log);
        getFCP(console.log);
        getLCP(console.log);
        getTTFB(console.log);
    });
```

## 🔄 Continuous Deployment

### GitHub Actions Workflow

The included workflow (`.github/workflows/deploy-pages.yml`) provides:

- **Automated testing** of HTML/CSS/JS syntax
- **Security scanning** for common vulnerabilities
- **Performance optimization** checks
- **Automatic deployment** on push to main
- **Pull request validation** for safe changes

### Deployment Triggers

```yaml
on:
  push:
    branches: [ main ]
    paths: [ 'docs/web/**' ]
  
  # Manual deployment
  workflow_dispatch:
  
  # Scheduled updates (monthly)
  schedule:
    - cron: '0 0 1 * *'
```

## 🧪 Testing Deployment

### Local Testing

```bash
# Python
cd docs/web && python -m http.server 8000

# Node.js
cd docs/web && npx serve

# PHP
cd docs/web && php -S localhost:8000
```

### Production Testing

```bash
# Test deployed site
curl -f -s https://your-username.github.io/seed-card/
curl -f -s https://your-username.github.io/seed-card/generator.html

# Check security headers
curl -I https://your-username.github.io/seed-card/

# Validate HTML
html5validator --root https://your-username.github.io/seed-card/
```

## 🚨 Rollback Procedures

### GitHub Pages Rollback

```bash
# Revert to previous commit
git revert HEAD
git push origin main

# Or rollback to specific commit
git reset --hard COMMIT_HASH
git push --force origin main
```

### Emergency Procedures

1. **Disable site**: Remove CNAME file or disable Pages in settings
2. **Hotfix deployment**: Push critical fixes directly to main
3. **Maintenance mode**: Replace index.html with maintenance page

## 📋 Post-Deployment Checklist

- [ ] Site loads correctly at primary URL
- [ ] All pages (index.html, generator.html) accessible
- [ ] JavaScript functions work (test password generation)
- [ ] CSS styles load properly
- [ ] Security headers are present
- [ ] HTTPS enforced
- [ ] Analytics tracking (if implemented)
- [ ] Error tracking functional
- [ ] Performance metrics acceptable
- [ ] Mobile responsive design works
- [ ] Offline functionality (test with network disabled)

## 🔧 Troubleshooting

### Common Issues

**Site not loading**:
- Check GitHub Actions deployment status
- Verify GitHub Pages source configuration
- Check for DNS propagation (24-48 hours)

**JavaScript errors**:
- Test locally first
- Check browser console for errors
- Verify CSP headers aren't blocking scripts

**CSS not loading**:
- Check for correct relative paths
- Verify CDN resources are accessible
- Test without external font dependencies

**Performance issues**:
- Optimize images and assets
- Minimize HTTP requests
- Consider CDN for static assets

### Debug Commands

```bash
# Check deployment status
gh api repos/:owner/:repo/pages/builds

# Validate HTML
html5validator --root docs/web/

# Test JavaScript syntax
node -c docs/web/crypto.js

# Check file sizes
ls -lah docs/web/
```
