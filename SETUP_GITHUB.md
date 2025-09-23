# GitHub Setup Instructions

## 1. Create GitHub Repository
1. Go to https://github.com/new
2. Name it: cybersec-wiki
3. Make it public
4. Don't initialize with README

## 2. Push to GitHub
```bash
git remote add origin https://github.com/YOUR_USERNAME/cybersec-wiki.git
git branch -M main
git push -u origin main
```

## 3. Enable GitHub Pages
1. Go to Settings > Pages
2. Source: GitHub Actions
3. Save

## 4. Wait for Deployment
- Check Actions tab for build status
- Site will be available at: https://YOUR_USERNAME.github.io/cybersec-wiki/

## 5. Custom Domain (Optional)
1. Add CNAME file to docs/ with your domain
2. Configure DNS:
   - A records: 185.199.108.153, 185.199.109.153, 185.199.110.153, 185.199.111.153
   - CNAME: YOUR_USERNAME.github.io
