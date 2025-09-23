# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cybersecurity research wiki built with MkDocs Material. It contains documentation on AI security, cloud security, red team tactics, techniques and procedures (TTPs), vulnerability research, and security tools.

## Development Commands

### Build and Serve Locally
```bash
# Install dependencies
pip install -r requirements.txt

# Serve locally with hot reload
mkdocs serve

# Build static site
mkdocs build
```

### Content Management
```bash
# Create new documentation section
mkdir docs/new-section
echo "# New Section" > docs/new-section/index.md

# Preview changes
mkdocs serve --dev-addr=127.0.0.1:8000
```

## Project Structure

- `docs/` - All documentation content in Markdown format
  - `ai-security/` - AI/ML security research and techniques
  - `cloud-security/` - Cloud platform security documentation
  - `ttps/` - Red team tactics, techniques, and procedures
  - `research/` - Vulnerability research and findings
  - `tools/` - Security tools and methodologies
  - `includes/abbreviations.md` - Common cybersecurity acronym definitions
- `mkdocs.yml` - MkDocs configuration (currently minimal)
- `requirements.txt` - Python dependencies for MkDocs and plugins
- `.github/workflows/deploy.yml` - Automated deployment to GitHub Pages
- `overrides/` - Custom theme overrides
- `site/` - Generated static site (auto-built)

## Deployment

The site automatically deploys to GitHub Pages on pushes to the main branch via GitHub Actions. The workflow:
1. Sets up Python 3.x
2. Installs MkDocs Material and plugins
3. Builds the site with `mkdocs build`
4. Deploys to GitHub Pages

## Content Guidelines

- All content is in Markdown format
- Use the abbreviations file for consistent acronym definitions
- Each major section has an index.md file
- Focus on cybersecurity research, defensive techniques, and educational content
- Organize content by security domain (AI, cloud, tools, etc.)