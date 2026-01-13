# Cyber

A website and repository for everything related to my studies and notes to be used as a reference.

## Quick Start

To clone this repository with all its submodules, use:

```bash
git clone --recursive https://github.com/opensourcekyle/cyber.git
```

### Download the Theme

**First time setup** (if you cloned without `--recursive` or the theme is missing):

```bash
rm -rf .themes
git submodule add https://github.com/McShelby/hugo-theme-relearn.git .themes/hugo-theme-relearn
```

### Build Website

```bash
\rm -rf public/ resources/ && hugo server --noHTTPCache
```

### Adding Front Matter to Lab Files (pre-commit hook)

A git pre-commit hook is set up at `.git/hooks/pre-commit` to automatically add front matter to lab files before each commit. This ensures all new lab files will have proper front matter even if you forget to add it manually.

The hook:

- Automatically runs `scripts/add-front-matter.py` on lab directories before each commit
- Processes files in `content/Labs - TryHackMe` and `content/Labs - HackTheBox`
- Automatically stages any modified files after adding front matter
- Runs silently and won't interrupt your commit workflow

**Note:** If you clone this repository, you may need to make the hook executable:

```bash
chmod +x .git/hooks/pre-commit
```
