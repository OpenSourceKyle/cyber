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
git submodule update --init --recursive
```

**Update the theme** to the latest version:

```bash
git submodule update --remote --recursive
```

### Adding Front Matter to Lab Files

Lab files need front matter for Hugo to render them correctly. A script automatically adds front matter to any lab files that don't have it:

**Manually run the script:**
```bash
python3 scripts/add-front-matter.py
```

**Dry run (see what would be changed):**
```bash
python3 scripts/add-front-matter.py --dry-run
```

A git pre-commit hook is also set up to automatically add front matter when you commit lab files. This ensures all new lab files will have proper front matter even if you forget to add it manually.
