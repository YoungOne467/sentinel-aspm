# Contributing to SENTINEL

Thank you for your interest in improving SENTINEL! We welcome contributions from developers, security researchers, and documenters alike. To ensure a smooth collaboration process and maintain codebase health, please follow the guidelines detailed below.

---

## 1. Getting Started

1.  **Fork the Repository**: Create a personal fork of the SENTINEL repository on GitHub.
2.  **Clone Your Fork**: Clone your personal fork to your local machine:
    ```bash
    git clone https://github.com/[your-username]/vulnerability-scanner.git
    cd vulnerability-scanner
    ```
3.  **Create a Branch**: Create a clean feature or bugfix branch off of the `main` branch. Use descriptive and clear naming patterns:
    *   `feature/your-change-name` for new features or enhancements.
    *   `bugfix/your-change-name` for bug fixes.
    *   `docs/your-change-name` for documentation improvements.
    
    ```bash
    git checkout -b feature/your-awesome-change
    ```

---

## 2. Code Style, Linting, & Formatting

We enforce strict formatting and linting checks across both Python (backend) and TypeScript (frontend) components to keep the codebase clean, legible, and consistent.

### Pre-commit Hooks (Recommended)
The easiest way to comply with our code style guidelines is to set up **pre-commit** hooks. They automatically check and format your code before every commit.

1.  Install `pre-commit` locally:
    ```bash
    pip install pre-commit
    ```
2.  Install the git hooks in the repository root:
    ```bash
    pre-commit install
    ```
3.  (Optional) Run all checks manually against the entire codebase:
    ```bash
    pre-commit run --all-files
    ```

### Manual Backend Check (Python)
If you prefer not to use pre-commit, you must run linting and formatting checks manually on the backend before submitting a PR:
*   **Ruff** (Linting & Code Style):
    ```bash
    cd backend
    ruff check .
    ```
*   **Black** (Code Formatting):
    ```bash
    cd backend
    black .
    ```

### Manual Frontend Check (TypeScript/React)
Ensure the UI meets the linting and formatting requirements before proposing frontend changes:
*   **ESLint** (Linting):
    ```bash
    cd aspm-frontend
    npm run lint
    ```
*   **Prettier** (Code Formatting):
    ```bash
    cd aspm-frontend
    npx prettier --write "src/**/*.{ts,tsx,css,html}"
    ```

---

## 3. Testing Requirements

All contributions must include appropriate unit or integration tests to ensure that changes do not introduce regressions.

### Backend Tests
*   Ensure all existing backend tests pass successfully:
    ```bash
    cd backend
    # Activate virtual environment
    # On macOS/Linux: source venv/bin/activate
    # On Windows: venv\Scripts\activate
    
    pytest
    ```
*   Alternatively, you can run the primary system layer tests directly:
    ```bash
    python backend/test_layer3.py
    ```

### Frontend Tests
*   Verify the frontend code compiles and builds correctly:
    ```bash
    cd aspm-frontend
    npm run build
    ```
*   Run the frontend test suite:
    ```bash
    cd aspm-frontend
    npm run test
    ```

---

## 4. Development Workflow & Git Discipline

### Commit Message Guidelines
We follow standard conventional commit guidelines. Keep messages structured and concise.
*   **Format**: `<type>(<scope>): <short summary>`
*   **Examples**:
    *   `feat(core): implement async subprocess runner in plugin engine`
    *   `fix(frontend): resolve memory leak in canvas network graph`
    *   `docs(readme): update environment variable reference table`

### Secrets Scrubbing & Security
SENTINEL is an application security product. To guarantee no local environment configurations, secrets, database credentials, or private paths are committed to the git history:
1.  Always run the history scrubbing script before committing or pushing changes:
    ```bash
    bash scratch/git_scrub.sh
    ```
2.  Never commit `.env` or any sensitive files. Verify your `git status` before committing.

---

## 5. Submitting your Pull Request (PR)

Before submitting your PR, ensure that:
1.  Your code meets all the style and linting standards (pre-commit checks pass).
2.  All backend and frontend tests pass.
3.  The git history scrubbing script has been executed.
4.  Your PR description clearly states:
    *   What the problem was and what change you made.
    *   Why you chose this specific implementation.
    *   Any relevant test commands run and screenshot evidence if there are UI additions or modifications.
5.  Target your PR against the `main` branch.
