
---

# CONTRIBUTIONS.md

```markdown
# Contributing to TS RBAC System

First off, thank you for considering contributing to the RBAC System! 🎉

We welcome contributions from everyone. Whether you're fixing a bug, adding a feature, or improving documentation, your help is invaluable.

## 📜 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it carefully:

- **Be respectful** — Treat everyone with kindness and professionalism.
- **Be inclusive** — Use inclusive language and welcome diverse perspectives.
- **Be collaborative** — Work together constructively and give constructive feedback.
- **Be responsible** — Take ownership of your work and communicate clearly.

---

## 🚀 Getting Started

1. ### Clone the Repository:
   ```bash
   git clone https://github.com/Steve-s-Circle-on-System-Design/py-fastapi-rbac-auth-system.git
   cd py-fastapi-rbac-auth-system

---

2. ### Install dependencies:
    ```bash
    uv sync

---

3. ### Configure Environment Variables:
    Create a .env file in the root directory and configure your credentials:
    ```bash
    cp .env.example .env

---

4. ### Run Database Migrations / Sync Engine:
    ```bash
    alembic upgrade head

---

5. ### Fire Up the Engine Server:
    #### Development watch mode
    

    #### Production build compilation
    

---

6. ### Create a Branch:
    #### Create a branch for your feature or bugfix:
    git checkout -b feature/your-feature-name
    ### or
    git checkout -b fix/your-bugfix-name

---

7. ### Development Guidelines:
    #### Code Style:
    ✅ Use Python for all new code

    ✅ Follow the FastAPI style guide and best practices

    ✅ Use Ruff for formatting

    ✅ Use pydantic for data validation 

    ✅ Write meaningful variable and function names

    ✅ Keep functions focused and single-purpose

    ### Run linter
    ruff check .

    ### Auto-fix linting issues
    uv run ruff check --fix .

    ### Format code
    ruff format .

---

8. ### Commit Message Convention:
    #### We follow the Conventional Commits specification:
    <type>(<scope>): <subject>

    <body>

    <footer>

    #### Types
    ✅ feat — New feature

    ✅ fix — Bug fix

    ✅ docs — Documentation changes

    ✅ style — Code style changes (formatting, semi-colons, etc.)

    ✅ refactor — Code refactoring

    ✅ perf — Performance improvements

    ✅ test — Adding or updating tests

    ✅ chore — Build process, dependencies, etc.

    #### Examples
    feat(auth): implement Google OAuth 2.0 integration

    Adds OAuth flow with automatic account linking for existing users.

    Closes #123

    fix(email): resolve retry logic in exponential backoff

    Fixes issue where retries would not trigger after the first failure.

    Fixes #456

---

9. ### Testing Requirements:
    ✅ All new features must include unit tests

    ✅ Bug fixes should include regression tests

    ✅ Maintain or improve code coverage (target: 80%+)

    ✅ Tests should be isolated and independent

    ### Run all tests
    uv run pytest

    ### Run tests for a particular file
    uv run pytest tests/<file_name>

    ### Run tests and stop after first failure
    uv run pytest -x

    ### Run tests verbose
    uv run pytest -v

    ### Generate coverage report
    uv run pytest --cov=.
    uv run pytest --cov=. --cov-report=term-missing #exposing missing coverage

---

10. ### Documentation Standards:
    ✅ Update README.md for user-facing changes

    ✅ Update CONTRIBUTIONS.md for developer-facing changes

    ✅ Add JSDoc comments to new functions and classes

    ✅ Include OpenAPI/Swagger annotations for all endpoints

    ✅ Create separate markdown files in /docs for complex features

---

11. ### Security Best Practices:
    ✅ Never commit sensitive data (passwords, secrets, API keys)

    ✅ Always validate and sanitize user inputs

    ✅ Always use parameterized queries for database operations

    ✅ Always use environment variables for configuration

    ✅ Always run security scans before PR submission

    ### Run security audit
    uv audit

---

12. ### Pull Request Process:
    #### Before Submitting a PR:
    ✅ Update your fork: Rebase against the latest main branch

    ✅ Run tests: Ensure all tests pass locally

    ✅ Update documentation: If you added/changed features, update README and docs

    ✅ Check coverage: Ensure coverage doesn't decrease

    ✅ Self-review: Review your own code before submission

    #### PR Submission Checklist:
    ✅ I have read and followed the code of conduct

    ✅ My code follows the project's style guide

    ✅ I have added/updated tests that prove my fix/feature works

    ✅ I have updated the documentation accordingly

    ✅ My commit messages follow the conventional commits spec

    ✅ I have linked related issues in the PR description

    ✅ All new and existing tests pass

    #### PR Title Convention:
    <type>(<scope>): <description>

    #### PR Description Template:
    ## Description
    [Provide a clear and concise description of what this PR does]

    #### Related Issues
    [Link any related issues using #issue-number]

    #### Type of Change
    - [ ] Bug fix (non-breaking change)
    - [ ] New feature (non-breaking change)
    - [ ] Breaking change
    - [ ] Documentation update

    #### Testing
    - [ ] Unit tests added/updated
    - [ ] E2E tests added/updated
    - [ ] Manually tested

    #### Screenshots (if applicable)
    [Add screenshots to demonstrate the changes]

    ## Checklist
    - [ ] Code follows project style
    - [ ] Documentation has been updated
    - [ ] Tests pass locally
    - [ ] No new warnings/errors
    - [ ] Security best practices followed

---

13. ### Issue Guidelines
    #### Reporting Bugs

    Use the Bug Report template and include:

    ✅ Title: Clear, descriptive summary

    ✅ Environment: OS, Node version, browser (if relevant)

    ✅ Steps to Reproduce: Step-by-step guide

    ✅ Expected Behavior: What should happen

    ✅ Actual Behavior: What actually happens

    ✅Screenshots: If applicable

    ✅ Logs/Errors: Full error messages and stack traces

    #### Suggesting Features

    Use the Feature Request template and include:

    ✅ Title: Clear, descriptive summary

    ✅ Problem: What problem does this solve?

    ✅ Solution: How would this feature work?

    ✅ Alternatives: Are there workarounds?

    ✅ Priority: How important is this to you?

    #### Labels

    Our maintainers will add labels to help categorize issues:

    ✅ bug — Something isn't working

    ✅ feature — New feature request

    ✅ enhancement — Improvement to existing feature

    ✅ documentation — Docs changes needed

    ✅ good-first-issue — Good for newcomers

    ✅ help-wanted — Community contributions welcome

---

14. ### Code Review Process
    ✅ Initial Review — Maintainers will review within 48 hours

    ✅ Feedback — Address comments and push updates

    ✅ Approval — At least one maintainer approval required

    ✅ Merge — PR will be merged once all checks pass

    #### Review Etiquette

    ✅ Be constructive and specific in feedback

    ✅ Explain the "why" behind suggestions

    ✅ Ask clarifying questions when needed

    ✅ Be open to different approaches

    ✅ Respond to reviews promptly

---

15. ### Security Vulnerabilities

    If you discover a security vulnerability, please do NOT open a public issue.

    Instead, email us directly at security@rbac-system.com with:

    ✅ A detailed description of the vulnerability

    ✅ Steps to reproduce

    ✅ Potential impact

    ✅ Suggested mitigation

    We will respond within 48 hours and work with you to resolve the issue.

---

16. ### Recognition

    Contributors who make significant contributions will be:

    ✅ Added to the CONTRIBUTORS.md file

    ✅ Recognized in release notes

    ✅ Considered for maintainer roles (after consistent contributions)

---

Thank you for contributing to RBAC System!