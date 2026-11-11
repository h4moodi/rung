"""Security probe tests. Fake credentials are assembled at runtime, never written whole."""

from __future__ import annotations

import pytest

from rung.models import Confidence, Dimension, Outcome, Severity
from rung.probes import security as sec
from rung.registry import REGISTRY

AWS_KEY = "AKIA" + "Q7RT" * 4
GH_TOKEN = "ghp_" + "a1B2" * 9
STRIPE_KEY = "sk_" + "live_" + "9zY8xW7v" * 3
SLACK_TOKEN = "xoxb-" + "1234509876" + "-" + "aBcD9eFg7hIj"
DB_PASSWORD = "Tr0ub4dor" + "Zebra9"
GENERIC_VALUE = "hT7" + "kP2mQ9" + "xL4wZ8vB"
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_BODY = "MIIEow" + "Ab3Xy9" * 10
PEM_BLOCK = f"{PEM_HEADER}\n{PEM_BODY}\n-----END " + "RSA PRIVATE KEY-----\n"
DB_URL = "postgres://appuser:" + DB_PASSWORD + "@db.internal.corp:5432/app"
RAW_VALUES = (AWS_KEY, GH_TOKEN, STRIPE_KEY, SLACK_TOKEN, DB_PASSWORD, GENERIC_VALUE, PEM_BODY)


def _text(check) -> str:
    return "\n".join([check.summary, *(h.message for h in check.hits)])


def _paths(check) -> list[str]:
    return [h.path for h in check.hits]


# ------------------------------------------------------------------------ registry


def test_registered_rules_are_well_formed():
    rules = [r for r in REGISTRY if r.id.startswith("SEC")]
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)) >= 13
    for r in rules:
        assert r.dimension is Dimension.security
        assert r.description.strip() and r.remediation.strip() and r.title.strip()


# -------------------------------------------------------------------------- SEC001


def test_sec001_flags_provider_credentials_with_location(make_repo):
    repo = make_repo(
        {
            "src/config.py": f'import os\nAWS_ID = "{AWS_KEY}"\nGH = "{GH_TOKEN}"\n',
            "deploy/settings.yml": f"stripe: {STRIPE_KEY}\nslack: {SLACK_TOKEN}\n",
            "src/key.py": f'KEY = """{PEM_BLOCK}"""\n',
            "src/db.py": f'URL = "{DB_URL}"\n',
        }
    )
    check = sec.no_provider_credentials(repo)
    assert check.outcome is Outcome.failed
    located = {(h.path, h.line) for h in check.hits}
    assert {
        ("src/config.py", 2),
        ("src/config.py", 3),
        ("deploy/settings.yml", 1),
        ("deploy/settings.yml", 2),
        ("src/key.py", 1),
        ("src/db.py", 1),
    } == located
    assert "AWS access key ID" in _text(check) and "GitHub token" in _text(check)
    by_path = {h.path: h for h in check.hits}
    assert by_path["src/db.py"].severity is Severity.high
    assert by_path["src/db.py"].confidence is Confidence.medium


def test_sec001_ignores_placeholders_lockfiles_and_lookalikes(make_repo):
    docs_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    repo = make_repo(
        {
            "README.md": f"export AWS_ACCESS_KEY_ID={docs_key}\n",
            "app.py": (
                'commit = "' + "9fceb02d0ae598e95dc970b74767f19372d61af8" + '"\n'
                'request_id = "550e8400-e29b-41d4-a716-446655440000"\n'
                'password = os.environ["DB_PASSWORD"]\n'
                'HEADER = "' + PEM_HEADER + '"\n'
                'url = "postgres://user:${DB_PASSWORD}@db:5432/app"\n'
                'tmpl = f"https://{user}:{password}@example.org/x"\n'
            ),
            "package-lock.json": f'{{"integrity": "sha512-{GH_TOKEN}", "k": "{AWS_KEY}"}}\n',
            "dist/app.min.js": f'var k="{GH_TOKEN}";\n',
            "certs/server.pem": "-----BEGIN CERTIFICATE-----\n" + PEM_BODY + "\n",
        }
    )
    assert sec.no_provider_credentials(repo).outcome is Outcome.passed
    assert sec.no_generic_secrets(repo).outcome is Outcome.passed


def test_sec001_lowers_confidence_in_tests_and_for_default_local_urls(make_repo):
    repo = make_repo(
        {
            "tests/test_client.py": f'TOKEN = "{GH_TOKEN}"\n',
            "docker-compose.yml": "DATABASE_URL: postgres://postgres:"
            + "postgres@localhost:5432/db\n",
        }
    )
    hits = {h.path: h for h in sec.no_provider_credentials(repo).hits}
    assert hits["tests/test_client.py"].confidence is Confidence.medium
    assert hits["docker-compose.yml"].confidence is Confidence.low
    assert hits["docker-compose.yml"].severity is Severity.low


# -------------------------------------------------------------------------- SEC002


def test_sec002_flags_generic_assignment_once(make_repo):
    repo = make_repo(
        {
            "settings.py": f'DB_PASSWORD = "{GENERIC_VALUE}"\nGH = "{GH_TOKEN}"\n',
            "config.json": f'{{"api_key": "{GENERIC_VALUE}"}}\n',
        }
    )
    check = sec.no_generic_secrets(repo)
    assert check.outcome is Outcome.failed
    assert {(h.path, h.line) for h in check.hits} == {("settings.py", 1), ("config.json", 1)}
    assert all(h.confidence in (Confidence.medium, Confidence.low) for h in check.hits)
    assert ("settings.py", 2) in {(h.path, h.line) for h in sec.no_provider_credentials(repo).hits}


def test_sec002_ignores_references_names_and_docs(make_repo):
    repo = make_repo(
        {
            "app.py": (
                'password = os.environ["DB_PASSWORD"]\n'
                'api_key = "your_api_key_here"\n'
                'secret = "${APP_SECRET}"\n'
                'grant = {"token": "client_credentials"}\n'
                'private_key = "config/keys/server.pem"\n'
                'password = "changeme123"\n'
                'if password == "whatever": pass\n'
            ),
            "docs/guide.md": f'Set `password = "{GENERIC_VALUE}"` in the config.\n',
        }
    )
    assert sec.no_generic_secrets(repo).outcome is Outcome.passed


# -------------------------------------------------------------------------- SEC003


def test_sec003_flags_private_keys_and_keystores(make_repo):
    repo = make_repo(
        {
            "deploy/id_rsa": PEM_BLOCK,
            "certs/server.key": PEM_BLOCK,
            "android/release.jks": b"\xfe\xed\xfe\xed\x00\x01",
        }
    )
    check = sec.no_private_key_files(repo)
    assert check.outcome is Outcome.failed
    assert _paths(check) == ["android/release.jks", "certs/server.key", "deploy/id_rsa"]
    # the key-file rule owns these files: SEC001 must not report them a second time
    assert sec.no_provider_credentials(repo).outcome is Outcome.passed


def test_sec003_ignores_public_material(make_repo):
    repo = make_repo(
        {
            "certs/ca.pem": "-----BEGIN CERTIFICATE-----\n" + PEM_BODY + "\n",
            "deploy/id_rsa.pub": "ssh-rsa AAAAB3Nza comment\n",
            "i18n/en.key": "greeting=hello\n",
        }
    )
    assert sec.no_private_key_files(repo).outcome is Outcome.passed


# -------------------------------------------------------------------------- SEC004


def test_sec004_flags_env_file_without_values_in_output(make_repo):
    repo = make_repo(
        {".env": f"# local\nDB_PASSWORD={DB_PASSWORD}\nexport DEBUG=1\nEMPTY=\n"},
    )
    check = sec.no_env_files(repo)
    assert check.outcome is Outcome.failed and _paths(check) == [".env"]
    assert "2 assigned value(s)" in check.hits[0].message
    assert DB_PASSWORD not in _text(check)


def test_sec004_ignores_templates_and_empty_files(make_repo):
    repo = make_repo(
        {
            ".env.example": "DB_PASSWORD=changeme\nAPI_KEY=your_key_here\n",
            ".env.local.sample": f"DB_PASSWORD={DB_PASSWORD}\n",
            "svc/.env": "# nothing yet\nTOKEN=\nHOST=${HOST}\n",
        }
    )
    assert sec.no_env_files(repo).outcome is Outcome.passed


# -------------------------------------------------------------------------- SEC005


def test_sec005_finds_secret_removed_from_head(make_repo):
    repo = make_repo(
        {"config.py": f'KEY = "{AWS_KEY}"\n', "keep.py": "x = 1\n"},
        commits=[
            {"message": "fix: drop key", "files": {"config.py": "KEY = None\n"}},
            {"message": "chore: touch", "files": {"keep.py": "x = 2\n"}},
        ],
    )
    assert sec.no_provider_credentials(repo).outcome is Outcome.passed
    check = sec.no_secrets_in_history(repo)
    assert check.outcome is Outcome.failed and len(check.hits) == 1
    hit = check.hits[0]
    introduced = repo.commits[-1].sha[:8]
    assert hit.path == "config.py" and introduced in hit.message
    assert "AWS access key ID" in hit.message and AWS_KEY not in _text(check)


def test_sec005_finds_deleted_private_key_file(make_repo):
    repo = make_repo(
        {"id_rsa": PEM_BLOCK, "a.txt": "a\n"},
        commits=[{"message": "chore: remove key", "files": {"id_rsa": None}}],
    )
    check = sec.no_secrets_in_history(repo)
    assert check.outcome is Outcome.failed and _paths(check) == ["id_rsa"]


def test_sec005_does_not_double_report_secret_still_in_head(make_repo):
    repo = make_repo(
        {"config.py": f'KEY = "{GH_TOKEN}"\n'},
        commits=[{"message": "docs: readme", "files": {"README.md": "# hi\n"}}],
    )
    assert sec.no_provider_credentials(repo).outcome is Outcome.failed
    assert sec.no_secrets_in_history(repo).outcome is Outcome.passed


def test_sec005_not_applicable_without_git(make_repo):
    repo = make_repo({"a.py": "x = 1\n"}, git=False)
    assert sec.no_secrets_in_history(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------- no raw values, ever


def test_no_secret_rule_ever_emits_a_raw_value(make_repo):
    repo = make_repo(
        {
            "old.py": f'A = "{AWS_KEY}"\nS = "{SLACK_TOKEN}"\n',
            "src/config.py": f'GH = "{GH_TOKEN}"\nDB_PASSWORD = "{GENERIC_VALUE}"\n',
            "src/pay.py": f'STRIPE = "{STRIPE_KEY}"\nURL = "{DB_URL}"\n',
            "src/key.py": f'KEY = """{PEM_BLOCK}"""\n',
            "id_ed25519": PEM_BLOCK,
            ".env": f"DB_PASSWORD={DB_PASSWORD}\nGITHUB_TOKEN={GH_TOKEN}\n",
        },
        commits=[{"message": "fix: remove", "files": {"old.py": None}}],
    )
    secret_rules = (
        sec.no_provider_credentials,
        sec.no_generic_secrets,
        sec.no_private_key_files,
        sec.no_env_files,
        sec.no_secrets_in_history,
        sec.gitignore_covers_env,
    )
    checks = [fn(repo) for fn in secret_rules]
    assert [c.outcome for c in checks[:5]] == [Outcome.failed] * 5
    for check in checks:
        text = _text(check) + "".join(h.path for h in check.hits)
        for raw in RAW_VALUES:
            leaked = raw in text or raw[6:] in text
            assert not leaked, "a raw secret value reached rule output"


# -------------------------------------------------------------------------- SEC006


def test_sec006_fails_when_gitignore_misses_env(make_repo):
    repo = make_repo({".gitignore": "node_modules/\n", ".env.example": "A=changeme\n"})
    check = sec.gitignore_covers_env(repo)
    assert check.outcome is Outcome.failed and _paths(check) == [".gitignore"]


@pytest.mark.parametrize("pattern", [".env", ".env*", "/.env", "*.env\n!.env.example"])
def test_sec006_passes_when_covered(make_repo, pattern):
    repo = make_repo({".gitignore": pattern + "\n", "requirements.txt": "python-dotenv==1.0.1\n"})
    assert sec.gitignore_covers_env(repo).outcome is Outcome.passed


def test_sec006_not_applicable_without_gitignore_or_env_usage(make_repo):
    assert sec.gitignore_covers_env(make_repo({"a.py": "x=1\n"})).outcome is Outcome.not_applicable
    repo = make_repo({".gitignore": "*.pyc\n", "a.py": "x=1\n"})
    assert sec.gitignore_covers_env(repo).outcome is Outcome.not_applicable
    negated = make_repo({".gitignore": ".env\n!.env\n", ".env.example": "A=changeme\n"})
    assert sec.gitignore_covers_env(negated).outcome is Outcome.failed


# -------------------------------------------------------------------------- SEC007


def test_sec007_manifest_present_missing_and_not_applicable(make_repo):
    ok = make_repo({"pyproject.toml": "[project]\nname='x'\n", "src/a.py": "x=1\n"})
    assert sec.dependency_manifest_present(ok).outcome is Outcome.passed
    missing = make_repo({"src/a.py": "import requests\n", "src/b.py": "x=1\n"})
    check = sec.dependency_manifest_present(missing)
    assert check.outcome is Outcome.failed and "2 source file(s)" in check.summary
    docs_only = make_repo({"README.md": "# notes\n", "vendor/lib/setup.py": "x\n"})
    assert sec.dependency_manifest_present(docs_only).outcome is Outcome.not_applicable


# -------------------------------------------------------------------------- SEC008


def test_sec008_flags_manifests_without_lockfile(make_repo):
    repo = make_repo(
        {
            "package.json": '{"dependencies": {"express": "^4.19.0"}}\n',
            "api/requirements.txt": "flask>=3.0\nrequests==2.32.3\n",
            "tool/go.mod": "module x\n\nrequire github.com/a/b v1.2.3\n",
        }
    )
    check = sec.lockfiles_present(repo)
    assert check.outcome is Outcome.failed
    assert _paths(check) == ["api/requirements.txt", "package.json", "tool/go.mod"]


def test_sec008_accepts_locks_pins_workspace_roots_and_skips_unlocked_ecosystems(make_repo):
    repo = make_repo(
        {
            "package.json": '{"devDependencies": {"turbo": "^2.0.0"}}\n',
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
            "packages/web/package.json": '{"dependencies": {"react": "^18.3.1"}}\n',
            "api/requirements.txt": "flask==3.0.3\nrequests==2.32.3  # pinned\n",
            "lib/go.mod": "module x\n\ngo 1.22\n",
            "svc/pyproject.toml": "[tool.poetry]\nname = 'svc'\n",
            "svc/poetry.lock": "# lock\n",
        }
    )
    assert sec.lockfiles_present(repo).outcome is Outcome.passed
    plain = make_repo({"pyproject.toml": "[project]\nname='x'\ndependencies=['rich>=13']\n"})
    assert sec.lockfiles_present(plain).outcome is Outcome.not_applicable


def test_sec008_rust_library_gets_low_confidence(make_repo):
    repo = make_repo({"Cargo.toml": "[package]\nname='x'\n\n[dependencies]\nserde = '1'\n"})
    check = sec.lockfiles_present(repo)
    assert check.outcome is Outcome.failed and check.hits[0].confidence is Confidence.low


# -------------------------------------------------------------------------- SEC009


def test_sec009_flags_unpinned_lines(make_repo):
    repo = make_repo(
        {
            "requirements.txt": "# deps\nrequests\nflask>=3.0\n-r base.txt\nuvicorn[standard]\n",
            "package.json": '{\n  "dependencies": {\n    "left-pad": "*",\n    "b": "^1"\n  }\n}\n',
        }
    )
    check = sec.no_unpinned_dependencies(repo)
    assert check.outcome is Outcome.failed
    assert [(h.path, h.line) for h in check.hits] == [
        ("package.json", 3),
        ("requirements.txt", 2),
        ("requirements.txt", 5),
    ]


def test_sec009_accepts_ranges_urls_and_options(make_repo):
    repo = make_repo(
        {
            "requirements.txt": (
                "requests>=2.31,<3\nflask==3.0.3 ; python_version >= '3.9'\n"
                "-e .\n--extra-index-url https://pypi.example.org/simple\n"
                "git+https://github.com/a/b.git@v1.0\npkg @ https://host.example/pkg.whl\n"
            ),
            "package.json": '{"dependencies": {"react": "^18.3.1", "x": "~1.2.0"}}\n',
        }
    )
    assert sec.no_unpinned_dependencies(repo).outcome is Outcome.passed
    assert (
        sec.no_unpinned_dependencies(make_repo({"a.py": "x\n"})).outcome is Outcome.not_applicable
    )


# ----------------------------------------------------------------- SEC011 - SEC014


def test_sec011_dependency_automation(make_repo):
    base = {"package.json": '{"dependencies": {"a": "1.0.0"}}\n'}
    assert sec.dependency_updates_automated(make_repo(base)).outcome is Outcome.failed
    bot = make_repo({**base, ".github/dependabot.yml": "version: 2\n"})
    assert sec.dependency_updates_automated(bot).outcome is Outcome.passed
    inline = make_repo({"package.json": '{\n  "renovate": {"extends": ["config:base"]}\n}\n'})
    assert sec.dependency_updates_automated(inline).outcome is Outcome.passed
    none = make_repo({"README.md": "# x\n"})
    assert sec.dependency_updates_automated(none).outcome is Outcome.not_applicable


def test_sec012_security_policy(make_repo):
    assert sec.security_policy_present(make_repo({"README.md": "x\n"})).outcome is Outcome.failed
    for path in ("SECURITY.md", "docs/SECURITY.md", ".github/SECURITY.md"):
        repo = make_repo({path: "# Reporting\n"})
        assert sec.security_policy_present(repo).outcome is Outcome.passed
    elsewhere = make_repo({"src/security.md": "notes\n", "SECURITY.md": ""})
    assert sec.security_policy_present(elsewhere).outcome is Outcome.failed


def test_sec013_security_scanning(make_repo):
    wf = ".github/workflows/ci.yml"
    scanned = make_repo(
        {wf: "jobs:\n  s:\n    steps:\n      - uses: github/codeql-action/init@v3\n"}
    )
    assert sec.security_scanning_configured(scanned).outcome is Outcome.passed
    hook = make_repo({".pre-commit-config.yaml": "repos:\n  - repo: https://x/gitleaks/gitleaks\n"})
    assert sec.security_scanning_configured(hook).outcome is Outcome.passed
    plain = make_repo(
        {wf: "jobs:\n  t:\n    steps:\n      - run: pytest\n      # TODO add bandit\n"}
    )
    check = sec.security_scanning_configured(plain)
    assert check.outcome is Outcome.failed and _paths(check) == [wf]
    assert sec.security_scanning_configured(make_repo({"a.py": "x\n"})).outcome is Outcome.failed


def test_sec014_large_binaries(make_repo):
    blob = b"\x00\x01" * 2_600_000
    repo = make_repo(
        {"bin/tool.exe": blob, "assets/hero.png": blob, "small.bin": b"\x00"}, git=False
    )
    check = sec.no_large_binaries(repo)
    assert check.outcome is Outcome.failed and _paths(check) == ["bin/tool.exe"]
    assert "5.2 MB" in check.hits[0].message
    text = make_repo({"data.csv": "a,b\n" * 10, "x.bin": b"\x00" * 100}, git=False)
    assert sec.no_large_binaries(text).outcome is Outcome.passed
