import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def test_parse_github_target_variants():
    from core.github_recon import is_github_target, parse_github_target

    assert parse_github_target("https://github.com/acme") == {"type": "owner", "owner": "acme"}
    assert parse_github_target("github.com/acme/app") == {"type": "repo", "owner": "acme", "repo": "app"}
    assert parse_github_target("git@github.com:acme/app.git") == {"type": "repo", "owner": "acme", "repo": "app"}
    assert is_github_target("https://github.com/acme/app") is True
    assert is_github_target("https://example.com") is False


def test_scan_repo_collects_urls_and_contributors(monkeypatch):
    from core.github_recon import GitHubRecon

    recon = GitHubRecon(token="", max_repos=10)

    def fake_get_json(path, params=None):
        if path == "/users/acme":
            return {
                "login": "acme",
                "type": "Organization",
                "html_url": "https://github.com/acme",
                "blog": "https://acme.test",
                "public_repos": 9,
            }
        if path == "/repos/acme/app":
            return {
                "name": "app",
                "full_name": "acme/app",
                "html_url": "https://github.com/acme/app",
                "homepage": "https://docs.acme.test",
                "language": "Python",
                "topics": ["security", "scanner"],
                "private": False,
                "archived": False,
                "has_pages": True,
                "owner": {"login": "acme"},
            }
        if path == "/repos/acme/app/pages":
            return {"html_url": "https://acme.github.io/app/", "custom_domain": "pages.acme.test"}
        if path == "/repos/acme/app/contributors":
            return [{"login": "alice"}, {"login": "bob"}]
        raise AssertionError(f"Unexpected API path: {path}")

    monkeypatch.setattr(recon, "_get_json", fake_get_json)
    result = recon.scan_target("https://github.com/acme/app")

    assert result["contributors"] == ["alice", "bob"]
    assert "https://docs.acme.test" in result["urls"]
    assert "https://pages.acme.test" in result["urls"]
    assert "docs.acme.test" in result["hosts"]
    assert result["repos"][0]["full_name"] == "acme/app"
