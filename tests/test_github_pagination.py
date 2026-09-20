from guardian.github import GitHubClient


def test_commit_pagination():
    client = GitHubClient()
    calls = []

    def fake_get(path, **params):
        calls.append(params)
        page = params["page"]
        if page == 1:
            return [{"sha": str(i)} for i in range(100)]
        return [{"sha": "100"}, {"sha": "101"}]

    client._get = fake_get
    commits = client.commits("owner", "repo", limit=102)

    assert len(commits) == 102
    assert calls[0]["per_page"] == 100
    assert calls[1]["per_page"] == 2
    assert calls[1]["page"] == 2
