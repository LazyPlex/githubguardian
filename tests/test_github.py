import pytest

from guardian.github import parse_repository


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("octocat/Hello-World", ("octocat", "Hello-World")),
        ("https://github.com/octocat/Hello-World", ("octocat", "Hello-World")),
        ("https://github.com/octocat/Hello-World.git", ("octocat", "Hello-World")),
    ],
)
def test_parse_repository(value, expected):
    assert parse_repository(value) == expected


def test_parse_repository_rejects_invalid_input():
    with pytest.raises(ValueError):
        parse_repository("not-a-repository")
