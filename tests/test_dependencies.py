from guardian.dependencies import extract_dependencies


def test_parse_requirements():
    deps = extract_dependencies("requirements.txt", "requests==2.32.3\n# comment\n")
    assert deps == [("requests", "2.32.3")]


def test_parse_package_json():
    deps = extract_dependencies("package.json", '{"dependencies":{"react":"18.3.1","lodash":"^4.17.21"}}')
    assert ("react", "18.3.1") in deps
    assert ("lodash", "4.17.21") in deps
