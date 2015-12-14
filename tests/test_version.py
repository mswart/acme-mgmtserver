from acmems import version


def test_version_string():
    assert type(version.STRING) is str


def test_minimum_version():
    assert (version.MAJOR, version.MINOR) >= (0, 1)
