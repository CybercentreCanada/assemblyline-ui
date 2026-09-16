import pytest

import assemblyline_ui.helper.submission as submission_helper
from assemblyline_ui.helper.submission import fetch_file, refang_url


# noinspection PyUnusedLocal
def test_refang_url():

    # Testing the
    assert refang_url('http://examples[.]com') == 'http://examples.com'
    assert refang_url('http://examples(.)com') == 'http://examples.com'
    assert refang_url('http://examples{.}com') == 'http://examples.com'
    assert refang_url('http://examples[.)com') == 'http://examples.com'
    assert refang_url('http://examples(.}com') == 'http://examples.com'
    assert refang_url('http://examples{.]com') == 'http://examples.com'

    assert refang_url('http://examples[dot]com') == 'http://examples.com'
    assert refang_url('http://examples(dot)com') == 'http://examples.com'
    assert refang_url('http://examples{dot}com') == 'http://examples.com'
    assert refang_url('http://examples[dot)com') == 'http://examples.com'
    assert refang_url('http://examples(dot}com') == 'http://examples.com'
    assert refang_url('http://examples{dot]com') == 'http://examples.com'

    assert refang_url('http://examples\\.com') == 'http://examples.com'

    assert refang_url('http://examples.com[/]path') == 'http://examples.com/path'
    assert refang_url('http://examples.com[/)path') == 'http://examples.com/path'
    assert refang_url('http://examples.com[/}path') == 'http://examples.com/path'

    assert refang_url('http[:]//examples.com') == 'http://examples.com'
    assert refang_url('http[:)//examples.com') == 'http://examples.com'
    assert refang_url('http[:}//examples.com') == 'http://examples.com'
    assert refang_url('http[://]examples.com') == 'http://examples.com'
    assert refang_url('http[://)examples.com') == 'http://examples.com'
    assert refang_url('http[://}examples.com') == 'http://examples.com'

    assert refang_url('hxxp://examples.com') == 'http://examples.com'
    assert refang_url('hxXp://examples.com') == 'http://examples.com'
    assert refang_url('hXXp://examples.com') == 'http://examples.com'

    assert refang_url('hxXps[:]//test\\.example[.)com{.]uk[dot)test[/]path') == 'https://test.example.com.uk.test/path'


@pytest.mark.parametrize("method, value", [
    # Custom hash types (declared by file_sources) can have URI-like values
    ("internal", "SCHEME://internal/path/sample"),
    # ssdeep hashes contain ":" and can contain "/" and "+"
    ("ssdeep", "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGH/sNhxLsr2C3"),
])
def test_fetch_file_lookup_with_reserved_characters(datastore_connection, monkeypatch, method, value):
    # The datastore lookup in fetch_file() must not raise a parse error when the input contains
    # Lucene reserved characters; the expected outcome here is a clean "not found" since no
    # external sources are given
    monkeypatch.setattr(submission_helper, "STORAGE", datastore_connection)
    monkeypatch.setattr(submission_helper, "FETCH_METHODS", submission_helper.FETCH_METHODS | {"internal"})

    user = {"uname": "admin", "roles": [], "classification": ""}

    with pytest.raises(FileNotFoundError):
        fetch_file(method, value, user, s_params={}, metadata={}, out_file=None,
                   default_external_sources=[], name=value)
