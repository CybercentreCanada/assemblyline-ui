from assemblyline_ui.helper.submission import refang_url


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
