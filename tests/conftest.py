sender='Foo <foo@localhost>'
passphrase='mysecret'
receiver='Bar <bar@localhost>'

def pytest_addoption(parser):
    parser.addoption("--generate", action="store_true", help="generate PGP keys")
    parser.addoption("--gpglog", action="store_true", help="verbose gnupg output")

def compare_mail(a,b):
    if type(a)==str: return a==b
    assert a.is_multipart() == b.is_multipart()
    #from kryptomime.mail import ProtectedMessage
    #assert isinstance(a,ProtectedMessage)==isinstance(b,ProtectedMessage)
    # todo headers
    if a.is_multipart():
        for i in range(len(a.get_payload())):
            ap = a.get_payload(i)
            bp = b.get_payload(i)
            assert ap.as_string() == bp.as_string()
    else:
        assert a.get_payload() == b.get_payload()
