
def pytest_addoption(parser):
    parser.addoption("--generate", action="store_true", help="generate PGP keys")
    parser.addoption("--gpglog", action="store_true", help="verbose gnupg output")

