kryptomime
==========

A package for encrypted MIME messages. It currently supports PGP/MIME
via GPG. S/MIME support is planned for future releases.

Disclaimer
~~~~~~~~~~

Proper kryptography requires security audits of the complete system.
Even though the author is not aware of any bugs in this software, it
comes with ABSOLUTELY NO WARRANTY. USE THIS SOFTWARE AT YOUR OWN RISK.

Installation
~~~~~~~~~~~~

From `PyPI <https://pypi.python.org>`__
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    [sudo] pip install kryptomime

From this git repository
^^^^^^^^^^^^^^^^^^^^^^^^

To install this package from this git repository, do::

    git clone https://github.com/ttanner/kryptomime.git
    cd kryptomime
    python setup.py install
    python setup.py test

Optionally to build the documentation after installation, do::

    cd docs
    make html

This is a simple example of how to use kryptomime::

    >>> from kryptomime import create_mail, GPGMIME
    >>> import gnupg
    >>> gpg = gnupg.GPG(home='gpghome')
    >>> krypto = GPGMIME(gpg,default_key=('foo@bar.com','passphrase'))
    >>> msg = create_mail('foo@bar.com','bar@fnord.net','subject','body\nmessage')
    >>> sgnmsg,results = krypto.sign(msg)
    >>> verified, results = krypto.verify(sgnmsg)
    >>> rawmsg,signed = krypto.strip_signature(sgnmsg)
    >>> encmsg,results = krypto.encrypt(msg,sign=True)
    >>> verified, results = krypto.verify(encmsg)
    >>> decmsg, verified, results = krypto.decrypt(encmsg)

Bug Reports & Feature Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please use the
`bugtracker <https://github.com/ttanner/kryptomime/issues>`__ on Github.
