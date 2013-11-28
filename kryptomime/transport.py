# -*- coding: utf-8 -*-
#
# TLS IMAP and SMTP support
#
# This file is part of kryptomime, a Python module for email kryptography.
# Copyright © 2013 Thomas Tanner <tanner@gmx.net>
# 
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included LICENSE file for details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# For more details see the file COPYING.

"""
.. module:: transport
   :synopsis: Secure IMAP4 and SMTP connections.

.. moduleauthor:: Thomas Tanner <tanner@gmx.net>

Secure E-Mail transport does not only involve encryption of the E-Mail contents
but also of the metadata (sender, receiver), and prevention of man in the middle attacks,
which could, for example, lead to deliberate loss of E-Mails.
Ideally, all connections from sender MUA -> sender MTA -> receiver MTA/IMAP4 Server -> receiver MUA
should be properly encrypted.

This module provides extensions to the Python standard IMAP4 and SMTP classes to support
- full access to SSL parameters
- X.509 certificate based login to the servers
- login only to servers with a valid certificate
"""

import imaplib, smtplib

class IMAP4_TLS(imaplib.IMAP4_SSL):
    """IMAP4 client class over SSL/TLS connection

    Instantiate with: IMAP4_TLS([host[, port[, keyfile[, certfile[, ca_certs]]]],**sslargs])

    :param host: host's name (default: localhost);
    :param port: port number (default: standard IMAP4 SSL port).
    :param keyfile: PEM formatted file that contains your private key (default: None);
    :param certfile: PEM formatted certificate chain file (default: None);
    :param ca_certs: PEM formatted file for permitted certificates (default: None), if specified, and the default for cert_reqs is CERT_REQUIRED;
    :param sslargs: a dict with further SSL arguments, see ssl module (default: {});

    The default for ssl_version is PROTOCOL_TLSv1.
    For more documentation see the docstring of the parent class IMAP4.
    """

    def __init__(self, host = '', port = imaplib.IMAP4_SSL_PORT, keyfile = None, certfile = None, **sslargs):
        """
        :param foo: A string to be converted
        :returns: A bar formatted string
        """

        if not sslargs.get('ssl_version'):
            sslargs['cert_reqs'] = ssl.PROTOCOL_TLSv1
        if not sslargs.get('cert_reqs'):
            sslargs['cert_reqs'] = ssl.CERT_REQUIRED if sslargs.get('ca_certs') else ssl.CERT_NONE
        self.sslargs = sslargs
        imaplib.IMAP4_SSL.__init__(self, host, port, keyfile, certfile)

    def open(self, host = '', port = imaplib.IMAP4_SSL_PORT):
        import socket, ssl
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port))
        self.sslobj = ssl.wrap_socket(self.sock, self.keyfile, self.certfile, **self.sslargs)
        self.file = self.sslobj.makefile('rb')

class SMTP_TLS(smtplib.SMTP_SSL):
    """This is a subclass derived from SMTP that connects over an SSL encrypted
    socket (to use this class you need a socket module that was compiled with SSL
    support). If host is not specified, '' (the local host) is used. If port is
    omitted, the standard SMTP-over-SSL port (465) is used. keyfile and certfile
    are also optional - they can contain a PEM formatted private key and
    certificate chain file for the SSL connection.

    In addition the starttls command accepts extra SSL parameters.
    """

    def starttls(self, **sslargs):
        """Puts the connection to the SMTP server into TLS mode.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.

        If the server supports TLS, this will encrypt the rest of the SMTP
        session. If you provide the keyfile and certfile parameters,
        the identity of the SMTP server and client can be checked. This,
        however, depends on whether the socket module really checks the
        certificates.

        :param sslargs: a dict with further SSL arguments, see ssl module (default: {});
        :param ca_certs: PEM formatted file for permitted certificates (default: None), if specified, and the default for cert_reqs is CERT_REQUIRED;

        This method may raise the following exceptions:

         SMTPHeloError            The server didn't reply properly to
                                  the helo greeting.
        """
        import ssl
        self.ehlo_or_helo_if_needed()
        if not self.has_extn("starttls"):
            raise smtplib.SMTPException("STARTTLS extension not supported by server.")
        (resp, reply) = self.docmd("STARTTLS")
        if resp == 220:
            if not sslargs.get('ssl_version'):
                sslargs['cert_reqs'] = ssl.PROTOCOL_TLSv1
            if not sslargs.get('cert_reqs'):
                sslargs['cert_reqs'] = ssl.CERT_REQUIRED if sslargs.get('ca_certs') else ssl.CERT_NONE
            self.sock = ssl.wrap_socket(self.sock, keyfile, certfile, **sslargs)
            self.file = smtplib.SSLFakeFile(self.sock)
            # RFC 3207:
            # The client MUST discard any knowledge obtained from
            # the server, such as the list of SMTP service extensions,
            # which was not obtained from the TLS negotiation itself.
            self.helo_resp = None
            self.ehlo_resp = None
            self.esmtp_features = {}
            self.does_esmtp = 0
        return (resp, reply)
