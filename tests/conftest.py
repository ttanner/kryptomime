# -*- coding: utf-8 -*-

# This file is part of kryptomime, a Python module for email kryptography.
# Copyright © 2013,2014 Thomas Tanner <tanner@gmx.net>
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
