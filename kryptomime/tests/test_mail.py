#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Mail unit tests
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

from unittest import TestCase, main

from ..mail import protect_mail

def test_protect():
    #> From foo
    msg='''Content-Type: multipart/mixed;
 boundary="------------030608090900090202040409"

This is a multi-part message in MIME format.
--------------030608090900090202040409
Content-Type: text/plain; charset=ISO-8859-15
Content-Transfer-Encoding: quoted-printable

body
line2

--------------030608090900090202040409
Content-Type: text/plain; charset=UTF-8;
 name="attach.txt"
Content-Transfer-Encoding: quoted-printable
Content-Disposition: attachment;
 filename="attach.txt"

attachment
line2
--------------030608090900090202040409--
'''
    prot = protect_mail(msg,ending='\n',sevenbit=True)
    assert prot.as_string() == msg

if __name__ == '__main__':
    main()
