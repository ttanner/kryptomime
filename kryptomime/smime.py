# -*- coding: utf-8 -*-
#
# S/MIME support
#
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

from .mail import KryptoMIME

class SMIME(KryptoMIME):
    def __init__(self, defaultkey=None):
        self.defaultkey = defaultkey

    def strip_signature(self,mail):
        raise NotImplementedError

    def sign(self, mail, verify=True, **kwargs):
         raise NotImplementedError

    def verify(self, mail, **kwargs):
         raise NotImplementedError

    def encrypt(self, mail, sign=True, verify=False, **kwargs):
         raise NotImplementedError

    def decrypt(self, mail, **kwargs):
         raise NotImplementedError
