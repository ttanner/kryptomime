# -*- coding: utf-8 -*-
#
# EMail kryptography support
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

def make_list(x):
    from six import string_types
    if isinstance(x, string_types): return [x]
    return x

class KryptoMIME(object):
    def __init__(self, default_key=None):
        self.default_key = default_key

    def analyze(self,mail):
        """Checks whether the email is encrypted or signed.

        :param mail: A string or email
        :returns: Whether the email is encrypted and whether it is signed (if it is not encrypted).
        :rtype: (bool,bool/None)
        """
        raise NotImplementedError

    def strip_signature(self,mail):
        """Returns the raw email without signature. Does not check for valid signature.

        :param mail: A string or email
        :returns: An email without signature and whether the input was signed
        :rtype: (Message,bool)
        """
        raise NotImplementedError

    def verify(self, mail, **kwargs):
        """Verifies the validity of the signature of an email.

        :type mail: string or Message object
        :param mail: A string or email
        :returns: whether the input was signed by the sender and detailed results
        :rtype: (bool,dict)
        """
        raise NotImplementedError

    def decrypt(self, mail, **kwargs):
        """Decrypts and verifies an email.

        :param mail: A string or email
        :type mail: string or Message object
        :returns: An email without signature (None if the decryption failed),
             whether the input was signed by the sender and detailed results
        :rtype: (Message,bool,dict)
        """
        raise NotImplementedError

    def sign(self, mail, verify=True, **kwargs):
        """Signs an email with the sender's (From) signature.

        :param mail: A string or email
        :type mail: string or Message object
        :param verify: Whether to verify the signed mail immediately
        :type verify: bool
        :returns: The signed email (None if it fails) and the sign details.
        :rtype: (Message,dict)
        """
        raise NotImplementedError

    def encrypt(self, mail, sign=True, verify=False, **kwargs):
        """Encrypts an email for the recipients in To/CC.

        :param mail: A string or email
        :type mail: string or Message object
        :param sign: Whether to sign the mail with the sender's (From) signature
        :type sign: bool
        :param verify: Whether to verify the encrypted mail immediately
        :type verify: bool
        :returns: The encrypted email (None if it fails) and the encryption details.
        :rtype: (Message,dict)
        """
        raise NotImplementedError
