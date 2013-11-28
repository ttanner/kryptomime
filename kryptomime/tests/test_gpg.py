#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# GPG unit tests
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

from kryptomime import create_mail, GPGMIME, protect_mail
import gnupg, email.mime.text

sender='foo@localhost'
receiver='bar@localhost'
home='test'
attachment = email.mime.text.MIMEText('some\nattachment')
msg = create_mail(sender,receiver,'subject','body\nmessage')
msga = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
prot = protect_mail(msg,ending='\r\n')

def mktmp():
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    name = tmp.name
    tmp.close()
    return name

def compare_mail(a,b):
    assert a.is_multipart() == b.is_multipart()
    if a.is_multipart():
        for i in range(len(a.get_payload())):
            ap = a.get_payload(i)
            bp = b.get_payload(i)
            assert ap.as_string() == bp.as_string()
    else:
        assert a.get_payload() == b.get_payload()

def setUpModule():
    global gpg1, gpg2, pubkey1, pubkey2, keyrings, secrings
    keyring1=mktmp()
    keyring2=mktmp()
    secring1=mktmp()
    secring2=mktmp()
    keyrings = [keyring1,keyring2]
    secrings = [secring1,secring2]

    verbose=False
    if verbose: gnupg._logger.create_logger(10)

    gpg1 = gnupg.GPG(keyring=keyring1,secring=secring1,verbose=verbose)
    gpg2 = gnupg.GPG(keyring=keyring2,secring=secring2,verbose=verbose)

    key1 = gpg1.gen_key(gpg1.gen_key_input(name_email=sender,key_length=1024)).fingerprint
    key2 = gpg2.gen_key(gpg2.gen_key_input(name_email=receiver,key_length=1024)).fingerprint

    pubkey1= gpg1.export_keys(key1)
    pubkey2= gpg2.export_keys(key2)

def tearDownModule():
    import os
    keyring1,keyring2 = keyrings
    os.unlink(keyring1)
    os.unlink(keyring2)
    secring1,secring2 = secrings
    os.unlink(secring1)
    os.unlink(secring2)

def test_unknown_sign():
    # bad sign
    id2 = GPGMIME(gpg2,default_key=receiver)
    assert id2.sign(msg)[0] is None # sender key missing - cannot sign
    
def test_unknown_encrypt():
    # bad encrypt
    id1 = GPGMIME(gpg1,default_key=sender)
    assert id1.encrypt(msg)[0] is None # receiver key missing - cannot encrypt

class UnilateralTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyring=mktmp()
        cls.gpg = gnupg.GPG(keyring=cls.keyring,secring=secrings[0])
        cls.gpg.import_keys(pubkey1)
        cls.gpg.import_keys(pubkey2) # sender knows receiver pubkey
        cls.id1 = GPGMIME(cls.gpg,default_key=sender)
        cls.id2 = GPGMIME(gpg2,default_key=receiver)
        cls.sgn = cls.id1.sign(msg)[0]
        cls.enc = cls.id1.encrypt(msg,sign=False)[0]

    @classmethod
    def tearDownClass(cls):
        import os
        os.unlink(cls.keyring)

    def test_basic(self):
        assert self.enc and self.sgn

    def test_sender_signed(self):
        # good self sign
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        raw, verified, result1 = id1.decrypt(sgn)
        verified2, result2 = id1.verify(sgn)
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed'] and result1['key_ids']
        assert result1['key_ids']==result2['key_ids']

    def test_sender_encrypted(self):
        # bad self decrypt
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        raw, verified, result1 = id1.decrypt(enc)
        verified2, result2 = id1.verify(enc)
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['key_ids'] or result2['key_ids'])

    def test_receiver_signed(self):
        # bad sign
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        # receiver does not know sender, cannot verify, but can decrypt
        raw, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        compare_mail(prot,raw)
        assert not (result1['encrypted'] or result1['signed'] or result2['signed'] or verified)
        assert not (result1['key_ids'] or result2['key_ids'])

    def test_receiver_encrypted(self):
        # bad encrypt
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        raw, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        compare_mail(msg,raw)
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['key_ids'] or result2['key_ids'])

class BilateralTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyring1=mktmp()
        cls.keyring2=mktmp()
        cls.gpg1 = gnupg.GPG(keyring=cls.keyring1,secring=secrings[0])
        cls.gpg2 = gnupg.GPG(keyring=cls.keyring2,secring=secrings[1])
        cls.gpg1.import_keys(pubkey1)
        cls.gpg1.import_keys(pubkey2) # sender knows receiver pubkey
        cls.gpg2.import_keys(pubkey1)
        cls.gpg2.import_keys(pubkey2)
        cls.id1 = GPGMIME(cls.gpg1,default_key=sender)
        cls.id2 = GPGMIME(cls.gpg2,default_key=receiver)

    @classmethod
    def tearDownClass(cls):
        import os
        os.unlink(cls.keyring1)
        os.unlink(cls.keyring2)

    def encrypt(self,msg,sign):
        id1, id2 = self.id1, self.id2
        enc,_ = id1.encrypt(msg,sign=sign)
        assert id2.analyze(enc) == (True,None)
        mail, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert verified==verified2
        assert result1['encrypted'] and verified==sign and result1['signed']==sign and result2['signed']==sign
        assert result1['key_ids']==result2['key_ids']
        compare_mail(mail,msg)

    def sign(self,msg,inline):
        id1, id2 = self.id1, self.id2
        prot = protect_mail(msg,ending='\r\n')
        sgn,_ = id1.sign(msg,inline=inline)
        assert id2.analyze(sgn) == (False,True)
        mail, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        rawmail, signed = id2.strip_signature(sgn)
        assert verified==verified2
        compare_mail(mail,rawmail)
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed']
        assert result1['key_ids']==result2['key_ids']
        compare_mail(rawmail,prot)

    def test_sign(self):
        self.sign(msg, inline=False)

    def test_sign_attach(self):
        self.sign(msga, inline=False)

    def test_sign_inline(self):
        self.sign(msg, inline=True)

    def test_sign_inline_attach(self):
        self.sign(msga, inline=True)

    def test_encrypt(self):
        self.encrypt(msg, sign=False)

    def test_encrypt_attach(self):
        self.encrypt(msga, sign=False)

    def test_encrypt_inline(self):
        self.encrypt(msg, sign=True)

    def test_encrypt_inline_attach(self):
        self.encrypt(msga, sign=True)

if __name__ == '__main__':
    main()
