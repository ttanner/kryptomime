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

from .. import create_mail, GPGMIME, protect_mail
import gnupg, email.mime.text

generate=False # whether to generate key on the fly instead default
sender='foo@localhost'
passphrase='mysecret'
receiver='bar@localhost'
attachment = email.mime.text.MIMEText('some\nattachment')
msg = create_mail(sender,receiver,'subject','body\nmessage')
msgatt = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
msgrev = create_mail(receiver,sender,'subject','body\nmessage')
msgself = create_mail(sender,sender,'subject','body\nmessage')
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
    import os
    from ..pgp import find_gnupg_key
    verbose = False
    if verbose: gnupg._logger.create_logger(10)
    if generate:
        keyrings = [mktmp() for i in range(2)]
        secrings = [mktmp() for i in range(2)]
    else:
        home = os.path.dirname(os.path.abspath(__file__))
        keyrings = [os.path.join(home,'keyring%i'%i) for i in range(2)]
        secrings = [os.path.join(home,'secring%i'%i) for i in range(2)]
    keygen = generate
    if not keygen:
        for fname in keyrings+secrings:
            if os.path.exists(fname): continue
            keygen = True
            break
    if keygen:
        for fname in keyrings+secrings:
            if os.path.exists(fname): os.unlink(fname)
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=secrings[0],verbose=verbose)
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=secrings[1],verbose=verbose)
    if keygen:
        key1 = gpg1.gen_key(gpg1.gen_key_input(name_email=sender,key_length=1024,passphrase=passphrase)).fingerprint
        key2 = gpg2.gen_key(gpg2.gen_key_input(name_email=receiver,key_length=1024)).fingerprint
    else:
        key1 = find_gnupg_key(gpg1,sender)
        key2 = find_gnupg_key(gpg2,receiver)
    pubkey1= gpg1.export_keys(key1)
    pubkey2= gpg2.export_keys(key2)

def tearDownModule():
    if not generate: return
    import os
    for tmp in keyrings+secrings: os.unlink(tmp)

def test_selfie():
    id1 = GPGMIME(gpg1,default_key=(sender,passphrase))
    assert id1.sign(msg)[0]
    assert id1.encrypt(msgrev,toself=False,sign=False)[0]

def test_unknown_sign():
    # bad sign
    id2 = GPGMIME(gpg2,default_key=receiver)
    assert id2.sign(msg)[0] is None # sender key missing - cannot sign
    
def test_unknown_encrypt():
    # bad encrypt
    id1 = GPGMIME(gpg1,default_key=(sender,passphrase))
    assert id1.encrypt(msg)[0] is None # receiver key missing - cannot encrypt

class UnilateralTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyring = mktmp()
        cls.gpg = gnupg.GPG(keyring=cls.keyring,secring=secrings[0])
        cls.gpg.import_keys(pubkey1)
        cls.gpg.import_keys(pubkey2) # sender knows receiver pubkey
        cls.id1 = GPGMIME(cls.gpg,default_key=(sender,passphrase))
        cls.id2 = GPGMIME(gpg2,default_key=receiver)
        cls.sgn = cls.id1.sign(msg)[0]
        cls.enc = cls.id1.encrypt(msg,toself=False,sign=False)[0]

    @classmethod
    def tearDownClass(cls):
        import os
        os.unlink(cls.keyring)

    def test_raw(self):
        assert self.id1.analyze(msg) == (False,False)

    def test_verify(self):
        assert self.enc and self.sgn
        assert self.id1.sign(msg,verify=True)[0]
        assert self.id1.encrypt(msg,sign=False,verify=True)[0]

    def test_sender_signed(self):
        # good self sign
        id1, id2 = self.id1, self.id2
        sgn = self.sgn
        raw, verified, result1 = id1.decrypt(sgn)
        verified2, result2 = id1.verify(sgn)
        assert raw and result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed'] and result1['key_ids']
        assert result1['key_ids']==result2['key_ids']

    def test_sender_signed_nl(self):
        # good self sign
        id1, id2 = self.id1, self.id2
        sgn = protect_mail(self.sgn,ending='\n')
        raw, verified, result1 = id1.decrypt(sgn,strict=False)
        verified2, result2 = id1.verify(sgn,strict=False)
        assert raw and result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed'] and result1['key_ids']
        assert result1['key_ids']==result2['key_ids']

    def test_sender_encrypted(self):
        # bad self decrypt
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        raw, verified, result1 = id1.decrypt(enc)
        verified2, result2 = id1.verify(enc)
        assert not raw and result1 and result2
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['key_ids'] or result2['key_ids'])

    def test_receiver_signed(self):
        # bad sign
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        # receiver does not know sender, cannot verify, but can decrypt
        raw, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        assert raw and result1 and result2
        assert not result1['encrypted'] and not verified
        assert result1['signed'] and result2['signed']
        assert not (result1['key_ids'] or result2['key_ids'])
        compare_mail(prot,raw)

    def test_receiver_encrypted(self):
        # bad encrypt
        id1, id2 = self.id1, self.id2
        sgn, enc = self.sgn, self.enc
        raw, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert raw and result1 and result2
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['key_ids'] or result2['key_ids'])
        compare_mail(msg,raw)

class BilateralTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyrings = [mktmp() for i in range(2)]
        cls.gpg1 = gnupg.GPG(keyring=cls.keyrings[0],secring=secrings[0])
        cls.gpg2 = gnupg.GPG(keyring=cls.keyrings[1],secring=secrings[1])
        cls.gpg1.import_keys(pubkey1)
        cls.gpg1.import_keys(pubkey2) # sender knows receiver pubkey
        cls.gpg2.import_keys(pubkey1)
        cls.gpg2.import_keys(pubkey2)
        cls.id1 = GPGMIME(cls.gpg1,default_key=(sender,passphrase))
        cls.id2 = GPGMIME(cls.gpg2,default_key=receiver)
        cls.id2u = GPGMIME(gpg2,default_key=receiver) # without pubkey1

    @classmethod
    def tearDownClass(cls):
        import os
        for tmp in cls.keyrings: os.unlink(tmp)

    def encrypt(self,msg,sign,inline):
        id1, id2 = self.id1, self.id2
        enc,_ = id1.encrypt(msg,sign=sign,inline=inline)
        assert enc and id2.analyze(enc) == (True,None)
        mail, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert mail and verified==verified2 and result1 and result2
        assert result1['encrypted'] and verified==sign and result1['signed']==sign and result2['signed']==sign
        assert result1['key_ids']==result2['key_ids']
        compare_mail(mail,msg)

    def sign(self,msg,inline):
        id1, id2 = self.id1, self.id2
        prot = protect_mail(msg,ending='\r\n')
        sgn,_ = id1.sign(msg,inline=inline)
        assert sgn and id2.analyze(sgn) == (False,True)
        mail, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        rawmail, signed = id2.strip_signature(sgn)
        assert mail and verified==verified2
        compare_mail(mail,rawmail)
        assert result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed']
        assert result1['key_ids']==result2['key_ids']
        compare_mail(rawmail,prot)

    def test_sign(self):
        self.sign(msg, inline=False)

    def test_sign_attach(self):
        self.sign(msgatt, inline=False)

    def test_sign_inline(self):
        self.sign(msg, inline=True)

    def test_sign_inline_attach(self):
        self.sign(msgatt, inline=True)

    def test_encrypt(self):
        self.encrypt(msg, sign=False, inline=False)

    def test_encrypt_attach(self):
        self.encrypt(msgatt, sign=False, inline=False)

    def test_encrypt_inline(self):
        self.encrypt(msg, sign=False, inline=True)

    def test_encrypt_sign(self):
        self.encrypt(msg, sign=True, inline=False)

    def test_encrypt_sign_attach(self):
        self.encrypt(msgatt, sign=True, inline=False)

    def test_encrypt_sign_inline(self):
        self.encrypt(msg, sign=True, inline=True)

    def test_no_defkey(self):
        # missing defkekf, cannot sign
        id1 = GPGMIME(self.gpg1)
        assert id1.sign(msg)[0] is None
        assert id1.encrypt(msg,sign=True)[0] is None
        # no receiver key, cannot decrypt
        enc = self.id2.encrypt(msgrev)[0]
        assert enc and id1.decrypt(enc)[0] is None

    def test_bad_passphrase(self):
        # bad sender passphrase, cannot sign
        id1 = GPGMIME(self.gpg1,default_key=(sender,'wrong'))
        assert id1.sign(msg)[0] is None
        assert id1.encrypt(msg,sign=True)[0] is None
        # bad receiver passphrase, cannot decrypt
        enc = self.id2.encrypt(msgrev)[0]
        assert enc and id1.decrypt(enc)[0] is None

    def test_bad_defkey(self):
        # bad sender passphrase, cannot sign
        id1 = GPGMIME(self.gpg1,default_key=receiver)
        assert id1.sign(msgrev)[0] is None
        assert id1.encrypt(msgrev,sign=True)[0] is None
        # bad receiver key, cannot decrypt
        enc = self.id2.encrypt(msgrev,toself=False)[0]
        assert enc
        assert id1.decrypt(enc)[0] is None

    def bad_sign(self,msg,encrypt):
        # id1 signs, but id2 doesn't know id1
        id1, id2 = self.id1, self.id2u
        prot = protect_mail(msg,ending='\r\n')
        if encrypt: out,_ = id1.encrypt(msg,sign=True)
        else: out,_ = id1.sign(msg)
        assert out
        if encrypt: assert id2.analyze(out) == (True,None)
        else: assert id2.analyze(out) == (False,True)
        mail, verified, result1 = id2.decrypt(out)
        verified2, result2 = id2.verify(out)
        assert mail and result1 and result2
        assert result1['encrypted']==encrypt and not verified and not verified2
        assert result1['signed'] and result2['signed']
        assert not result1['key_ids'] and not result2['key_ids']

    def test_bad_sign(self):
        self.bad_sign(msg, False)

    def test_bad_sign_encrypt(self):
        self.bad_sign(msg, True)

    def bad_encrypt(self,sign):
        # id1 encrypts for id1, but id2 can't decrypt id1
        id1, id2 = self.id1, self.id2u
        enc,_ = id1.encrypt(msgself,sign=sign)
        assert enc and id2.analyze(enc) == (True,None)
        mail, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert not mail and result1 and result2
        assert result1['encrypted'] and not verified and not verified2
        assert not result1['key_ids'] and not result2['key_ids']
        assert not result1['signed'] and not result2['signed']

    def test_bad_encrypt(self):
        self.bad_encrypt(False)

    def test_bad_encrypt_sign(self):
        self.bad_encrypt(True)

if __name__ == '__main__':
    main()
