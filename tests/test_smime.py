#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# S/MIME unit tests
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

from pytest import fixture, mark, raises

from kryptomime import KeyMissingError
from kryptomime.mail import create_mail, protect_mail
from kryptomime.smime import OpenSMIME, PublicKey, PrivateKey, X509MemoryKeyStore, OpenSSL, OpenSSL_CA

import email.mime.text

from conftest import sender, receiver

passphrase='mysecret'
attachment = email.mime.text.MIMEText('some\nattachment')
msg = create_mail(sender,receiver,'subject','body\nmessage')
msg.epilogue=''
msgatt = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
msgrev = create_mail(receiver,sender,'subject','body\nmessage')
msgself = create_mail(sender,sender,'subject','body\nmessage')
prot = protect_mail(msg,linesep='\r\n')
protatt = protect_mail(msgatt,linesep='\r\n')

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

@fixture(scope='module')
def keys(request):
    import os
    generate = request.config.getoption('generate')
    home = os.path.dirname(os.path.abspath(__file__))
    fcacert = [os.path.join(home,'cacert%i.pem'%(i+1)) for i in range(2)]
    fpubkey = [os.path.join(home,'pubkey%i.pem'%(i+1)) for i in range(2)]
    fseckey = [os.path.join(home,'seckey%i.pem'%(i+1)) for i in range(2)]
    keygen = generate
    if not keygen:
        for fname in fcacert+fpubkey+fseckey:
            if os.path.exists(fname): continue
            keygen = True
            break
    if keygen:
        for fname in fcacert+fpubkey+fseckey:
            if os.path.exists(fname): os.unlink(fname)
    if keygen:
        print ('generating keys')
        ca1dir = os.path.join(home,'ca1')
        ca2dir = os.path.join(home,'ca2')
        ca1 = OpenSSL_CA(directory=ca1dir)
        ca2 = OpenSSL_CA(directory=ca2dir)
        cacert1 = ca1.generate_ca('CN=ca1')
        cacert2 = ca2.generate_ca('CN=ca2')
        csr1, seckey1 = ca1.generate_key(sender,password=passphrase)
        pubkey1 = ca1.sign_key(csr1,cacert=False,policy='policy_anything',days=3600)
        csr2, seckey2 = ca2.generate_key(receiver)
        pubkey2 = ca2.sign_key(csr2,cacert=False,policy='policy_anything',days=3600)
        assert pubkey1 and pubkey2
        key1 = PrivateKey(pubkey1,private=seckey1,passphrase=passphrase,cacerts=cacert1)
        key1.save(fpubkey[0],fseckey[0],fcacert[0])
        key2 = PrivateKey(pubkey2,private=seckey2,cacerts=cacert2)
        key2.save(fpubkey[1],fseckey[1],fcacert[1])
        from shutil import rmtree
        rmtree(ca1dir)
        rmtree(ca2dir)
    else:
        key1 = PrivateKey(passphrase=passphrase)
        key1.load(fpubkey[0],fseckey[0],fcacert[0])
        key2 = PrivateKey()
        key2.load(fpubkey[1],fseckey[1],fcacert[1])
    return (key1, key2)

@fixture(scope='module')
def smimesender(keys):
    return (OpenSMIME(default_key=keys[0]),keys[0].cacerts)

@fixture(scope='module')
def smimereceiver(keys):
    return (OpenSMIME(default_key=keys[1]),keys[0].cacerts)

@mark.parametrize("attach", [False,True])
def test_sign(keys, attach, smimesender, smimereceiver):
    id1, cacert1 = smimesender
    id2, cacert2 = smimereceiver
    mail = protatt if attach else prot
    sgn = id1.sign(mail)
    vfy, signer, valid = id2.verify(sgn,cacerts=cacert1)
    assert valid and keys[0].public == signer
    compare_mail(mail,vfy)

@mark.parametrize("sign", [False,True])
def test_encrypt(keys, sign, smimesender, smimereceiver):
    id1, cacert1 = smimesender
    id2, cacert2 = smimereceiver
    enc = id1.encrypt(protatt,[keys[1]],sign=sign, verify=True)
    dec = id2.decrypt(enc,verify=sign,cacerts=[cacert1])
    if sign:
        dec, signer, valid = dec
        assert valid and keys[0].public == signer
    compare_mail(protatt,dec)
