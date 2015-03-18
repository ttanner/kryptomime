#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# OpenSSL unit tests
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
from kryptomime.smime import Certificate, PrivateKey, MemoryKeyStore
from kryptomime.backends import split_pem
from kryptomime.backends.openssl import OpenSSL, OpenSSL_CA

import email.mime.text

from conftest import sender, receiver, passphrase

@fixture(scope='module')
def openssl():
    return OpenSSL()

@fixture(scope='module')
def x509keys(request):
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
        cacert1 = ca1.generate_root_ca('CN=ca1')
        cacert2 = ca2.generate_root_ca('CN=ca2')
        csr1, seckey1 = ca1.generate_key(sender,passphrase=passphrase)
        pubkey1 = ca1.sign_key(csr1,cacert=False,policy='policy_anything',days=3600)
        csr2, seckey2 = ca2.generate_key(receiver)
        pubkey2 = ca2.sign_key(csr2,cacert=False,policy='policy_anything',days=3600)
        assert pubkey1 and pubkey2
        key1 = PrivateKey(pubkey1,private=seckey1,passphrase=passphrase,cacerts=[cacert1])
        key1.save(fpubkey[0],fseckey[0],fcacert[0])
        key2 = PrivateKey(pubkey2,private=seckey2,cacerts=[cacert2])
        key2.save(fpubkey[1],fseckey[1],fcacert[1])
        from shutil import rmtree
        rmtree(ca1dir)
        rmtree(ca2dir)
    else:
        key1 = PrivateKey(passphrase=passphrase)
        key1.load(fpubkey[0],fseckey[0],[fcacert[0]])
        key2 = PrivateKey()
        key2.load(fpubkey[1],fseckey[1],[fcacert[1]])
    return (key1, key2)

def test_verify_key(x509keys,openssl):
    key1, key2 = x509keys
    assert openssl.verify_x509(key1.cert,cacerts=key1.cacerts)[0]
    assert openssl.verify_x509(key2.cert,cacerts=key2.cacerts)[0]
    assert not openssl.verify_x509(key1.cert,cacerts=key2.cacerts)[0]
    assert not openssl.verify_x509(key2.cert,cacerts=key1.cacerts)[0]

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    from datetime import datetime
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial

def print_x509(cert):
    from json import dumps
    openssl = OpenSSL()
    for k,v in split_pem(cert).iteritems():
        print (k)
        for x509 in v:
            res = openssl.decode_x509(x509)
            if not res: continue
            print (dumps(res,indent=2,default=json_serial))

def test_hierarchical_pki():
    from tempfile import mkdtemp
    from collections import OrderedDict
    try:
        a0_dir,b0_dir = mkdtemp(), mkdtemp()
        a1_dir,b1_dir = mkdtemp(), mkdtemp()
        a2_dir = mkdtemp()
        dirs = [a0_dir,b0_dir,a1_dir,b1_dir,a2_dir]
        a0_ca = OpenSSL_CA(directory=a0_dir)
        b0_ca = OpenSSL_CA(directory=b0_dir)
        a1_ca = OpenSSL_CA(directory=a1_dir)
        b1_ca = OpenSSL_CA(directory=b1_dir)
        a2_ca = OpenSSL_CA(directory=a2_dir)
        # pure CA signing CA
        ca_cfg = a0_ca.config_v3(req=True)+[
            ('basicConstraints', 'critical,CA:TRUE,pathlen:1'),
            ('keyUsage', 'cRLSign, keyCertSign'),
            ('subjectAltName','email:copy,email:hello@foo.com,URI:http://localhost/'),
            ('authorityKeyIdentifier', 'keyid'),
            ('authorityInfoAccess', ['OCSP;URI:http://ocsp.my.host/',
                'caIssuers;URI:http://my.ca/ca.html']),
            ('crlDistributionPoints', 'URI:http://my.com/my.crl,URI:http://oth.com/my.crl'),
        ]
        dn = dict(C='de',ST='Bavaria',L='Munich',O='Test',CN='root A',emailAddress='bar@localhost')
        a0_cert = a0_ca.generate_root_ca(dn,bits=1024,extensions=ca_cfg)

        dn.update(dict(CN='sub A',emailAddress='foo@localhost'))
        a1_cert = a0_ca.generate_sub_ca(a1_ca,dn,altname='email:copy,DNS:bad.org',bits=1024)

        a_crt, a_sec = a1_ca.generate_signed_key('/CN=foo/emailAddress=no@body.org',
            bits=1024,cacert=True,chain=True)

        # general CA
        b0_cert = b0_ca.generate_root_ca('CN=root B\nemailAddress=no@body.org',bits=1024)
    finally:
        from shutil import rmtree
        for cadir in dirs: rmtree(cadir)

def test_private(openssl):
    sec = openssl.generate_private(bits=1024,pkcs8=False)
    assert sec == openssl.convert_key(sec,pkcs8=False)
    sec = openssl.generate_private(bits=1024,pkcs8=True)
    assert sec == openssl.convert_key(sec,pkcs8=True)
