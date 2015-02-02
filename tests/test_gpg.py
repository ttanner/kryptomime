#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# GPG unit tests
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
from kryptomime.mail import create_mail, create_mime, protect_mail
from kryptomime.pgp import GPGMIME, find_gnupg_key
from kryptomime.backends import tmpfname

import gnupg, email.mime.text

"""
TODO: 'multipart/encrypted' but single-part, text/plain but encrypted, 'multipart/mixed' but signed
"""
from conftest import sender, receiver, compare_mail

passphrase='mysecret'
attachment = email.mime.text.MIMEText('some\nattachment')
msg = create_mail(sender,receiver,'subject','body\nmessage')
msg.epilogue=''
msgatt = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
msgrev = create_mail(receiver,sender,'subject','body\nmessage')
msgself = create_mail(sender,sender,'subject','body\nmessage')
prot = protect_mail(msg,linesep='\r\n')
protatt = protect_mail(msgatt,linesep='\r\n')

@fixture(scope='module')
def keys(request):
    import os
    generate = request.config.getoption('generate')
    verbose = request.config.getoption('gpglog')
    if verbose: gnupg._logger.create_logger(10)
    keyrings = [tmpfname() for i in range(2)]
    secrings = [tmpfname() for i in range(2)]
    home = os.path.dirname(os.path.abspath(__file__))
    fpubkey = [os.path.join(home,'pubkey%i.asc'%(i+1)) for i in range(2)]
    fseckey = [os.path.join(home,'seckey%i.asc'%(i+1)) for i in range(2)]
    keygen = generate
    if not keygen:
        for fname in fpubkey+fseckey:
            if os.path.exists(fname): continue
            keygen = True
            break
    if keygen:
        for fname in fpubkey+fseckey:
            if os.path.exists(fname): os.unlink(fname)
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=secrings[0],verbose=verbose,use_agent=False)
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=secrings[1],verbose=verbose,use_agent=False)
    if keygen:
        print ('generating keys')
        key1 = gpg1.gen_key(gpg1.gen_key_input(name_email=sender,key_length=1024,
            passphrase=passphrase,expire_date='0'))
        key2 = gpg2.gen_key(gpg2.gen_key_input(name_email=receiver,key_length=1024,
            expire_date='0'))
        assert key1 and key2
        key1, key2 = key1.fingerprint, key2.fingerprint
        pubkey1= gpg1.export_keys(key1)
        pubkey2= gpg2.export_keys(key2)
        open(fpubkey[0],'wt').write(pubkey1)
        open(fpubkey[1],'wt').write(pubkey2)
        seckey1= gpg1.export_keys(key1,secret=True)
        seckey2= gpg2.export_keys(key2,secret=True)
        open(fseckey[0],'wt').write(seckey1)
        open(fseckey[1],'wt').write(seckey2)
    else:
        pubkey1 = open(fpubkey[0],'rt').read()
        pubkey2 = open(fpubkey[1],'rt').read()
        gpg1.import_keys(pubkey1)
        gpg2.import_keys(pubkey2)
        seckey1 = open(fseckey[0],'rt').read()
        seckey2 = open(fseckey[1],'rt').read()
        gpg1.import_keys(seckey1)
        gpg2.import_keys(seckey2)
        key1 = find_gnupg_key(gpg1,sender)
        key2 = find_gnupg_key(gpg2,receiver)
        assert key1 and key2
    def fin():
        for tmp in keyrings+secrings: os.unlink(tmp)
    if generate: request.addfinalizer(fin)
    return {'gpg1':gpg1, 'gpg2':gpg2, 'pubkey1':pubkey1, 'pubkey2':pubkey2, 'secrings':secrings}

@fixture(scope='module')
def gpgsender(keys):
    return GPGMIME(keys['gpg1'],default_key=(sender,passphrase))

@fixture(scope='module')
def gpgreceiver(keys):
    return GPGMIME(keys['gpg2'],default_key=receiver)

def print_mail(m):
    from kryptomime.mail import ProtectedMessage
    print ('main', repr(m._linesep) if isinstance(m,ProtectedMessage) else '')
    print (repr(m.as_string()))
    if m.is_multipart():
        for i, sub in enumerate(m.get_payload()):
            print ('part',i, repr(sub._linesep) if isinstance(sub,ProtectedMessage) else '')
            print (repr(sub.as_string()))
            print (repr(sub.get_payload()))
    else:
        print (repr(m.get_payload()))

@mark.parametrize("variant", range(16))
def test_sign(gpgsender,variant):
    # protect = use protected CRLF message
    import copy
    inline,attach,asstr,protect=variant&8,variant&4,variant&2,variant&1
    if inline and attach: return

    global prot, protatt
    if attach: # with attachment
        nmsg, pmsg = protect_mail(msgatt,linesep='\n'), protatt
        inmsg = protatt if protect else nmsg
    else:
        inmsg = prot if protect else msg
        nmsg, pmsg = msg, prot
    if asstr: inmsg, nmsg, pmsg = inmsg.as_string(), nmsg.as_string(), pmsg.as_string()
    omsg = copy.deepcopy(inmsg)
    sgn, result = gpgsender.sign(inmsg,inline=inline,verify=True)
    assert sgn
    compare_mail(omsg,inmsg) # unmodified
    if inline:
        assert not sgn.is_multipart()
        body = gpgsender.without_signature(sgn.get_payload())
        if not asstr: assert body==pmsg.get_payload()
    if asstr: sgn = sgn.as_string()
    if protect: sgn = protect_mail(sgn,linesep='\r\n')
    osgn = copy.deepcopy(sgn)
    assert gpgsender.verify(sgn,strict=True)[0]
    compare_mail(osgn,sgn) # unmodified
    msg2, signed, results = gpgsender.decrypt(sgn,strict=True)
    assert signed and msg2
    compare_mail(osgn,sgn) # unmodified
    if asstr: msg2 = msg2.as_string()
    compare_mail(pmsg,msg2)

    assert gpgsender.verify(sgn,strict=False)[0]
    compare_mail(osgn,sgn) # unmodified
    msg2, signed, results = gpgsender.decrypt(sgn,strict=False)
    assert signed and msg2
    compare_mail(osgn,sgn) # unmodified
    if asstr: msg2 = msg2.as_string()
    compare_mail(pmsg,msg2)

    nsgn = protect_mail(sgn,linesep='\n') # use LF message as input
    if asstr: nsgn = nsgn.as_string()
    compare_mail(osgn,sgn) # unmodified
    onsgn = copy.deepcopy(nsgn)
    msg2, signed, results = gpgsender.decrypt(nsgn,strict=True)
    assert signed==bool(inline) and msg2 # sgn was modified, should fail for detached
    compare_mail(onsgn,nsgn) # unmodified
    if asstr: msg2 = msg2.as_string()
    compare_mail(nmsg,msg2)

    msg2, signed, results = gpgsender.decrypt(nsgn,strict=False)
    assert signed and msg2
    compare_mail(onsgn,nsgn)
    if asstr: msg2 = msg2.as_string()
    if inline:
        compare_mail(nmsg,msg2)
    else:
        compare_mail(pmsg,msg2)

@mark.parametrize("variant", range(4))
def test_encrypt(gpgsender,variant):
    import copy
    asstr,protect=variant&2,variant&1
    inmsg = protect_mail(msgrev,linesep='\r\n') if protect else msgrev
    if asstr: inmsg = inmsg.as_string()
    omsg = copy.deepcopy(inmsg)
    enc, results = gpgsender.encrypt(inmsg,toself=False,sign=False) # we only know sender keys
    assert enc
    compare_mail(omsg,inmsg)
    if protect: enc = protect_mail(enc,linesep='\r\n')
    if asstr: enc = enc.as_string()
    oenc = copy.deepcopy(enc)
    msg2, signed, results = gpgsender.decrypt(enc,strict=True)
    assert not signed and msg2
    compare_mail(oenc,enc)
    if asstr: msg2 = msg2.as_string()
    compare_mail(inmsg,msg2)

def test_unknown_sign(gpgreceiver):
    # bad sign
    with raises(KeyMissingError):
        gpgreceiver.sign(msg) # sender key missing - cannot sign

def test_unknown_encrypt(gpgsender):
    # bad encrypt
    with raises(KeyMissingError):
        gpgsender.encrypt(msg) # receiver key missing - cannot encrypt

@fixture(scope='module')
def unilateral(request,keys):
    keyring = tmpfname()
    gpg = gnupg.GPG(keyring=keyring,secring=keys['secrings'][0],use_agent=False)
    gpg.import_keys(keys['pubkey1'])
    gpg.import_keys(keys['pubkey2']) # sender knows receiver pubkey
    id = GPGMIME(gpg,default_key=(sender,passphrase))
    sgn = id.sign(msg)[0]
    enc = id.encrypt(msg,toself=False,sign=False)[0]
    def fin():
        import os
        os.unlink(keyring)
    request.addfinalizer(fin)
    return {'id':id,'sgn':sgn,'enc':enc}

class TestUnilateral:

    def test_raw(self,unilateral):
        id1 = unilateral['id']
        assert id1.analyze(msg) == (False,False)
        raw, verified, result1 = id1.decrypt(msg)
        verified2, result2 = id1.verify(msg)
        assert raw and result1 and result2
        assert not result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['fingerprints'] or result2['fingerprints'])
        compare_mail(msg,raw)

    def test_verify(self,unilateral):
        id1, sgn, enc = unilateral['id'], unilateral['sgn'], unilateral['enc']
        assert enc and sgn
        assert id1.sign(msg,verify=True)[0]
        assert id1.encrypt(msg,sign=False,verify=True)[0]

    def test_sender_signed(self,unilateral,gpgreceiver):
        # good self sign
        id1, id2, sgn = unilateral['id'], gpgreceiver, unilateral['sgn']
        raw, verified, result1 = id1.decrypt(sgn)
        verified2, result2 = id1.verify(sgn)
        assert raw and result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed'] and result1['fingerprints']
        assert result1['fingerprints']==result2['fingerprints']

    def test_sender_signed_nl(self,unilateral,gpgreceiver):
        # good self sign
        id1, id2, sgn = unilateral['id'], gpgreceiver, unilateral['sgn']
        sgn = protect_mail(sgn,linesep='\n')
        raw, verified, result1 = id1.decrypt(sgn,strict=False)
        verified2, result2 = id1.verify(sgn,strict=False)
        assert raw and result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed'] and result1['fingerprints']
        assert result1['fingerprints']==result2['fingerprints']

    def test_sender_encrypted(self,unilateral,gpgreceiver):
        # bad self decrypt
        id1, id2, enc = unilateral['id'], gpgreceiver, unilateral['enc']
        raw, verified, result1 = id1.decrypt(enc)
        verified2, result2 = id1.verify(enc)
        assert not raw and result1 and result2
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['fingerprints'] or result2['fingerprints'])

    def test_receiver_signed(self,unilateral,gpgreceiver):
        # bad sign
        id1, id2, sgn = unilateral['id'], gpgreceiver, unilateral['sgn']
        # receiver does not know sender, cannot verify, but can decrypt
        raw, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        assert raw and result1 and result2
        assert not result1['encrypted'] and not verified
        assert result1['signed'] and result2['signed']
        assert not (result1['fingerprints'] or result2['fingerprints'])
        compare_mail(prot,raw)

    def test_receiver_encrypted(self,unilateral,gpgreceiver):
        # bad encrypt
        id1, id2, enc = unilateral['id'], gpgreceiver, unilateral['enc']
        raw, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert raw and result1 and result2
        assert result1['encrypted'] and not (verified or result1['signed'] or result2['signed'])
        assert not (result1['fingerprints'] or result2['fingerprints'])
        compare_mail(msg,raw)

@fixture(scope='module')
def bilateral(request,keys):
    keyrings = [tmpfname() for i in range(2)]
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=keys['secrings'][0],use_agent=False)
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=keys['secrings'][1],use_agent=False)
    gpg1.import_keys(keys['pubkey1'])
    gpg1.import_keys(keys['pubkey2']) # sender knows receiver pubkey
    gpg2.import_keys(keys['pubkey1'])
    gpg2.import_keys(keys['pubkey2'])
    id1 = GPGMIME(gpg1,default_key=(sender,passphrase))
    id2 = GPGMIME(gpg2,default_key=receiver)
    def fin():
        import os
        for tmp in keyrings: os.unlink(tmp)
    request.addfinalizer(fin)
    return {'id1':id1,'id2':id2,'gpg1':gpg1}

class TestBilateral:

    def test_keys(self,bilateral):
        id1 = bilateral['id1']
        s = id1.find_key(sender)
        r = id1.find_key(receiver)
        assert s and r
        k = id1.find_key([sender,receiver])
        assert k[sender]==s and k[receiver]==r
        assert id1.find_key('un@known') is None

    def encrypt(self,ids,msg,sign,inline):
        id1, id2 = ids['id1'], ids['id2']
        enc,_ = id1.encrypt(msg,sign=sign,inline=inline)
        assert enc and id2.analyze(enc) == (True,None)
        mail, verified, result1 = id2.decrypt(enc)
        verified2, result2 = id2.verify(enc)
        assert mail and verified==verified2 and result1 and result2
        assert result1['encrypted'] and verified==sign and result1['signed']==sign and result2['signed']==sign
        assert result1['fingerprints']==result2['fingerprints']
        compare_mail(mail,msg)

    def sign(self,ids,msg,inline):
        id1, id2 = ids['id1'], ids['id2']
        prot = protect_mail(msg,linesep='\r\n')
        sgn,_ = id1.sign(msg,inline=inline)
        assert sgn and id2.analyze(sgn) == (False,True)
        mail, verified, result1 = id2.decrypt(sgn)
        verified2, result2 = id2.verify(sgn)
        rawmail, signed = id2.strip_signature(sgn)
        assert mail and verified==verified2
        compare_mail(mail,rawmail)
        assert result1 and result2
        assert not result1['encrypted'] and verified and result1['signed'] and result2['signed']
        assert result1['fingerprints']==result2['fingerprints']
        compare_mail(rawmail,prot)

    def test_sign(self,bilateral):
        self.sign(bilateral, msg, inline=False)

    def test_sign_attach(self,bilateral):
        self.sign(bilateral, msgatt, inline=False)

    def test_uni_sign_attach(self,bilateral):
        usender = sender.replace('Foo','Föo')
        ureceiver = receiver.replace('Bar','Bär')
        attachment = create_mime(u'söme\nattachment',charset='utf-8')
        msgatt = create_mail(usender,ureceiver,u'sübject',u'bödy\nmessage',
            attach=[attachment],charset='utf-8')
        self.sign(bilateral, msgatt, inline=False)

    def test_sign_inline(self,bilateral):
        self.sign(bilateral, msg, inline=True)

    def test_sign_inline_attach(self,bilateral):
        self.sign(bilateral, msgatt, inline=True)

    def test_encrypt(self,bilateral):
        self.encrypt(bilateral, msg, sign=False, inline=False)

    def test_encrypt_attach(self,bilateral):
        self.encrypt(bilateral, msgatt, sign=False, inline=False)

    def test_uni_encrypt_attach(self,bilateral):
        usender = sender.replace('Foo','Föo')
        ureceiver = receiver.replace('Bar','Bär')
        attachment = email.mime.text.MIMEText(u'söme\nattachment',_charset='utf-8')
        msgatt = create_mail(usender,ureceiver,u'sübject',u'bödy\nmessage',
            attach=[attachment],charset='utf-8')
        self.encrypt(bilateral, msgatt, sign=False, inline=False)

    def test_encrypt_inline(self,bilateral):
        self.encrypt(bilateral, msg, sign=False, inline=True)

    def test_encrypt_sign(self,bilateral):
        self.encrypt(bilateral, msg, sign=True, inline=False)

    def test_encrypt_sign_attach(self,bilateral):
        self.encrypt(bilateral, msgatt, sign=True, inline=False)

    def test_encrypt_sign_inline(self,bilateral):
        self.encrypt(bilateral, msg, sign=True, inline=True)

    def test_no_defkey(self,bilateral):
        # missing defkey, cannot sign
        id1 = GPGMIME(bilateral['gpg1'])
        assert id1.sign(msg)[0] is None
        assert id1.encrypt(msg,sign=True)[0] is None
        # no receiver key, cannot decrypt
        enc = bilateral['id2'].encrypt(msgrev)[0]
        assert enc
        mail, valid, result = id1.decrypt(enc)
        assert mail is None and not valid and not result['signed']

    def test_no_defkey2(self,bilateral):
        # missing defkey, cannot sign
        id1 = GPGMIME(bilateral['gpg1'])
        mail, result = id1.sign(msg,passphrase='bad')
        assert mail is None and not result
        mail, result = id1.encrypt(msg,sign=True,passphrase='bad')
        assert mail is None and not result
        # no receiver key, cannot decrypt
        enc = bilateral['id2'].encrypt(msgrev)[0]
        assert enc
        mail, valid, result = id1.decrypt(enc,passphrase='bad')
        assert mail is None and not valid and not result['signed']

    def test_bad_passphrase(self,bilateral):
        # bad sender passphrase, cannot sign
        id1 = GPGMIME(bilateral['gpg1'],default_key=(sender,'wrong'))
        assert id1.sign(msg)[0] is None
        assert id1.encrypt(msg,sign=True)[0] is None
        # bad receiver passphrase, cannot decrypt
        enc = bilateral['id2'].encrypt(msgrev)[0]
        assert enc and id1.decrypt(enc)[0] is None

    def test_bad_defkey(self,bilateral):
        # bad sender passphrase, cannot sign
        id1 = GPGMIME(bilateral['gpg1'],default_key=receiver)
        with raises(KeyMissingError): id1.sign(msgrev)
        with raises(KeyMissingError): id1.encrypt(msgrev,sign=True)
        # bad receiver key, cannot decrypt
        enc = bilateral['id2'].encrypt(msgrev,toself=False)[0]
        assert enc and id1.decrypt(enc)[0] is None

    def bad_sign(self,ids,receiver,msg,encrypt):
        # id1 signs, but id2 doesn't know id1
        id1, id2 = ids['id1'], receiver
        prot = protect_mail(msg,linesep='\r\n')
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
        assert not result1['fingerprints'] and not result2['fingerprints']

    def test_bad_sign(self,bilateral,gpgreceiver):
        self.bad_sign(bilateral,gpgreceiver,msg,False)

    def test_bad_sign_encrypt(self,bilateral,gpgreceiver):
        self.bad_sign(bilateral,gpgreceiver,msg,True)

    def bad_encrypt(self,ids,receiver,sign):
        # id1 encrypts for id1, but id2 can't decrypt id1
        id1, id2 = ids['id1'], receiver
        enc,_ = id1.encrypt(msgself,sign=sign)
        assert enc and id2.analyze(enc) == (True,None)
        valid, result = id2.verify(enc)
        assert not valid and not result['signed'] and result['encrypted']
        mail, valid, result = id2.decrypt(enc)
        assert mail is None and not valid and not result['signed'] and result['encrypted']

    def test_bad_encrypt(self,bilateral,gpgreceiver):
        self.bad_encrypt(bilateral,gpgreceiver,False)

    def test_bad_encrypt_sign(self,bilateral,gpgreceiver):
        self.bad_encrypt(bilateral,gpgreceiver,True)

    def test_str(self,bilateral):
        id1, id2 = bilateral['id1'], bilateral['id2']
        secret = 'some\nsecret'
        sgn = id1.sign_str(secret)
        assert sgn
        assert id2.verify_str(str(sgn))
        enc = id1.encrypt_str(secret,[receiver],sign=sender)
        assert enc
        result = id2.decrypt_str(str(enc))
        assert str(result) == secret

    @mark.parametrize("binary", [False,True])
    def test_file(self,bilateral,binary):
        from six import BytesIO, StringIO, PY3
        if PY3 and not binary: return # FIXME: known bug in python-gnupg 1.4.0
        id1, id2 = bilateral['id1'], bilateral['id2']
        stream = BytesIO if binary else StringIO
        secret = 'some\nsecret'
        if binary: secret = secret.encode('ascii')
        sgn = id1.sign_file(stream(secret))
        assert sgn
        sgn = str(sgn)
        if binary: sgn = sgn.encode('ascii')
        assert id2.verify_file(stream(sgn))
        enc = id1.encrypt_file(stream(secret),[receiver],sign=sender)
        assert enc
        enc = str(enc)
        if binary: enc = enc.encode('ascii')
        result = id2.decrypt_file(stream(enc))
        assert result
        dec = str(result)
        if binary: dec = dec.encode('ascii')
        assert dec == secret
