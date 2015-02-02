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

from .core import KryptoMIME, make_list
from .backends.openssl import OpenSSL, OpenSSL_CA

class SMIME(KryptoMIME):
    def __init__(self, default_key=None, key_store=None):
        self.default_key = default_key
        self.key_store = key_store

    def find_key(self,addr,secret=False):
        """find keyid for email 'addr' or return None."""
        if not self.key_store: return None
        return self.key_store.find_key(addr,secret)

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

class PublicKey(object):
    def __init__(self, public=None, cacerts=None):
        self.public = public
        self.cacerts = cacerts

    def load(self,fname,cafile=None):
        self.public = open(fname,'rt').read()
        if not cafile: return
        self.cacerts = ''
        for fname in make_list(cafile):
            self.cacerts += open(fname,'rt').read()

    def save(self,fname,cafile=None):
        "with cafile=True include in public, None=don't save"
        f = open(fname,'wt')
        f.write(self.public)
        if cafile==True: f.write(self.cacerts)
        f.close()
        if not cafile or cafile==True: return
        f = open(cafile,'wt')
        f.write(self.cacerts)
        f.close()

class PrivateKey(PublicKey):
    def __init__(self, public=None, private=None, passphrase=None, cacerts=None):
        super(PrivateKey,self).__init__(public,cacerts)
        self.private = private
        self.passphrase = passphrase

    def load(self,fname,private=None,cafile=None):
        super(PrivateKey,self).load(fname,cafile)
        if not private: return
        self.private = open(private,'rt').read()

    def save(self,fname,private=None,cafile=None):
        "with cafile/private=True include in public, None=don't save"
        f = open(fname,'wt')
        if private==True: f.write(self.private)
        f.write(self.public)
        if cafile==True: f.write(self.cacerts)
        f.close()
        if private and private!=True:
            f = open(private,'wt')
            f.write(self.private)
            f.close()
        if cafile and cafile!=True:
            f = open(cafile,'wt')
            f.write(self.cacerts)
            f.close()

class X509KeyStore(object):

    def find_key(self,keyid,secret=False):
        raise NotImplementedError

    def import_key(self,key):
        raise NotImplementedError

    def export_key(self,keyid):
        raise NotImplementedError

class X509MemoryKeyStore(X509KeyStore):

    def __init__(self):
        self.keys = []

class X509DirectoryKeyStore(X509KeyStore):
    def __init__(self, path):
        self.path = path

def _remove_headers(mail, decode=False):
    from email.message import Message
    from .mail import protect_mail
    import copy, six
    if not isinstance(mail,(Message,)+six.string_types):
        raise TypeError("mail must be Message or str")
    mail = protect_mail(mail,linesep='\r\n',sevenbit=not decode) # fix line separators + 7bit RFC2822
    multipart = mail.is_multipart()
    # delete all headers except content
    inner = copy.copy(mail)
    for key in inner.keys():
        lkey = key.lower()
        if lkey=='content-type': continue
        if not multipart and lkey=='content-transfer-encoding': continue
        del inner[key]
    if multipart: inner.preamble='This is a multi-part message in MIME format.'
    return inner.as_string(), mail

def _restore_headers(mail, inner, decode=False):
    from .mail import protect_mail, _mail_addreplace_header, _protected
    import six
    inner = protect_mail(inner,linesep=None)
    if six.PY3: mail = _protected(mail,headersonly=True)
    if decode:
        for k,v in inner.items():
            _mail_addreplace_header(mail,k,v)
    else:
        mail.replace_header('Content-Type',inner['Content-Type'])
    mail.preamble = inner.preamble
    if inner.is_multipart():
        mail.set_payload(None)
        for payload in inner.get_payload():
            mail.attach(payload)
    else:
        mail.set_payload(inner.get_payload())
    return mail

class OpenSMIME(SMIME):

    def __init__(self, default_key=None, key_store=None, openssl=None):
        "initialize with an openssl instance and optionally default_key or key_store"
        from six import string_types
        if not openssl:
            self.openssl = OpenSSL()
        elif isinstance(openssl, string_types):
            self.openssl = OpenSSL(executable=openssl)
        else:
            self.openssl = openssl
        if default_key:
            assert isinstance(default_key, PrivateKey), "invalid default key"
        super(OpenSMIME,self).__init__(default_key, key_store)

    def sign(self, mail, verify=False, **kwargs):
        key = self.default_key
        inner, mail = _remove_headers(mail)
        signed = self.openssl.sign(inner,key.public,key.private,key.passphrase,**kwargs)
        if verify:
            vfy, signer, valid = self.openssl.verify(signed,cacerts=make_list(verify),**kwargs)
            assert valid and inner==vfy
        return _restore_headers(mail, signed)

    def verify(self, mail, cacerts=None, **kwargs):
        inner, mail = _remove_headers(mail, decode=True)
        inner, signer, valid = self.openssl.verify(inner,cacerts=make_list(cacerts),**kwargs)
        mail = _restore_headers(mail, inner, decode=True)
        return mail, signer, valid

    def encrypt(self, mail, recipients=None, sign=True, verify=False, **kwargs):
        if sign==True or verify:
            key = self.default_key
            kwargs.update(dict(private=key.private,
                password=key.passphrase,certs=key.cacerts))
            if sign==True: kwargs['sign'] = key.public
        elif sign: kwargs['sign'] = sign
        recipients = [key.public for key in recipients]
        if verify:
            key = self.default_key.public
            if not key in recipients: recipients.append(key)
        inner, mail = _remove_headers(mail, False)
        encrypted = self.openssl.encrypt(inner,recipients,**kwargs)
        if verify:
            key = self.default_key
            if sign:
                del kwargs['sign']
                dec, signer, valid = self.openssl.decrypt(encrypted,key.public,
                    verify=True,cacerts=[key.cacerts], **kwargs)
                assert valid
            else:
                dec = self.openssl.decrypt(encrypted, key.public, verify=False, **kwargs)
            assert inner==dec
        return _restore_headers(mail, encrypted, False)

    def decrypt(self, mail, recipient=None, verify=True, cacerts=None, **kwargs):
        key = recipient if recipient else self.default_key
        inner, mail = _remove_headers(mail, True)
        result = self.openssl.decrypt(inner,key.public,private=key.private,password=key.passphrase,
            verify=verify, cacerts=make_list(cacerts), **kwargs)
        mail = _restore_headers(mail, result[0] if verify else result, True)
        if verify: return mail,result[1],result[2]
        return mail
