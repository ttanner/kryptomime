# -*- coding: utf-8 -*-
#
# PGP/MIME (GnuPG) support
#
# This file is part of kryptomime, a Python module for email kryptography.
# Copyright © 2013,2014 Thomas Tanner <tanner@gmx.net>
# partially inspired by the Mailman Secure List Server patch by 
#  Stefan Schlott <stefan.schlott informatik.uni-ulm.de>
#  Joost van Baal <joostvb-mailman-pgp-smime.mdcc.cx>
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

from .core import KryptoMIME

class KeyMissingError(Exception):
    def __init__(self, key):
        self.key = key
    def __str__(self):
        return "key missing: "+self.key

class PGPMIME(KryptoMIME):

    def find_key(self,addr,secret=False):
        """find key (fingerprint) for email 'addr' or return None.
        If addr is a list or tuple, return a dict(addr:keyid).
        secret searches in the secrety keyring """
        raise NotImplementedError

    def sign_file(self, file, **kwargs):
        raise NotImplementedError

    def sign_str(self, data, **kwargs):
        raise NotImplementedError

    def verify_file(self, file, signature=None):
        raise NotImplementedError

    def verify_str(self, data, signature=None):
        raise NotImplementedError

    def encrypt_file(self, file, *recipients, **kwargs):
        raise NotImplementedError

    def encrypt_str(self, data, *recipients, **kwargs):
        raise NotImplementedError

    def decrypt_file(self, file, **kwargs):
        raise NotImplementedError

    def decrypt_str(self, data, **kwargs):
        raise NotImplementedError

    # WARNING: Be EXTREMLY CAREFUL with modifying the following code. It's very RFC-sensitive

    @staticmethod
    def _fix_quoting(text):
        "fix broken Thunderbird quoting"
        import re
        text = re.sub(re.compile('^=3D',flags=re.MULTILINE),'=',text)
        return text

    @staticmethod
    def _plaintext(mail, inline = False):
        # Extract / generate plaintext
        import copy
        multipart = mail.is_multipart()
        if not multipart and inline: return mail.get_payload(), None
        # delete all headers except content
        mail = copy.copy(mail)
        for key in mail.keys():
            if key=='Content-Type': continue
            if not multipart and key=='Content-Transfer-Encoding': continue
            del mail[key]
        #mail.add_header('Content-Disposition','inline')
        if multipart: mail.preamble='This is a multi-part message in MIME format.'
        return mail.as_string(), mail

    @staticmethod
    def _ciphertext(mail):
        ciphertext = None
        is_pgpmime = False
        # Check: Is inline pgp?
        from .mail import protect_mail
        if type(mail)==str: mail = protect_mail(mail,linesep=None)
        if mail.get_content_type()=='application/pgp' or mail.get_param('x-action')=='pgp-encrypted':
            ciphertext = mail.get_payload()
            is_pgpmime = False
        # Check: Is pgp/mime?
        elif mail.get_content_type()=='multipart/encrypted' and mail.get_param('protocol')=='application/pgp-encrypted':
            if mail.is_multipart():
                for submsg in mail.get_payload():
                    if submsg.get_content_type()=='application/octet-stream':
                        is_pgpmime = True
                        ciphertext = submsg.get_payload()
            else:
                ciphertext = mail.get_payload()
        # Some clients send text/plain messages containing PGP-encrypted data :-(
        if not mail.is_multipart() and (ciphertext==None) and len(mail.get_payload())>10:
            firstline = mail.get_payload().splitlines()[0]
            if firstline=='-----BEGIN PGP MESSAGE-----':
                is_pgpmime = False
                ciphertext = mail.get_payload()
        return ciphertext, is_pgpmime

    @staticmethod
    def _has_signature(mail):
        if mail.is_multipart():
            if mail.get_content_type()=='multipart/signed' and mail.get_param('protocol')=='application/pgp-signature':
                # handle detached signatures, these look like:
                for submsg in mail.get_payload():
                    if submsg.get_content_type()=='application/pgp-signature':
                        return True
            elif mail.get_content_type()=='multipart/mixed' and not mail.get_param('protocol'):
                nonsig = []
                for submsg in mail.get_payload():
                    if submsg.get_content_type()=='application/pgp-signature':
                        return True
        else:
            payload = mail.get_payload()
            if mail.get_content_type()!='text/plain' or len(payload)<=10:
                return False
            # handle inline signature; message
            firstline = payload.splitlines()[0]
            if firstline=='-----BEGIN PGP SIGNED MESSAGE-----': return True
        return False

    @staticmethod
    def _signature(mail):
        from .mail import as_protected, _mail_transfer_content, protect_mail
        from sys import version_info as vs
        payload = ''
        signatures = []
        rawmail = mail
        mail = as_protected(mail)
        fix_nl = (vs[0]==2 and vs[1]*10+vs[2]<77) or (vs[0]==3 and vs[1]*10+vs[2]<35)
        if mail.is_multipart():
            rawmail = as_protected(mail,headersonly=True)
            if fix_nl: rawmail.epilogue='' # ensure final newline, workaround for http://bugs.python.org/issue14983
            if mail.get_content_type()=='multipart/signed' and mail.get_param('protocol')=='application/pgp-signature':
                # handle detached signatures, these look like:
                for submsg in mail.get_payload():
                    if submsg.get_content_type()=='application/pgp-signature':
                        signatures.append(submsg.get_payload())
                    elif not payload:
                        # yes, including headers
                        payload = submsg.as_string()
                        if submsg.is_multipart() and len(submsg.get_payload())==1:
                            submsg = submsg.get_payload()[0]
                        _mail_transfer_content(submsg,rawmail)
                        if submsg.is_multipart():
                            rawmail.set_payload(None)
                            for subsubmsg in submsg.get_payload():
                                rawmail.attach(subsubmsg)
                        else:
                            rawmail.set_payload(submsg.get_payload())
                    else:
                        # we only deal with exactly one payload part and one or more signatures parts
                        assert False, 'multipart/signed message with more than one body'
            elif mail.get_content_type()=='multipart/mixed' and not mail.get_param('protocol'):
                nonsig = []
                for submsg in mail.get_payload():
                    if submsg.get_content_type()=='application/pgp-signature':
                        signatures.append(submsg.get_payload())
                    else: nonsig.append(submsg)
                if not len(signatures): # no signature found
                    return payload, signatures, mail
                rawmail.set_payload(None)
                for submsg in nonsig:
                    if submsg.get_content_type()=='text/plain':
                        signatures = [None]
                        payload = submsg.get_payload()
                        rawmail.set_payload(payload)
                        break
                    elif not payload: # multipart?
                        # yes, including headers
                        payload = submsg.as_string()
                        _mail_transfer_content(submsg,rawmail)
                        if submsg.is_multipart():
                            rawmail.set_payload(None)
                            for subsubmsg in submsg.get_payload():
                                rawmail.attach(subsubmsg)
                        else:
                            rawmail.set_payload(submsg.get_payload())
                    else:
                        # we only deal with exactly one payload part and one or more signatures parts
                        assert False, 'multipart/mixed message with more than one body'
        else:
            payload = mail.get_payload()
            if mail.get_content_type()!='text/plain' or len(payload)<=10:
                return payload, signatures, mail # no signature
            # handle inline signature; message
            firstline = payload.splitlines()[0]
            if firstline!='-----BEGIN PGP SIGNED MESSAGE-----':
                # no signature
                return payload, signatures, mail # no inline signature
            text = ''
            for line in payload.splitlines(True)[3:]: # remove first three lines
                if line.rstrip()=='-----BEGIN PGP SIGNATURE-----': break
                text += line
            signatures = [None]
            mail.del_param("x-action")
            mail.set_payload(text.rstrip()) # remove last line separator
            rawmail = mail
        return payload, signatures, rawmail

    @staticmethod
    def _decoded(mail,plaintext,is_pgpmime):
        # Check transfer type
        from .mail import _mail_addreplace_header, _mail_transfer_content
        from .mail import protect_mail
        mail = protect_mail(mail,linesep=None)
        tmpmsg = protect_mail(plaintext,linesep=None)
        if mail.get_content_type()=='application/pgp': mail.set_type("text/plain")
        mail.del_param("x-action")
        if tmpmsg.is_multipart() and len(tmpmsg.get_payload())==1:
            tmppayload = tmpmsg.get_payload(0)
            _mail_transfer_content(tmppayload,mail)
            mail.set_payload(tmppayload.get_payload())
        else:
            _mail_transfer_content(tmpmsg,mail)
            if tmpmsg.is_multipart():
                mail.set_payload(None)
                for i in tmpmsg.get_payload(): mail.attach(i)
            else:
                tmppayload = tmpmsg.get_payload()
                mail.set_payload(tmppayload)
        return mail

    def analyze(self,mail):
        """Checks whether the email is encrypted or signed.

        :param mail: A string or email
        :returns: Whether the email is encrypted and whether it is signed (if it is not encrypted).
        :rtype: (bool,bool/None)
        """
        from email.message import Message
        from .mail import protect_mail
        if type(mail)==str: mail = protect_mail(mail,linesep=None)
        elif not isinstance(mail,Message): return False, False
        ciphertext, is_pgpmime = self._ciphertext(mail)
        if not ciphertext is None: return True, None
        if self._has_signature(mail): return False, True
        return False, False

    def strip_signature(self,mail):
        """Returns the raw email without signature. Does not check for valid signature.

        :param mail: A string or email
        :returns: An email without signature and whether the input was signed
        :rtype: (Message,bool)
        """
        from email.message import Message
        from .mail import protect_mail
        if type(mail)==str: mail = protect_mail(mail,linesep=None)
        elif not isinstance(mail,Message):
            raise TypeError("mail must be Message or str")
        payload, signatures, rawmail = self._signature(mail)
        return rawmail, len(signatures)>0

    @staticmethod
    def without_signature(data):
        "remove signature from string, if present"
        if len(data)<=10: return data # no signature
        firstline = data.splitlines()[0]
        if firstline!='-----BEGIN PGP SIGNED MESSAGE-----':
            return data # no signature
        text = ''
        for line in data.splitlines(True)[3:]: # remove first three lines
            if line.rstrip()=='-----BEGIN PGP SIGNATURE-----': break
            text += line
        return text.rstrip()

    def _check_signatures(self,payload,signatures,rawmail,strict=False):
        "returns mail without signature, whether it was signed and with which keys"
        from .mail import protect_mail, fix_lines
        results, key_ids, fingerprints = [], [], []
        signed, fmt = False, False
        payload = str(payload) # copy
        for signature in signatures:
            if signature: signature = self._fix_quoting(signature)
            for linesep in (None,'\r\n','\n'):
                if linesep:
                    tmp = fix_lines(payload,linesep=linesep)
                    if tmp==payload: continue
                else: tmp = payload
                if signature is None:
                    result = self.verify_str(tmp)
                else:
                    result = self.verify_str(tmp, signature)
                if result.key_id: signed = True
                if fmt or strict: break # already found format
                if result.valid: # found valid
                    if not fmt and linesep:
                        payload = tmp # correct format
                        rawmail = protect_mail(rawmail,linesep=linesep,sevenbit=False)
                    fmt = True
                    break
            if not result: continue # no valid signature
            key_ids.append(result.key_id)
            fingerprints.append(result.fingerprint)
            results.append(result)
        return rawmail, {'signed':signed,'fingerprints':fingerprints,'key_ids':key_ids,'results':results}

    def verify(self, mail, strict=False, valid_keys=[], passphrase=None, **kwargs):
        """Verifies the validity of the signature of an email.

        :type mail: string or Message object
        :param mail: A string or email
        :param bool strict: Whether verify the message as is. Otherwise try with different line separators.
        :param list valid_keys: keyids accepted as valid signature. By default the sender email.
        :param passphrase: The passphrase(s) for the secret key(s) used for decryption. If a list is
            specified, each passphrase will be tried until decryption succeeds.
        :type passphrase: str or list of str
        :returns: whether the input was signed by the sender and detailed results
             (whether it was 'encrypted',the 'decryption' results, whether it was 'signed',
             the verification 'results' and valid 'key_ids'/'fingerprints')
        :rtype: (bool,{encrypted:bool,signed:bool,fingerprints:list,key_ids:list,decryption:dict,results:list of dicts})

        RFC1847 2.1 requires no modification of signed payloads, but some MTA change the line separators,
        which breaks the signature. With strict=False it is also checked, whether the signature would
        be valid after conversion to full CR/LF or LF.
        """
        mail, valid, results = self.decrypt(mail,strict,valid_keys,passphrase, **kwargs)
        return valid, results

    def decrypt(self, mail, strict=False, valid_keys=[], passphrase=None, **kwargs):
        """Decrypts and verifies an email.

        :param mail: A string or email
        :type mail: string or Message object
        :param bool strict: Whether verify the message as is. Otherwise try with different line separators.
        :param list valid_keys: keyids accepted as valid signature. By default the sender email.
        :param passphrase: The passphrase(s) for the secret key(s) used for decryption. If a list is
            specified, each passphrase will be tried until decryption succeeds.
        :type passphrase: str or list of str
        :returns: An email without signature (None if the decryption failed),
             whether the input was signed by at least one valid key and detailed results
             (whether it was 'encrypted',the 'decryption' results, whether it was 'signed',
             the decryption 'results' and valid 'key_ids'/'fingerprints')
        :rtype: (Message,bool,{encrypted:bool,signed:bool,key_ids:list,decryption:dict,results:list of dicts})

        RFC1847 2.1 requires no modification of signed payloads, but some MTA change the line separators,
        which breaks the signature. With strict=False it is also checked, whether the signature would
        be valid after conversion to full CR/LF or LF.
        """
        results = {'encrypted':False,'decryption':None,'signed':False,
                    'fingerprints':[],'key_ids':[],'results':[]}
        # possible encryptions: nothing,only signed, encrypted+signed, encrypted after signed 
        from email.message import Message
        from .mail import protect_mail
        import email.utils, six
        if isinstance(mail, six.string_types):
            mail = protect_mail(mail,linesep=None)
        elif not isinstance(mail,Message):
            raise TypeError("mail must be Message or str")
        from email.header import decode_header
        if not valid_keys:
            sender = mail.get('from', [])
            sender = email.utils.parseaddr(decode_header(sender)[0][0])[1]
            valid_keys = [self.find_key(sender)]
        else:
            valid_keys = [self.find_key(keyid) for keyid in valid_keys]
        ciphertext, is_pgpmime = self._ciphertext(mail)
        if ciphertext: # Ciphertext present? Decode
            results['encrypted'] = True
            ciphertext = self._fix_quoting(ciphertext)
            if passphrase is None and self.default_key:
                passphrase = self.default_key[1]
            if not type(passphrase) in (tuple,list):
                passphrase = [passphrase]
            for pp in passphrase:
                result = self.decrypt_str(ciphertext, passphrase=pp, **kwargs)
                if result.ok: break
            results['decryption'] = result
            if not result.ok:
                results['signed'] = None # unknown
                return None, False, results # cannot decrypt
            if result.key_id: results['signed'] = True
            plaintext = str(result)
            mail = self._decoded(mail,plaintext,is_pgpmime)
            if result.valid:
                results['fingerprints'] = [result.fingerprint]
                results['key_ids'] = [result.key_id]
                results['results'] = [result]
                if result.fingerprint in valid_keys: return mail, True, results
        payload, signatures, rawmail = self._signature(mail)
        if not payload: return rawmail, False, results # no plain msg
        rawmail, sresults = self._check_signatures(payload, signatures, rawmail, strict=strict)
        if sresults['signed']: results['signed'] = True
        results['fingerprints'].extend(sresults['fingerprints'])
        results['key_ids'].extend(sresults['key_ids'])
        results['results'].extend(sresults['results'])
        valid = results['signed'] and len(set(valid_keys).intersection(results['fingerprints']))
        return rawmail, valid, results

    def sign(self, mail, inline=False, signers=None, passphrase=None, verify=False, **kwargs):
        """Signs an email with the default_key if specified, otherwise the sender's (From) signature.

        :param mail: A string or email
        :type mail: string or Message object
        :param bool inline: Whether to use the PGP inline format for messages with attachments, i.e. no multipart.
        :param signers: Optional keyid(s) to sign with. By default the sender (From).
        :type str or list of str
        :param bool verify: Whether to verify the signed mail immediately
        :returns: The signed email (None if it fails) and the sign details.
        :rtype: (Message,dict)
        """
        signers = True if signers is None else signers
        return self._encrypt(mail, encrypt=False, sign=signers, inline=inline,
            passphrase=passphrase, verify=verify, **kwargs)

    def encrypt(self, mail, sign=True, inline=False, recipients=None, toself=True, passphrase=None,
         verify=False, **kwargs):
        """Encrypts an email for the recipients and optionally signs it.

        :param mail: A string or email
        :type mail: string or Message object
        :param sign: Optional keyid(s) to sign with. If true, uses to the sender (From).
        :type sign: bool or str or list
        :param bool inline: Whether to use the PGP inline format for non-multipart messages.
        :param recipients: List of keyids to encrypt for. By default the addresses in To/CC.
        :type recipients: list or None
        :param toself: Whether to add sender to the recipients for self-decryption.
        :type toself: bool
        :param bool verify: Whether to verify the encrypted mail immediately (toself must be enabled or recipient key be known).
        :returns: The encrypted email (None if it fails) and the encryption details.
        :rtype: (Message,dict)
        """
        return self._encrypt(mail, encrypt=True, sign=sign, inline=inline, recipients=recipients,
             toself=toself, passphrase=passphrase, verify=verify, **kwargs)

    def _encrypt(self, mail, encrypt=True, sign=True, inline=False, recipients=None, toself=True,
         passphrase=None, verify=False, **kwargs):
        import email.utils, six
        from email.header import decode_header
        from email.message import Message
        from .mail import _mail_addreplace_header, protect_mail, as_protected
        def find_sender(mail):
            sender = mail.get('from', [])
            sender = email.utils.parseaddr(decode_header(sender)[0][0])[1]
            sender = self.find_key(sender,secret=True)
            if not sender: raise KeyMissingError("sender")
            return sender

        if not isinstance(mail,(Message,)+six.string_types):
            raise TypeError("mail must be Message or str")
        if encrypt:
            mail = protect_mail(mail,linesep=None)
            if not recipients:
                tos = mail.get_all('to', []) + mail.get_all('cc', [])
                recipients = [self.find_key( email.utils.parseaddr(decode_header(to)[0][0])[1] ) for to in tos]
            else:
                recipients = [self.find_key( keyid ) for keyid in recipients]
            if None in recipients:
                raise KeyMissingError("public keys for recipients")
            if sign==True or toself: sender = find_sender(mail)
            if toself and not sender in recipients: recipients.append(sender)
        else:
            mail = protect_mail(mail,linesep='\r\n',sevenbit=True) # fix line separators + 7bit RFC2822
            if sign==True: sender = find_sender(mail)
        if sign:
            if sign==True:
                sign = sender
                if not passphrase and self.default_key and self.default_key[0]==sign:
                    passphrase = self.default_key[1]
            assert not type(sign) in (tuple,list), "multiple signers not yet supported"
            kwargs['default_key'] = sign
            kwargs['passphrase'] = passphrase
        plaintext, submsg = self._plaintext(mail, inline)
        if encrypt:
            # Do encryption, report errors
            try: result = self._encrypt_str(plaintext, recipients, armor=True, **kwargs)
            except: return None, None
            if not result: return None, result
            payload = str(result)
            if verify and toself:
                if sign: del kwargs['default_key']
                if self.default_key and kwargs.get('passphrase') is None:
                    kwargs['passphrase']= self.default_key[1]
                vresult = self.decrypt_str(payload, **kwargs)
                if not vresult.ok or (sign and not vresult.valid): return None, result
        else:
            # Generate signature, report errors
            try:
                if not mail.is_multipart() and inline:
                    result = self._sign_str(plaintext, clearsign=True, detach=False, **kwargs)
                else:
                    result = self._sign_str(plaintext, clearsign=False, detach=True, **kwargs)
            except: return None, None
            if not result: return None, result
            payload = str(result) #signature
            if verify:
                if not mail.is_multipart() and inline:
                    vresult = self.verify_str(payload)
                else:
                    vresult = self.verify_str(submsg.as_string(),payload)
                if not vresult.valid: return None, result
        # Compile encrypted message
        if not mail.is_multipart() and inline:
            mail.set_payload(payload)
            if encrypt:
                _mail_addreplace_header(mail,'Content-Transfer-Encoding','7bit')
                mail.set_param('x-action','pgp-encrypted')
            else:
                mail.set_param('x-action','pgp-signed')
        else:
            # workaround to preserve header order
            tmp = Message()
            tmp['Content-Type'] = mail['Content-Type']
            if encrypt:
                tmp.set_type('multipart/encrypted')
                tmp.set_param('protocol','application/pgp-encrypted')
            else:
                tmp.set_type('multipart/signed')
                tmp.del_param('boundary') # delete boundary as we need a new one
                tmp.set_param('protocol','application/pgp-signature')
                tmp.set_param('micalg','pgp-sha1;')
            mail.replace_header('Content-Type',tmp['Content-Type'])
            if six.PY3: mail = as_protected(mail,headersonly=True)
            mail.set_payload(None)
            if encrypt:
                mail.preamble = 'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'
                submsg = Message()
                submsg.add_header('Content-Type','application/pgp-encrypted')
                submsg.set_payload('Version: 1\n')
                mail.attach(submsg)
                submsg = Message()
                submsg.add_header('Content-Type','application/octet-stream; name="encrypted.asc"')
                submsg.add_header('Content-Description', 'OpenPGP encrypted message')
                submsg.add_header('Content-Disposition','inline; filename="encrypted.asc"')
                submsg.set_payload(payload)
                mail.attach(submsg)
            else:
                mail.preamble = 'This is an OpenPGP/MIME signed message (RFC 4880 and 3156)'
                assert submsg.as_string()==plaintext, "plaintext was broken"
                mail.attach(submsg)
                submsg = Message()
                submsg.add_header('Content-Type','application/pgp-signature; name="signature.asc"')
                submsg.add_header('Content-Description', 'OpenPGP digital signature')
                submsg.add_header('Content-Disposition','attachment; filename="signature.asc"')
                submsg.set_payload(payload)
                mail.attach(submsg)
        return mail, result

def find_gnupg_key(gpg,addr,secret=False,key_ids=False):
    """find keyid for email 'addr' or return None.
    If addr is a list or tuple, return a dict(addr:fingerprint) """
    import email.utils
    if type(addr) in (list,tuple):
        result = {}
        for a in addr: result[a] = find_gnupg_key(gpg,a,secret)
        return result
    from email.header import decode_header
    addr = decode_header(addr)[0][0]
    addr = email.utils.parseaddr(addr)[1]
    if not addr: return None
    for key in gpg.list_keys(secret):
        for uid in key['uids']:
            if uid.find(addr)>=0:
                if key_ids: return key['keyid']
                return key['fingerprint']
    return None

class GPGMIME(PGPMIME):
    "A PGP implementation based on GNUPG and the gnupg module"

    def __init__(self, gpg, default_key=None):
        "initialize with a gnupg instance and optionally a default_key (keyid,passphrase) tuple"
        from six import string_types
        self.gpg = gpg
        if not default_key: pass
        elif isinstance(default_key, string_types):
            defkey = self.find_key(default_key,secret=True)
            if defkey: default_key = (defkey, None)
        elif len(default_key)==2 and default_key[0]:
            defkey = self.find_key(default_key[0],secret=True)
            if defkey: default_key = (defkey,default_key[1])
        else: assert False, "default_key must be keyid or (keyid,passphrase)"
        super(GPGMIME,self).__init__(default_key)

    def _set_default_key(self,kwargs):
        if not 'default_key' in kwargs: return kwargs
        key = kwargs['default_key']
        if not key:
            del kwargs['default_key']
            return kwargs
        if key!=True:
            key = self.find_key(key,secret=True) or key
            kwargs['default_key'] = key
        else: assert self.default_key, "default key missing"
        if self.default_key:
            defkey,passphrase = self.default_key
            if key!=True:
                if key != defkey: return kwargs
            else: kwargs['default_key'] = defkey
            if kwargs.get('passphrase') is None and passphrase:
                kwargs['passphrase'] = passphrase
        return kwargs

    def find_key(self,addr,secret=False):
        """find keyid for email 'addr' or return None.
        If addr is a list or tuple, return a dict(addr:keyid) """
        return find_gnupg_key(self.gpg,addr,secret)

    def pubkey_attachment(self,key=None): # pragma: no cover
        "returns an attachment with the specified public key (default key if none specified)"
        from email.mime.text import MIMEText
        if not key:
            key = self.default_key
            if type(key)==tuple: key = key[0]
        key = self.find_key(key) or key
        pubkey = self.gpg.export_keys(key)
        attach = MIMEText(pubkey)
        attach.set_type("application/pgp-keys")
        fname= key+'.asc'
        attach.set_param('name',fname)
        attach.add_header('Content-Disposition', 'attachment', filename=fname)
        return attach

    def _sign_params(self, sign, kwargs):
        if sign==True or sign is None:
            if not self.default_key: raise KeyMissingError("sender")
            sign = self.default_key[0]
        elif sign:
            assert not type(sign) in (tuple,list), "multiple signers not yet supported"
            sign = self.find_key(sign)
            if not sign: raise KeyMissingError("sender")
        if sign:
            kwargs['default_key'] = sign
            if kwargs.get('passphrase') is None and self.default_key and self.default_key[0]==sign:
                kwargs['passphrase'] = self.default_key[1]
        return kwargs

    def sign_file(self, file, signers=None, **kwargs):
        return self.gpg.sign(file, **self._sign_params(signers, kwargs))

    def sign_str(self, data, signers=None, **kwargs):
        return self.gpg.sign(data, **self._sign_params(signers, kwargs))

    def _sign_str(self, data, **kwargs):
        return self.gpg.sign(data, **kwargs)

    def verify_file(self, file, signature=None):
        return self.gpg.verify_file(file,signature)

    def verify_str(self, data, signature=None):
        import gnupg
        f = gnupg._util._make_binary_stream(data, self.gpg._encoding)
        if signature:
            import os, tempfile
            tmp = tempfile.NamedTemporaryFile(mode='w+',prefix='gnupg',delete=False)
            fd, fn = tmp.file, tmp.name
            fd.write(signature)
            fd.close()
            try: result = self.gpg.verify_file(f,fn)
            finally: os.unlink(fn)
        else:
            result = self.gpg.verify_file(f)
            f.close()
        return result

    def _encrypt_params(self, recipients, sign, kwargs):
        recipients = [self.find_key( keyid ) for keyid in recipients]
        if None in recipients: raise KeyMissingError("public keys for recipients")
        kwargs = self._sign_params(sign, kwargs)
        return recipients, kwargs

    def encrypt_file(self, file, recipients, sign=True, **kwargs):
        recipients, kwargs = self._encrypt_params(recipients, sign, kwargs)
        return self.gpg._encrypt(file, recipients, **kwargs)

    def encrypt_str(self, data, recipients, sign=True, **kwargs):
        recipients, kwargs = self._encrypt_params(recipients, sign, kwargs)
        return self.gpg.encrypt(data, *recipients, **kwargs)

    def _encrypt_str(self, data, recipients, **kwargs):
        return self.gpg.encrypt(data, *recipients, **kwargs)

    def decrypt_file(self, file, **kwargs):
        if 'passphrase' not in kwargs and self.default_key:
            kwargs['passphrase'] = self.default_key[1]
        return self.gpg.decrypt_file(file, **kwargs)

    def decrypt_str(self, data, **kwargs):
        if 'passphrase' not in kwargs and self.default_key:
            kwargs['passphrase'] = self.default_key[1]
        return self.gpg.decrypt(data, **kwargs)
