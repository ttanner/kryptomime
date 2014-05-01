# -*- coding: utf-8 -*-
#
# E-Mail stuff
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

def fix_lines(text,ending='\n',replace=True,final=True):
    "fix line ending in text: 'replace' all or not, ensure 'final' line ending"
    if not text or not ending: return text
    if replace:
        if ending=='\n':
            text = text.replace('\r\n','\n')
        elif ending=='\r\n':
            text = text.replace('\r\n','\n').replace('\n','\r\n')
    if not final: return text
    return text.rstrip()+ending

from email.message import Message

class ProtectedMessage(Message):
    "A Message object with specified line endings and which preserves the original header"
    def __init__(self):
        Message.__init__(self)
        self.ending = None
    def as_string(self, unixfrom=False):
        return _mail_raw(self,unixfrom=unixfrom,ending=self.ending)

def _mail_raw(mail,ending=None,unixfrom=False):
    "workaround email problem (headers are left untouched only for multipart/signed but not its payloads)"
    from email.generator import Generator
    from six.moves import cStringIO
    fp = cStringIO()
    g = Generator(fp,maxheaderlen=0,mangle_from_=False)
    g.flatten(mail,unixfrom)
    s = fp.getvalue()
    if ending: return fix_lines(s,ending=ending)
    return s

def _mail_addreplace_header(msg,key,value):
    if key in msg: msg.replace_header(key,value)
    else: msg.add_header(key,value)

def _mail_transfer_content(src,dest):
    for key in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
        if not key in src: continue
        _mail_addreplace_header(dest,key,src.get(key))

def as_protected(txt,ending=None,headersonly=False):
    "convert txt to a protected message without modifying the subparts"
    from email.parser import HeaderParser, Parser
    P = HeaderParser if headersonly else Parser
    if isinstance(txt,ProtectedMessage):
        if (not ending or ending==txt.ending) and not headersonly: return txt
        txt = txt.as_string()
    elif isinstance(txt,Message): txt = _mail_raw(txt)
    if not ending: # autodetect CRLF or LF
        i = txt.find('\n')
        if i>0 and txt[i-1]=='\r': ending='\r\n' #CRLF
        else: ending='\n' # default LF
    mail = P(_class=ProtectedMessage).parsestr(txt)
    mail.ending = ending
    return mail

def protect_mail(mail,ending='\r\n',sevenbit=True):
    "convert mail and subparts to ProtectedMessage, convert payloads to 7bit and CRLF"
    from email.parser import Parser
    from email.encoders import encode_quopri
    import copy

    def toseven(msg):
        try: msg.get_payload().encode('ascii')
        except UnicodeError: encode_quopri(msg)
        else:
            enc = 'Content-Transfer-Encoding'
            if not enc in msg: msg.add_header(enc,'7bit')

    mail = as_protected(mail,ending=ending)
    if mail.is_multipart():
        converted = []
        for submsg in mail.get_payload():
            if submsg.is_multipart():
                submsg = protect_mail(submsg,ending,sevenbit)
            else:
                if sevenbit: toseven(submsg)
                if ending: submsg = as_protected(submsg,ending=ending)
            converted.append(submsg)
        mail.set_payload(None)
        for submsg in converted: mail.attach(submsg)
    else:
        if sevenbit: toseven(mail)
        if ending: mail.set_payload(fix_lines(mail.get_payload(),ending=ending))
    return mail

def create_mail(sender,to,subject,body,cc='',attach=None,time=None,headers={}):
    """create an email with sender 'sender', receivers 'to', subject and body,
     optional CC, attachments, extra headers and time"""
    import email.mime.text, email.mime.multipart, email.utils
    import time as time_mod
    from six import iteritems
    msg = email.mime.text.MIMEText(fix_lines(body,replace=False))
    if not attach is None:
        mmsg = email.mime.multipart.MIMEMultipart()
        mmsg.attach(msg)
        for msg in attach: mmsg.attach(msg)
        msg = mmsg
    msg.set_unixfrom(sender)
    msg['From'] = sender
    msg['To'] = to
    if cc: msg['CC'] = cc
    msg['Subject'] = subject
    if not time: time = time_mod.time()
    msg['Date'] = email.utils.formatdate(time,localtime=True)
    for k, v in iteritems(headers):
        if k.lower()=='content-type':
            msg.set_type(v)
        elif msg.has_key(k):
            msg.replace_header(k,v)
        else:
            msg.add_header(k,v)
    return msg

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
