# -*- coding: utf-8 -*-
#
# Workarounds for the broken Python email package
#
# This file is part of kryptomime, a Python module for email kryptography.
# Copyright © 2013-2015 Thomas Tanner <tanner@gmx.net>
# 
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
# 
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included GNU Lesser General
# Public License file for details.
# 
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
# For more details see the file COPYING.

def fix_lines(text,linesep='\n',replace=True,final=False):
    "fix line separators in text: 'replace' all or not, ensure 'final' line separator"
    if not text or not linesep: return text
    if replace:
        if linesep=='\n':
            text = text.replace('\r\n','\n')
        elif linesep=='\r\n':
            text = text.replace('\r\n','\n').replace('\n','\r\n')
    if not final: return text
    return text.rstrip()+linesep

def get_linesep(mail):
    "autodetect CRLF or LF in str"
    import six
    if six.PY3 and isinstance(mail,six.binary_type):
        mail = mail.decode('utf-8','ignore')
    i = mail.find('\n')
    if i>0 and mail[i-1]=='\r': return '\r\n' #CRLF
    return '\n' # default LF

import six
from email.message import Message

if six.PY2:
    from email.generator import Generator

    class CharsetGenerator(Generator):

        def __init__(self, outfp, mangle_from_=True, maxheaderlen=78, charset=None):
            Generator.__init__(self, outfp, mangle_from_, maxheaderlen)
            self.charset = charset

        def _write_headers(self, msg): # pragma: no cover
            for h, v in msg.items():
                print >> self._fp, '%s:' % h,
                if self._maxheaderlen == 0:
                    # Explicit no-wrapping
                    print >> self._fp, v
                elif isinstance(v, Header):
                    # Header instances know what to do
                    print >> self._fp, v.encode()
                elif _is8bitstring(v):
                    # If we have raw 8bit data in a byte string, we have no idea
                    # what the encoding is.  There is no safe way to split this
                    # string.  If it's ascii-subset, then we could do a normal
                    # ascii split, but if it's multibyte then we could break the
                    # string.  There's no way to know so the least harm seems to
                    # be to not split the string and risk it being too long.
                    print >> self._fp, v
                else:
                    # Header's got lots of smarts, so use it.  Note that this is
                    # fundamentally broken though because we lose idempotency when
                    # the header string is continued with tabs.  It will now be
                    # continued with spaces.  This was reversedly broken before we
                    # fixed bug 1974.  Either way, we lose.
                    print >> self._fp, Header(v, maxlinelen=self._maxheaderlen, 
                        header_name=h, charset=self.charset).encode()
            # A blank line always separates headers from body
            print >> self._fp

    class ProtectedMessage(Message):
        "A Message object with specified line separators and which preserves the original header"

        def __init__(self):
            Message.__init__(self)
            self._linesep = None

        def as_string(self, unixfrom=False):
            return mail_binary(self,unixfrom=unixfrom,
                linesep=self._linesep,charset=self._charset)

        as_bytes = as_string # py3 compatibility

    def mail_binary(mail,linesep=None,unixfrom=False,charset=None):
        "generate 8bit byte str representation of email"
        # work around email problem (headers are left untouched only
        # for multipart/signed but not its payloads)
        from cStringIO import StringIO
        fp = StringIO()
        g = CharsetGenerator(fp,maxheaderlen=0,mangle_from_=False,charset=charset)
        g.flatten(mail,unixfrom)
        s = fp.getvalue()
        if linesep: return fix_lines(s,linesep=linesep)
        return s

else:
    from email.generator import BytesGenerator
    ProtectedMessage = Message

    class CharsetGenerator(BytesGenerator):
        def flatten(self, msg, unixfrom=False, linesep=None):
            from email.charset import Charset
            charset = msg.get_content_charset()
            self._encoding = str(charset) if type(charset)==Charset else charset
            super().flatten(msg, unixfrom, linesep)
        def write(self, s):
            self._fp.write(self._encode(s))
        def _new_buffer(self):
            from io import BytesIO
            return BytesIO()
        def _encode(self, s):
            encoding = self._encoding or 'utf-8'
            return s.encode(encoding,'surrogateescape')

    def mail_binary(mail,linesep=None,unixfrom=False):
        "generate 8bit byte str representation of email"
        if mail.policy.cte_type=='7bit':
            return mail.as_string()
        from io import BytesIO
        with BytesIO() as fp:
            g = CharsetGenerator(fp,maxheaderlen=0,mangle_from_=False, policy=mail.policy)
            g.flatten(mail, unixfrom=unixfrom, linesep=linesep)
            return fp.getvalue()

def _mail_addreplace_header(msg,key,value):
    if key in msg: msg.replace_header(key,value)
    else: msg.add_header(key,value)

def _mail_transfer_content(src,dest):
    for key in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
        if not key in src: continue
        _mail_addreplace_header(dest,key,src.get(key))

def _protected(txt,linesep=None,headersonly=False,template=None,cte_type='7bit'):
    "convert txt to a protected message without modifying the subparts"
    from email.parser import Parser
    from email.message import Message

    if six.PY3:
        from email.policy import default
        if isinstance(txt,Message):
            if not headersonly:
                if not linesep or linesep==txt.policy.linesep:
                    import copy
                    return copy.deepcopy(txt)
                return protect_mail(txt,linesep)
            txt = mail_binary(txt)
        if linesep is None: linesep = get_linesep(txt)
        policy = default.clone(linesep=linesep,cte_type=cte_type)
        if not template: template = Message
        if isinstance(txt,bytes):
            from email.parser import BytesParser
            return BytesParser(policy=policy,_class=template).parsebytes(txt,headersonly)
        return Parser(policy=policy,_class=template).parsestr(txt,headersonly)

    if isinstance(txt,ProtectedMessage):
        if not headersonly and (not linesep or linesep==txt._linesep):
            import copy
            return copy.deepcopy(txt)
        charset = txt._charset
        txt = txt.as_string()
    elif isinstance(txt,Message):
        charset = txt.get_content_charset()
        txt = mail_binary(txt)
    else: charset = None
    if linesep is None: linesep = get_linesep(txt)
    else: txt = fix_lines(txt,linesep) # convert lineseps
    if not template: template = ProtectedMessage
    from email.parser import HeaderParser
    P = HeaderParser if headersonly else Parser
    mail = P(_class=template).parsestr(txt)
    if not charset: charset = mail.get_content_charset()
    if charset:
        # cannot use mail.set_charset(charset), as it adds MIME-Version header
        mail._charset = charset
    mail._linesep = linesep
    return mail

def protect_mail(mail,linesep='\r\n',sevenbit=True):
    "convert mail and subparts to ProtectedMessage, convert payloads to 7bit and CRLF"
    from email.message import Message
    from email.parser import Parser
    from email.encoders import encode_quopri
    import copy, six

    def fix_encoding(msg):
        cte = 'Content-Transfer-Encoding'
        if msg[cte] == '8bit' and msg.get_content_maintype()=='text' and msg.get_charset() is None:
            charset = msg.get_content_charset()
            if not charset: return #broken
            payload = msg.get_payload(decode=False)
            msg.set_payload(payload)
            msg.set_charset(charset)
        if not sevenbit: return
        try: msg.get_payload().encode('ascii')
        except UnicodeError: encode_quopri(msg)
        else:
            if not cte in msg: msg.add_header(cte,'7bit')

    if six.PY3:
        from email.policy import default
        cte_type='7bit' if sevenbit else '8bit'
        if not isinstance(mail,Message):
            mail = _protected(mail,linesep=linesep,cte_type=cte_type)
            linesep = mail.policy.linesep
        elif not linesep:
            linesep = get_linesep(mail.as_string())
        policy = default.clone(linesep=linesep,cte_type=cte_type)
        mail = copy.deepcopy(mail)
        mail.policy = policy
    else:
        mail = _protected(mail,linesep=linesep)
        linesep = mail._linesep # get new or original lineseps
    if mail.is_multipart():
        converted = []
        for submsg in mail.get_payload():
            if submsg.is_multipart():
                submsg = protect_mail(submsg,linesep,sevenbit)
            else:
                fix_encoding(submsg)
                submsg = _protected(submsg,linesep=linesep)
            converted.append(submsg)
        mail.set_payload(None)
        for submsg in converted: mail.attach(submsg)
    else:
        fix_encoding(mail)
        if linesep:
            payload = mail.get_payload()
            if isinstance(payload,six.string_types):
                mail.set_payload(fix_lines(payload,linesep=linesep))
    return mail

def check_charset(s, charset=None, use_locale=True):
    "check or autodetect the charset of str s"
    from six import PY3
    from locale import getpreferredencoding
    import codecs
    # work around gnupg workaround :/
    codecs.register_error('strict', codecs.strict_errors)
    if PY3:
        if charset:
            if type(s)==str: s.encode(charset)
            else: s.decode(charset)
            return s, charset
        try: return check_charset(s, 'us-ascii')
        except UnicodeEncodeError: pass
        if use_locale: # pragma: no cover
            charset = getpreferredencoding(True)
            try: return check_charset(s, charset)
            except UnicodeEncodeError: pass
        return check_charset(s, 'UTF-8')
    if type(s)==unicode:
        if charset:
            return s.encode(charset), charset
        charset = 'us-ascii'
        try: return s.encode(charset), charset
        except UnicodeEncodeError: pass
        if use_locale: # pragma: no cover
            charset = getpreferredencoding(True)
            try: return s.encode(charset), charset
            except UnicodeEncodeError: pass
        charset = 'UTF-8'
        return s.encode(charset), charset
    if charset:
        s.decode(charset)
        return s, charset
    charset = 'us-ascii'
    try:
        s.decode(charset)
        return s, charset
    except UnicodeDecodeError: pass
    if use_locale:
        charset = getpreferredencoding(True)
        try:
            s.decode(charset)
            return s, charset
        except UnicodeDecodeError: pass
    charset = 'UTF-8'
    s.decode(charset)
    return s, charset

def mail_payload(msg, i=None):
    """get decoded mail payload(s). i is the index or None for all payloads.
    8bit non-text is converted to bytes"""
    from email.message import Message
    if not isinstance(msg, Message):
        msg = protect_mail(msg,linesep=None,sevenbit=False)
    if msg.is_multipart() and i is None:
        return [mail_payload(submsg) for submsg in msg.get_payload()]
    charset = msg.get_content_charset()
    ctype = msg.get_content_maintype()
    if (six.PY3 and ctype=='text' and
        msg['Content-Transfer-Encoding'].lower() in ('8bit','binary')):
        payload = msg.get_payload(i, decode=False)
    else:
        payload = msg.get_payload(i, decode=True)
        if not charset is None:
            payload = payload.decode(str(charset))
    return payload

def _set_header(msg,key,value,charset=None):
    from email.header import Header
    value, charset = check_charset(value, charset)
    if charset!='us-ascii': value = Header(value, charset).encode()
    if key.lower()=='content-type':
        msg.set_type(value)
    elif key in msg:
        msg.replace_header(key,value)
    else:
        msg.add_header(key,value)

def create_mime(data,maintype='text',subtype=None,charset=None,
    params={}, headers={}, encoding=None):
    """ create MIME message from data.
    if maintype is None, the default content type is text/plain for str,
     and application/octet-stream for binary data.
    The default charset and encoding are automatically detected.
    """
    from email.mime.base import MIMEBase
    from email.mime.application import MIMEApplication
    from email.mime.audio import MIMEAudio
    from email.mime.image import MIMEImage
    from email.mime.message import MIMEMessage
    from email.mime.text import MIMEText
    import email.encoders, six
    if maintype is None:
        if isinstance(data,(six.text_type,)+six.string_types):
            maintype= 'text'
        elif isinstance(data,six.binary_type):
            maintype,subtype = 'application', subtype or 'octet-stream'
    else:
        maintype = maintype.lower()
    cte = 'Content-Transfer-Encoding'
    if maintype=='text':
        subtype = subtype or 'plain'
        data, charset = check_charset(data,charset)
        if encoding is None:
            msg = MIMEText(data, subtype, charset)
        else:
            msg = MIMEText('', subtype, charset)
        if encoding in ('base64','quoted-printable'):
            del msg[cte]
            if not isinstance(data,six.binary_type): data = data.encode(charset)
            msg.set_payload(data)
            if encoding=='base64': email.encoders.encode_base64(msg)
            else: email.encoders.encode_quopri(msg)
        elif encoding:
            if six.PY3:
                from email.policy import default
                policy = default.clone(cte_type='8bit' if encoding=='8bit' else '7bit')
                msg.policy = policy
            msg.replace_header(cte,encoding)
            if encoding=='7bit' and charset!='us-ascii':
                raise UnicodeEncodeError
            if six.PY3 and isinstance(data,six.binary_type): data = data.decode(charset)
            msg.set_payload(data)
        if msg[cte]=='base64': # remove superflous newline
            data = msg.get_payload(decode=False)
            msg.set_payload(data.rstrip())
    else:
        idata = data if encoding else ''
        if maintype=='application': msg = MIMEApplication(idata, subtype, **params)
        elif maintype=='audio': msg = MIMEAudio(idata, subtype, **params)
        elif maintype=='image': msg = MIMEImage(idata, subtype, **params)
        elif maintype=='message': msg = MIMEMessage(idata, subtype)
        else:
            msg = MIMEBase(maintype, subtype, **params)
            encoding = encoding or 'base64'
        if encoding in ('base64','quoted-printable'):
            del msg[cte]
            msg.set_payload(data)
            if encoding=='base64': email.encoders.encode_base64(msg)
            else: email.encoders.encode_quopri(msg)
        elif encoding:
            if six.PY3:
                from email.policy import default
                policy = default.clone(cte_type='7bit' if encoding=='7bit' else '8bit')
                msg.policy = policy
            msg.replace_header(cte,encoding)
            if encoding=='7bit':
                if isinstance(data,six.string_types): data.encode('us-ascii')
                else: data.decode('us-ascii')
            if six.PY3 and isinstance(data,six.binary_type):
                data = data.decode('utf-8','surrogateescape')
            msg.set_payload(data)
        if msg[cte]=='base64': # remove superflous newline
            data = msg.get_payload(decode=False)
            msg.set_payload(data.rstrip())
    for k, v in six.iteritems(headers):
        _set_header(msg,k,v)
    return msg

def create_mail(sender,to,subject,body,cc=None,bcc=None,
    attach=None,time=None,subtype='plain',headers={},charset=None,encoding=None):
    """create an email with sender 'sender', receivers 'to', subject and body,
     optional CC, BCC, attachments, extra headers and time"""
    import email.mime.text, email.mime.multipart, email.utils
    import time as time_mod
    import six

    if attach: assert isinstance(attach,(list,tuple)), "attach must be a list"
    body = fix_lines(body,replace=False)
    msg = create_mime(body,subtype=subtype,charset=charset,encoding=encoding)
    if not attach is None:
        mmsg = email.mime.multipart.MIMEMultipart()
        mmsg.attach(msg)
        for msg in attach: mmsg.attach(msg)
        msg = mmsg
    msg.set_unixfrom(email.utils.parseaddr(sender)[1])
    _set_header(msg,'From',sender)
    _set_header(msg,'To',to)
    if cc: _set_header(msg,'CC',cc)
    if bcc: _set_header(msg,'BCC',bcc)
    _set_header(msg,'Subject',subject)
    if not time: time = time_mod.time()
    if not isinstance(time,six.string_types):
        time = email.utils.formatdate(time,localtime=True)
    msg['Date'] = time
    for k, v in six.iteritems(headers):
        _set_header(msg,k,v)
    return msg
