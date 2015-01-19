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

# workarounds for the totally broken Python email package

import six

if six.PY2:
    from email.message import Message
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
            return _mail_raw(self,unixfrom=unixfrom,linesep=self._linesep,charset=self._charset)

    def _mail_raw(mail,linesep=None,unixfrom=False,charset=None):
        """work around email problem (headers are left untouched only
        for multipart/signed but not its payloads)"""
        from six.moves import cStringIO
        fp = cStringIO()
        g = CharsetGenerator(fp,maxheaderlen=0,mangle_from_=False,charset=charset)
        g.flatten(mail,unixfrom)
        s = fp.getvalue()
        if linesep: return fix_lines(s,linesep=linesep)
        return s

def _mail_addreplace_header(msg,key,value):
    if key in msg: msg.replace_header(key,value)
    else: msg.add_header(key,value)

def _mail_transfer_content(src,dest):
    for key in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
        if not key in src: continue
        _mail_addreplace_header(dest,key,src.get(key))

def get_linesep(mail): # autodetect CRLF or LF
    i = mail.find('\n')
    if i>0 and mail[i-1]=='\r': return '\r\n' #CRLF
    return '\n' # default LF

def as_protected(txt,linesep=None,headersonly=False,template=None):
    "convert txt to a protected message without modifying the subparts. only for internal use!"
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
            txt = txt.as_string()
        if not linesep: linesep = get_linesep(txt)
        policy = default.clone(linesep=linesep)
        if not template: template = Message
        return Parser(policy=policy,_class=template).parsestr(txt,headersonly)

    if isinstance(txt,ProtectedMessage):
        if not headersonly and (not linesep or linesep==txt._linesep):
            import copy
            return copy.deepcopy(txt)
        txt = txt.as_string()
    elif isinstance(txt,Message): txt = _mail_raw(txt)
    if not linesep: linesep = get_linesep(txt)
    else: txt = fix_lines(txt,linesep) # convert lineseps
    if not template: template = ProtectedMessage
    from email.parser import HeaderParser
    P = HeaderParser if headersonly else Parser
    mail = P(_class=template).parsestr(txt)
    mail._linesep = linesep
    return mail

def protect_mail(mail,linesep='\r\n',sevenbit=True):
    "convert mail and subparts to ProtectedMessage, convert payloads to 7bit and CRLF"
    from email.message import Message
    from email.parser import Parser
    from email.encoders import encode_quopri
    import copy, six

    def to7bit(msg):
        try: msg.get_payload().encode('ascii')
        except UnicodeError: encode_quopri(msg)
        else:
            enc = 'Content-Transfer-Encoding'
            if not enc in msg: msg.add_header(enc,'7bit')

    if six.PY3:
        from email.policy import default
        if not isinstance(mail,Message):
            mail = as_protected(mail,linesep)
            linesep = mail.policy.linesep
        elif not linesep:
            linesep = get_linesep(mail.as_string())
        policy = default.clone(linesep=linesep,cte_type='7bit' if sevenbit else '8bit')
        mail = copy.deepcopy(mail)
        mail.policy = policy
    else:
        mail = as_protected(mail,linesep=linesep)
        linesep = mail._linesep # get new or original lineseps
    if mail.is_multipart():
        converted = []
        for submsg in mail.get_payload():
            if submsg.is_multipart():
                submsg = protect_mail(submsg,linesep,sevenbit)
            else:
                if sevenbit: to7bit(submsg)
                submsg = as_protected(submsg,linesep=linesep)
            converted.append(submsg)
        mail.set_payload(None)
        for submsg in converted: mail.attach(submsg)
    else:
        if sevenbit: to7bit(mail)
        mail.set_payload(fix_lines(mail.get_payload(),linesep=linesep))
    return mail

def check_charset(s, charset=None, use_locale=True):
    from six import PY3
    from locale import getpreferredencoding
    import codecs
    # work around gnupg workaround :/
    codecs.register_error('strict', codecs.strict_errors)
    if PY3:
        if charset:
            s.encode(charset)
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

def create_mail(sender,to,subject,body,cc=None,bcc=None,
    attach=None,time=None,headers={},charset=None):
    """create an email with sender 'sender', receivers 'to', subject and body,
     optional CC, BCC, attachments, extra headers and time"""
    import email.mime.text, email.mime.multipart, email.utils
    import time as time_mod
    from six import iteritems
    def set_header(msg,key,value,charset):
        from email.header import Header
        value, charset = check_charset(value, charset)
        msg[key] = value if charset=='us-ascii' else str(Header(value, charset))

    body = fix_lines(body,replace=False)
    body, bcharset = check_charset(body,charset)
    msg = email.mime.text.MIMEText(body,_charset=bcharset)
    if not attach is None:
        mmsg = email.mime.multipart.MIMEMultipart()
        mmsg.attach(msg)
        for msg in attach: mmsg.attach(msg)
        msg = mmsg
    msg.set_unixfrom(email.utils.parseaddr(sender)[1])
    set_header(msg,'From',sender,charset)
    set_header(msg,'To',to,charset)
    if cc: set_header(msg,'CC',cc,charset)
    if bcc: set_header(msg,'BCC',bcc,charset)
    set_header(msg,'Subject',subject,charset)
    if not time: time = time_mod.time()
    msg['Date'] = email.utils.formatdate(time,localtime=True)
    for k, v in iteritems(headers):
        if k.lower()=='content-type':
            msg.set_type(v)
        elif k in msg:
            msg.replace_header(k,v)
        else:
            msg.add_header(k,v)
    return msg
