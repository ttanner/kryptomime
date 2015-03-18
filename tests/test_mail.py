#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Mail unit tests
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

from __future__ import print_function

from pytest import raises, fixture
from kryptomime.mail import (protect_mail, _protected,
    create_mail, create_mime, check_charset, mail_payload,
    fix_lines, _mail_addreplace_header, mail_binary)
import six
from conftest import sender, receiver, compare_mail

def test_fixlines():
    assert fix_lines('') == ''
    assert fix_lines('a\r\nb',linesep=None) == 'a\r\nb'
    for var in range(16):
        first,linesep,final,replace=var&8,var&4,var&2,var&1
        first = '\r\n' if first else '\n'
        linesep = '\r\n' if linesep else '\n'
        for last in ('','\n','\r\n'):
            input = 'a'+first+'b'+last
            output = 'a'
            output+= linesep if replace else first
            output+= 'b'
            output+= linesep if final or (replace and last) else last
            assert fix_lines(input,linesep=linesep,final=final,replace=replace) == output

def test_protect():
    #> From foo
    msg='''Content-Type: multipart/mixed;
 boundary="------------030608090900090202040409"

This is a multi-part message in MIME format.
--------------030608090900090202040409
Content-Type: text/plain; charset=ISO-8859-15
Content-Transfer-Encoding: quoted-printable

body
line2

--------------030608090900090202040409
Content-Type: text/plain; charset=UTF-8;
 name="attach.txt"
Content-Transfer-Encoding: quoted-printable
Content-Disposition: attachment;
 filename="attach.txt"

attachment
line2
--------------030608090900090202040409--
'''
    prot = protect_mail(msg,linesep='\n',sevenbit=True)
    assert prot.as_string() == msg
    prot = protect_mail(msg,linesep='\r\n',sevenbit=True)
    assert prot.as_string() == fix_lines(msg,'\r\n')
    msg = create_mail(sender,receiver,'subject','body\nmessage')
    prot = protect_mail(msg,linesep='\n')
    assert msg.get_payload() == prot.get_payload()
    prot = protect_mail(msg,linesep='\r\n')
    assert fix_lines(msg.get_payload(),'\r\n') == prot.get_payload()

def test_payload():
    body = 'body\nmessage'
    ubody = u'bödy\nmessäge'
    enc8 = ('base64','quoted-printable','8bit')
    for uni in range(2):
        encodings = enc8 if uni else ['7bit']
        for enc in encodings:
            msg = create_mail(sender,receiver,'subject',
                ubody if uni else body,charset='UTF-8' if uni else 'us-ascii',
                encoding=enc)
            txt = mail_payload(msg)
            if uni: assert txt == ubody
            else: assert txt == body
    binary = b'\xc3\n\xf1'
    for encoding in enc8:
        att = create_mime(binary,'application','octet-stream',encoding=encoding)
        msg = create_mail(sender,receiver,'subject',body,attach=[att])
        cont = mail_payload(msg)
        assert len(cont)==2 and cont[0]==body and cont[1]==binary
    with raises(UnicodeError):
        create_mime(binary,'application','octet-stream',encoding='7bit')
    body = b'body\nmessage'
    att = create_mime(body,'application','octet-stream',encoding='7bit')
    assert mail_payload(att)==body

def test_attach():
    attachment = create_mime('some\nattachment')
    msg = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
    # boundary is generated randomly by as_string - hardcode here
    msg.set_boundary('===============1808028167789866750==')
    prot = _protected(msg)
    assert prot.as_string() == msg.as_string()
    prot = protect_mail(msg,linesep='\n',sevenbit=True)
    assert prot.as_string() == msg.as_string()

def test_charset():
    cascii, clatin, cutf = 'us-ascii', 'latin_1', 'UTF-8'
    s = 'uber'
    assert check_charset(s,use_locale=False) == (s,cascii)
    assert check_charset(s,cascii) == (s,cascii)
    assert check_charset(s,clatin) == (s,clatin)
    assert check_charset(s,cutf) == (s,cutf)
    s = 'über'
    assert check_charset(s,use_locale=False) == (s,cutf)
    with raises(UnicodeError): assert check_charset(s,cascii)
    assert check_charset(s,clatin) == (s,clatin)
    assert check_charset(s,cutf) == (s,cutf)
    l = '\xfcber'
    if six.PY2:
        with raises(UnicodeError): assert check_charset(l,use_locale=False)
        with raises(UnicodeError): assert check_charset(l,cascii)
        assert check_charset(l,clatin) == (l,clatin)
        with raises(UnicodeError): assert check_charset(l,cutf)
    u = u'über'
    assert check_charset(u,use_locale=False) == (s,cutf)
    with raises(UnicodeError): assert check_charset(s,cascii)
    assert check_charset(u,clatin) == (l,clatin)
    assert check_charset(u,cutf) == (s,cutf)

@fixture(scope='module')
def attachments():
    s = u'über\n1\n2'
    a0 = create_mime('uber')
    a1 = create_mime(s)
    a2 = create_mime(s,encoding='base64')
    a3 = create_mime(s,encoding='quoted-printable')
    a4 = create_mime(s,encoding='8bit')
    a5 = create_mime(s.encode('iso8859-1'),charset='iso8859-1')
    a6 = create_mime(s.encode('iso8859-1'),charset='iso8859-1',encoding='base64')
    a7 = create_mime(s.encode('iso8859-1'),charset='iso8859-1',encoding='quoted-printable')
    a8 = create_mime(s.encode('iso8859-1'),charset='iso8859-1',encoding='8bit')
    return [a0,a1,a2,a3,a4,a5,a6,a7,a8]

def test_attach_encoding(attachments):
    import six
    s = u'über\n1\n2'
    a = attachments
    cte = 'Content-Transfer-Encoding'
    assert a[0][cte] == '7bit'
    for i in (4,8): assert a[i][cte] == '8bit'
    for i in (3,7): assert a[i][cte] == 'quoted-printable'
    for i in (1,2,5,6): assert a[i][cte] == 'base64'
    for msg in a[1:]: assert mail_payload(msg)==s

def test_8bit(attachments):
    expect=b'''Content-Type: multipart/mixed; boundary="===============6661726347990728450=="
MIME-Version: 1.0
From: Foo <foo@localhost>
To: Bar <bar@localhost>
Subject: subject
Date: Mon, 02 Feb 2015 12:00:00 +0100

--===============6661726347990728450==
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

w7xiZXIKMQoy
--===============6661726347990728450==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

uber
--===============6661726347990728450==
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

w7xiZXIKMQoy
--===============6661726347990728450==
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

w7xiZXIKMQoy
--===============6661726347990728450==
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

=C3=BCber
1
2
--===============6661726347990728450==
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

\xc3\xbcber
1
2
--===============6661726347990728450==
Content-Type: text/plain; charset="iso8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: base64

/GJlcgoxCjI=
--===============6661726347990728450==
Content-Type: text/plain; charset="iso8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: base64

/GJlcgoxCjI=
--===============6661726347990728450==
Content-Type: text/plain; charset="iso8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable

=FCber
1
2
--===============6661726347990728450==
Content-Type: text/plain; charset="iso8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: 8bit

\xfcber
1
2
--===============6661726347990728450==--
'''
    s = u'über\n1\n2'
    msg = create_mail(sender,receiver,'subject',s,attach=attachments,time='Mon, 02 Feb 2015 12:00:00 +0100')
    msg.set_boundary('===============6661726347990728450==')
    out = mail_binary(msg)
    assert out==expect
    prot = protect_mail(out,linesep='\n',sevenbit=False)
    att = prot.get_payload()
    out2 = mail_binary(prot)
    assert out==out2
    compare_mail(msg,prot)

def test_unicode():
    from email.header import decode_header
    def get_header(msg,key):
        v = msg[key]
        v = decode_header(v)[0]
        v = v[0].decode(v[1])
        return v
    usender = sender.replace('Foo',u'Föo')
    ureceiver = receiver.replace('Bar',u'Bär')
    usubject = u'sübject'
    body = 'body\nmessage'
    ubody = u'bödy\nmessage'
    msg = create_mail(usender,ureceiver,usubject,body,headers={'X-Spam':'No'})
    assert get_header(msg,'From') == usender
    assert get_header(msg,'To') == ureceiver
    assert get_header(msg,'Subject') == usubject
    assert msg['X-Spam'] == 'No'
    assert msg.get_charset() == 'us-ascii'
    assert msg.get_payload(decode=False) == body

    msg = create_mail(sender,receiver,'subject',ubody)
    assert not msg['X-Spam']
    _mail_addreplace_header(msg,'X-Spam','No')
    assert msg['X-Spam'] == 'No'
    _mail_addreplace_header(msg,'X-Spam','Yes')
    assert msg['X-Spam'] == 'Yes'
    assert msg.get_charset() == 'UTF-8'
    assert mail_payload(msg) == ubody

    attachment = 'some\nattachment'
    uattachment = u'söme\nattachment'
    attach=create_mime(attachment)
    uattach=create_mime(uattachment,charset='utf-8')
    for variant in range(1,4):
        unibody,uniatt  = variant&1,variant&2
        msg = create_mail(sender,receiver,'subject',ubody if unibody else body,
            attach=[uattach if uniatt else attach])
        assert not msg.get_charset()
        submsg = msg.get_payload(0)
        if unibody:
            assert submsg.get_charset() == 'UTF-8'
            assert submsg.get_payload(decode=True).decode('UTF-8') == ubody
        else:
            assert submsg.get_charset() == 'us-ascii'
            assert submsg.get_payload(decode=False) == body
        submsg = msg.get_payload(1)
        if uniatt:
            assert submsg.get_charset() == 'UTF-8'
            assert submsg.get_payload(decode=True).decode('UTF-8') == uattachment
        else:
            assert submsg.get_charset() == 'us-ascii'
            assert submsg.get_payload(decode=False) == attachment
