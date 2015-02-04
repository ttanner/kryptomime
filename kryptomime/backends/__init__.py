# -*- coding: utf-8 -*-
#
# Common backend code
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

import os, six

ASN_abbrevations = dict( # abbrevations
        CN='commonName',
        C='countryName',
        L='localityName',
        ST='stateOrProvinceName',
        O='organizationName',
        OU='organizationalUnitName',
        GN='givenName',
        SN='surname',
)

def create_DN(dname,separator='\n',expand=False):
    from six import iteritems
    if isinstance(dname,dict):
        if expand:
            dname = (ASN_abbrevations.get(k,k)+'='+v for k,v in iteritems(dname))
        else: dname = (k+'='+v for k,v in iteritems(dname))
        return separator.join(dname)
    return dname

def parse_DN(dname,separator='/'):
    res = {}
    for rdn in dname.split(separator):
        if not rdn: continue
        i = rdn.index('=')
        key,value = rdn[:i].strip(),rdn[i+1:].strip()
        res[ASN_abbrevations.get(key,key)] = value
    return res

def split_pem(pem,strip=False):
    from collections import OrderedDict
    parts = OrderedDict()
    block, within = '',''
    begin, end = '-----BEGIN', '-----END'
    for line in pem.splitlines(True):
        if within:
            final = line.startswith(end)
            if final:
                i = len(end)+1
                j = line.index('-----',i)
                assert within == line[i:j]
                if not strip: block += line
                if within in parts:
                    parts[within].append(block)
                else:
                    parts[within] = [block]
                block, within = '', False
            else: block += line
        else:
            within = line.startswith(begin)
            if within:
                i = len(begin)+1
                j = line.index('-----',i)
                within = line[i:j]
                if not strip: block += line
    return parts

class SubProcessError(Exception):
    def __init__(self, returncode, cmd, output=None, error=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output
        self.error = error
    def __str__(self):
        return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)

if six.PY2:
    from subprocess32 import TimeoutExpired
else:
    from subprocess import TimeoutExpired

def runcmd(cmd, input=None, stringio=False, **kwargs):
    if six.PY2:
        from subprocess32 import Popen, PIPE
    else:
        from subprocess import Popen, PIPE
    timeout = kwargs.pop('timeout', None)
    if input: kwargs['stdin'] = PIPE
    if not 'bufsize' in kwargs: kwargs['bufsize']= -1
    if isinstance(cmd, six.string_types):
        import shlex
        cmd = shlex.split(cmd)
    elif kwargs.get('shell'):
        from six.moves import shlex_quote
        cmd = [shlex_quote(arg) for arg in cmd]
    process = Popen(cmd,universal_newlines=stringio,stdout=PIPE,stderr=PIPE,**kwargs)
    try:
        output, error = process.communicate(input=input, timeout=timeout)
    except TimeoutExpired:
        process.kill()
        output, error = process.communicate()
        raise TimeoutExpired(process.args, timeout, output=output)
    retcode = process.poll()
    if retcode:
        raise SubProcessError(retcode, process.args, output=output, error=error)
    return output, error

class TmpDir(object):

    def __init__(self,dir=None):
        from tempfile import mkdtemp
        self.dir = mkdtemp(dir=dir)
        self.files = []

    def generate(self,data=None,mode='wt'):
        from tempfile import NamedTemporaryFile
        tmp = NamedTemporaryFile(delete=False,mode=mode,dir=self.dir)
        fname = tmp.name
        if not data is None: tmp.write(data)
        tmp.close()
        self.files.append(fname)
        return fname

    def cleanup(self):
        for fname in self.files:
            if os.path.exists(fname):
                os.unlink(fname)

    def destroy(self):
        from shutil import rmtree
        rmtree(self.dir)

def tmpfname(data=None,mode='w+b',dir=None):
    from tempfile import NamedTemporaryFile
    tmp = NamedTemporaryFile(delete=False,mode=mode,dir=dir)
    name = tmp.name
    if not data is None: tmp.write(data)
    tmp.close()
    return name

def find_binary(binary, default):
    def which(executable, flags=os.X_OK, abspath_only=False, disallow_symlinks=False):
        """Borrowed from Twisted's :mod:twisted.python.proutils .

        Search PATH for executable files with the given name.

        On newer versions of MS-Windows, the PATHEXT environment variable will be
        set to the list of file extensions for files considered executable. This
        will normally include things like ".EXE". This fuction will also find files
        with the given name ending with any of these extensions.

        On MS-Windows the only flag that has any meaning is os.F_OK. Any other
        flags will be ignored.

        Note: This function does not help us prevent an attacker who can already
        manipulate the environment's PATH settings from placing malicious code
        higher in the PATH. It also does happily follows links.

        :param str name: The name for which to search.
        :param int flags: Arguments to L{os.access}.
        :rtype: list
        :returns: A list of the full paths to files found, in the order in which
                  they were found.
        """
        def can_allow(p):
            if not os.access(p, flags):
                return False
            if abspath_only and not os.path.abspath(p):
                log.warn('Ignoring %r (path is not absolute)', p)
                return False
            if disallow_symlinks and os.path.islink(p):
                log.warn('Ignoring %r (path is a symlink)', p)
                return False
            return True

        result = []
        exts = filter(None, os.environ.get('PATHEXT', '').split(os.pathsep))
        path = os.environ.get('PATH', None)
        if path is None:
            return []
        for p in os.environ.get('PATH', '').split(os.pathsep):
            p = os.path.join(p, executable)
            if can_allow(p):
                result.append(p)
            for e in exts:
                pext = p + e
                if can_allow(pext):
                    result.append(pext)
        return result

    found = None
    if binary is not None:
        if os.path.isabs(binary) and os.path.isfile(binary):
            return binary
        if not os.path.isabs(binary):
            try:
                found = which(binary)[0]
                #log.debug("Found potential binary paths: %s"
                #          % '\n'.join([path for path in found]))
            except IndexError as ie: found = None
                #log.info("Could not determine absolute path of binary: '%s'"
                #          % binary)
        elif os.access(binary, os.X_OK):
            found = binary
    if found is None:
        try: found = which(default, abspath_only=True)[0]
        except IndexError as ie: found = None
            #log.error("Could not find binary for 'openssl'.")
    assert found, "%s is not installed!" % default
    return found
