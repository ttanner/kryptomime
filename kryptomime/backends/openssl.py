# -*- coding: utf-8 -*-
#
# OpenSSL S/MIME support
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

from . import tmpfname, TmpDir, runcmd, SubProcessError
import os

def create_subj(subj):
    from six import iteritems
    if isinstance(subj,dict):
        return '\n'.join((k+'='+v for k,v in iteritems(subj)))
    return subj

class OpenSSL(object):
    def __init__(self,executable=None):
        from . import find_binary
        self.openssl = find_binary(executable, 'openssl')

    def generate_selfsigned(self,email,subj=None,pubkey=None,seckey=None,password=None,
        bits=2048,digest='sha256',days=365,args=None):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_subj(subj)
        config = tmpfname()
        f = open(config,'wt')
        f.write("""[ req ]
prompt = no
default_md = {digest}
default_bits = {bits}
output_password = {password}
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[ req_distinguished_name ]
{subj}
[ v3_ca ]
subjectKeyIdentifier = hash
subjectAltName = email:copy
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:true
nsCertType = email
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = emailProtection""".format(
        digest=digest,bits=bits,subj=subj,password=password))
        f.close()
        cmd = self.openssl+' req -x509 -config "{config}" -new -keyout "{seckey}" -days {days} -batch'
        if not password: cmd += ' -nodes'
        cmd = cmd.format(seckey=seckey,days=days,config=config)
        if args: cmd+= ' '+args
        try:
            pub, error = runcmd(cmd)
            sec = open(seckey,'rt').read()
        except SubProcessError as e:
            print ('error', e.error)
            return None, None
        finally:
            os.unlink(config)
            if tmpsec: os.unlink(seckey)
        if pubkey:
            f = open(pubkey,'wt')
            f.write(pub)
            f.close()
        return pub, sec

    def generate_key(self,email,subj=None,req=None,seckey=None,password=None,
        bits=2048,digest='sha256',args=None):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_subj(subj)
        config = tmpfname()
        f = open(config,'wt')
        f.write("""[ req ]
prompt = no
default_md = {digest}
default_bits = {bits}
output_password = {password}
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
{subj}
""".format(
        digest=digest,bits=bits,subj=subj,password=password))
        f.close()
        cmd = self.openssl+' req -config "{config}" -new -keyout "{seckey}" -batch'
        if not password: cmd += ' -nodes'
        cmd = cmd.format(seckey=seckey,config=config)
        if args: cmd+= ' '+args
        try:
            csr, error = runcmd(cmd)
            sec = open(seckey,'rt').read()
        except SubProcessError as e:
            print ('error', e.error)
            return None, None
        finally:
            os.unlink(config)
            if tmpsec: os.unlink(seckey)
        if req:
            f = open(req,'wt')
            f.write(csr)
            f.close()
        return csr, sec

    def convert_key(self,key,inform='pem',outform='pem',
        password=None,passout=None,cipher='des3',public=False,args=None):
        cmd = self.openssl+' rsa -inform %s -outform %s' % (inform,outform)
        stringio = inform=='pem' and outform=='pem'
        if not stringio: key = bytes(key)
        env = {}
        if password:
            cmd += ' -passin env:PASSIN'
            env['PASSIN'] = password
        if passout and outform=='pem':
            cmd += ' -passout env:PASSOUT -'+cipher
            env['PASSOUT'] = passout
        if public: cmd+= ' -pubout'
        if args: cmd+= ' '+args
        try: out, err = runcmd(cmd,input=key,stringio=stringio,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        if not stringio and outform=='pem': return out.decode('ascii')
        return out

    def extract_pkcs12(self,pkcs12,password=None,passout=None,
        cacert=True,client=True,private=True,args=None):
        env = {}
        cmd = self.openssl+' pkcs12'
        if not cacert:
            if not client: cmd+= ' -nocerts'
            else: cmd+= ' -clcerts'
        elif not client:
            cmd+= ' -cacerts'
        if not private: cmd+= ' -nokeys'
        elif passout:
            cmd += ' -passout env:PASSOUT'
            env['PASSOUT'] = passout
        else: cmd+= ' -nodes'
        if password:
            cmd += ' -passin env:PASSIN'
            env['PASSIN'] = password
        if args: cmd+= ' '+args
        try: pem, err = runcmd(cmd,input=pkcs12,env=env,stringio=False)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        return pem.decode('ascii')

    @classmethod
    def write_keys(cls,cmd,keys,tmpdir,prefix=''):
        if not keys: return cmd
        if not isinstance(keys,(tuple,list,set)):
            keys = [keys]
        if prefix: prefix=' -'+prefix
        for key in keys:
            cmd +='%s "%s"' % (prefix,tmpdir.generate(data=key))
        return cmd

    def sign(self,msg,public,private=[],password=None,certs=[],
        detach=False,compress=False,version=3,args=None):
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        cmd = self.openssl+' '+('smime' if version==2 else 'cms')+' -sign'
        tmpdir = TmpDir()
        if isinstance(public,(tuple,list,set)) and len(public)>1:
            for i, key in enumerate(public):
                cmd +=' -signer "%s"' % tmpdir.generate(data=key)
                if not len(private): continue
                cmd +=' -inkey "%s"' % tmpdir.generate(data=private[i])
        else:
            cmd +=' -signer "%s"' % tmpdir.generate(data=public)
            if private:
                cmd +=' -inkey "%s"' % tmpdir.generate(data=private)
        cmd = self.write_keys(cmd,certs,tmpdir,'certfile')
        env = {}
        if password:
            cmd += ' -passin env:PASSWORD'
            env = {'PASSWORD':password}
        if compress: cmd += ' -compress'
        if detach: cmd += ' -nodetach'
        if args: cmd+= ' '+args
        try: out, err = runcmd(cmd,input=msg,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out

    def encrypt(self,msg,recipients,
        sign=None,private=None,password=None,certs=[],
        cipher='des3',compress=False,version=3,args=None):
        "cacerts must contain all intermediate and root CAs in chain"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        if sign:
            msg = self.sign(msg,sign,private,password,certs,
                compress=compress,version=version,args=args)
        cmd = self.openssl+' '+('smime' if version==2 else 'cms')+' -encrypt'
        if cipher: cmd+= ' -'+cipher
        tmpdir = TmpDir()
        cmd = self.write_keys(cmd,recipients,tmpdir)
        if args: cmd+= ' '+args
        try: out, err = runcmd(cmd,input=msg)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out

    def verify(self,msg,cacerts=[],certs=[],detach=None,
        compress=False,version=3,args=None):
        """cacerts must contain all intermediate and root CAs in chain,
        must be filename or list of certs"""
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = self.openssl+' '+('smime' if version==2 else 'cms')+' -verify'
        tmpdir = TmpDir()
        signer = tmpdir.generate()
        cmd +=' -signer "%s"' % signer
        if detach:
            content = tmpdir.generate(data=detach)
            cmd +=' -content "%s"' % content
        cmd = self.write_keys(cmd,certs,tmpdir,'certfile')
        if cacerts:
            tmpca = isinstance(cacerts,(tuple,list,set))
            if tmpca:
                cacerts = tmpdir.generate(data=''.join(cacerts))
            cmd +=' -CAfile "%s"' % cacerts
        if compress: cmd += ' -uncompress'
        if args: cmd+= ' '+args
        try:
            out, err = runcmd(cmd,input=msg,env=env)
            pub = open(signer).read()
            valid = err.startswith('Verification successful')
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None, None, None
        finally: tmpdir.destroy()
        return out, pub, valid

    def decrypt(self,msg,recipient,private=None,password=None,
        verify=True,cacerts=[],certs=[],
        compress=False,version=3,args=None):
        "cacerts must be filename or list of trused CA certs"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = self.openssl+' '+('smime' if version==2 else 'cms')+' -decrypt'
        tmpdir = TmpDir()
        pubkey = tmpdir.generate(data=recipient)
        cmd +=' -recip "%s"' % pubkey
        if private:
            seckey = tmpdir.generate(data=private)
            cmd +=' -inkey "%s"' % seckey
        env = {}
        if password:
            cmd += ' -passin env:PASSWORD'
            env = {'PASSWORD':password}
        if compress: cmd += ' -uncompress'
        if args: cmd+= ' '+args
        try: out, err = runcmd(cmd,input=msg,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            if not verify: return None
            return None, None, None
        finally: tmpdir.destroy()
        if not verify: return out
        return self.verify(out,cacerts=cacerts,certs=certs,
            compress=compress,version=version,args=args)

class OpenSSL_CA(OpenSSL):
    def __init__(self,directory=None,password=None,**kwargs):
        super(OpenSSL_CA,self).__init__(**kwargs)
        self.dir = os.path.abspath(directory or os.getcwd())
        self.password = password
        self.cacert = None
        fname = os.path.join(self.dir,'cacert.pem')
        if os.path.exists(fname):
            self.cacert = open(fname,'rt').read()

    def generate_crl(self,days=None,args=None):
        cmd = self.openssl+' ca -config openssl.cnf -batch -notext -gencrl -out crls/crl.pem'
        if days: cmd = cmd+' -crldays '+str(days)
        if args: cmd+= ' '+args
        cmd2 = self.openssl+' crl -inform pem -outform der -in crls/crl.pem -out crls/crl.der'
        env = {}
        if self.password:
            cmd += ' -passin env:PASSWORD'
            env = {'PASSWORD':self.password}
        try:
            out, err = runcmd(cmd,cwd=self.dir,env=env)
            out, err = runcmd(cmd2,cwd=self.dir)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None

    def generate_ca(self, subj, bits=2048,digest='sha256',days=3650,extra='',args=None):
        dir = self.dir
        if not os.path.isdir(dir):
            os.makedirs(dir,0o777)
        for sub in ('certs','crls','private','newcerts'):
            subdir = os.path.join(dir,sub)
            if not os.path.isdir(subdir): os.mkdir(subdir)
        open(os.path.join(dir,'serial'),'wt').write('1000\n')
        open(os.path.join(dir,'crlnumber'),'wt').write('00\n')
        open(os.path.join(dir,'index.txt'),'wt').write('')
        open(os.path.join(dir,'openssl.cnf'),'wt').write("""[ ca ]
default_ca	= CA_default		# The default ca section
[ CA_default ]
dir		= .			# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
new_certs_dir	= $dir/newcerts		# default place for new certs.
certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem # The private key
RANDFILE	= $dir/private/.rand	# private random number file
x509_extensions	= email_cert		# The extentions to add to the cert
default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= {digest}		# use public key default MD
preserve	= no			# keep passed DN ordering
policy		= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= optional
emailAddress	= supplied

[ req ]
default_bits		= 2048
distinguished_name	= req_distinguished_name
attributes		= req_attributes
default_md = {digest}
string_mask = utf8only
req_extensions = email_cert # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= Some Country
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some State
localityName			= Locality Name (eg, city)
localityName_default		= Some Locality
organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default	= Some Unit
commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

[ email_cert ]
subjectKeyIdentifier = hash
subjectAltName = email:copy
authorityKeyIdentifier = keyid:always,issuer:always
issuerAltName=issuer:copy

basicConstraints=CA:FALSE
nsCertType = email
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = emailProtection

[ crl_ext ]
issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ v3_OCSP ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = OCSPSigning
""".format(digest=digest)+extra)

        subj = create_subj(subj)
        config = """[ req ]
prompt = no
default_md = {digest}
default_bits = {bits}
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[ req_distinguished_name ]
{subj}
[ v3_ca ]
subjectKeyIdentifier = hash
subjectAltName = email:copy
authorityKeyIdentifier = keyid:always,issuer:always
issuerAltName=issuer:copy

basicConstraints = critical,CA:true
keyUsage = cRLSign, keyCertSign
nsCertType = sslCA, emailCA, objCA
""".format(digest=digest,bits=bits,subj=subj)
        config = tmpfname(data=config)
        seckey = os.path.join(dir,'private','cakey.pem')
        env = {}
        cmd = self.openssl+' req -config "{config}" -batch -x509 -new -keyout private/cakey.pem -out cacert.pem -days {days}'
        if not self.password: cmd += ' -nodes'
        else:
            cmd += ' -passout env:PASSWORD'
            env = {'PASSWORD':self.password}
        cmd = cmd.format(days=days,config=config)
        if args: cmd+= ' '+args
        try:
            out, error = runcmd(cmd,cwd=dir,env=env)
        except SubProcessError as e:
            print ('error', e.error)
            return None
        finally:
            os.unlink(config)
        self.generate_crl()
        self.cacert = open(os.path.join(dir,'cacert.pem'),'rt').read()
        return self.cacert

    def sign_key(self,csr,cacert=False,pubkey=None,days=365,policy=None,args=None):
        req = tmpfname(data=csr)
        env = {}
        cmd = self.openssl+' ca -config openssl.cnf -batch -notext -in "{req}" -days {days}'
        cmd = cmd.format(days=days,req=req)
        if policy: cmd += ' -policy '+policy
        if self.password:
            cmd += ' -passin env:PASSWORD'
            env = {'PASSWORD':self.password}
        if args: cmd+= ' '+args
        try:
            crt, err = runcmd(cmd,cwd=self.dir,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally:
            os.unlink(req)
        if pubkey:
            f = open(pubkey,'wt')
            f.write(crt)
            f.close()
        if cacert: crt += self.cacert
        return crt
