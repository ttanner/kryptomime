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
from collections import OrderedDict
import os

def create_subj(subj):
    from six import iteritems
    if isinstance(subj,dict):
        return '\n'.join((k+'='+v for k,v in iteritems(subj)))
    return subj

def config_section(name,cfg):
    from six import iteritems
    if not cfg: return ''
    s = '[ %s ]\n' % name
    for k,v in iteritems(cfg):
        s += '%s = %s\n' % (k,v)
    return s

def generate_config(cfg,extra):
    from six import iteritems
    s = ''
    for k,v in iteritems(cfg):
        if k in extra:
            v = extra[k]
            if v is None: continue
        if s: s+='\n'
        s += config_section(k,v)
    return s

class OpenSSL(object):
    def __init__(self,executable=None):
        from . import find_binary
        import re
        self.openssl = find_binary(executable, 'openssl')
        version, error = runcmd([self.openssl,'version'])
        version = re.match(r'^OpenSSL (\d).(\d+).(\d+)(\w+)',version)
        assert not version is None, 'invalid openssl version'
        version = [int(version.group(i)) for i in range(1,4)]+[version.group(4)]
        no = version[0]*100+version[1]*10+version[2]
        assert no>101 or no==101 and version[3]>='k', "obsolete openssl version"
        self.version = version

    def config_req(self, **kwargs):
        bits = kwargs.get('bits',2048)
        digest = kwargs.get('digest','sha256')
        req = OrderedDict([
            ("prompt", "no"),
            ("default_bits", str(bits)),
            ("default_md", digest),
            ("distinguished_name", "req_distinguished_name"),
            ("string_mask", "utf8only"),
        ])
        if 'password' in kwargs:
            req['output_password'] = kwargs['password']
        for field in ('attributes', 'req_extensions', 'x509_extensions'):
            if field not in kwargs: continue
            req[field] = kwargs[field]
        return req

    def config_v3_base(self, extra=[]):
        return OrderedDict([
            ("subjectKeyIdentifier", "hash"),
            ("subjectAltName", "email:copy"),
            ("authorityKeyIdentifier", "keyid:always,issuer:always"),
            ("issuerAltName", "issuer:copy"),
            ]+extra
        )

    def config_v3_ca(self):
        return self.config_v3_base([
            ("basicConstraints", "critical,CA:true"),
            ("keyUsage", "cRLSign, keyCertSign"),
            ("nsCertType", "sslCA, emailCA, objCA"),
        ])

    def config_v3_email(self,selfsigned=False):
        return self.config_v3_base([
            ("basicConstraints", "CA:"+str(selfsigned).upper()),
            ("nsCertType", "email"),
            ("keyUsage", "critical, digitalSignature, keyEncipherment"),
            ("extendedKeyUsage", "emailProtection"),
        ])

    def generate_selfsigned(self,email,subj=None,pubkey=None,seckey=None,password=None,
        bits=2048,digest='sha256',days=365,args=[]):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_subj(subj)
        reqcfg = self.config_req(digest=digest, bits=bits, password=password, x509_extensions="v3_email")
        v3_email = self.config_v3_email(selfsigned=True)
        cfg = config_section('req',reqcfg) + config_section('v3_email',v3_email)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        cmd = [self.openssl,'req','-x509','-config',config,'-new','-keyout',seckey,'-days',days,'-batch']
        if not password: cmd.append('-nodes')
        cmd.extend(args)
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
            with open(pubkey,'wt') as f: f.write(pub)
        return pub, sec

    def generate_key(self,email,subj=None,req=None,seckey=None,password=None,
        bits=2048,digest='sha256',args=[]):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_subj(subj)
        reqcfg = self.config_req(digest=digest, bits=bits, password=password)
        cfg = config_section('req',reqcfg)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        cmd = [self.openssl,'req','-config',config,'-new','-keyout',seckey,'-batch']
        if not password: cmd.append('-nodes')
        cmd.extend(args)
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
            with open(req,'wt') as f: f.write(csr)
        return csr, sec

    def convert_key(self,key,inform='pem',outform='pem',
        password=None,passout=None,cipher='des3',public=False,args=[]):
        cmd = [self.openssl,'rsa','-inform',inform,'-outform',outform]
        stringio = inform=='pem' and outform=='pem'
        env = {}
        if password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = password
        if passout and outform=='pem':
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passout
        if public: cmd.append('-pubout')
        cmd.append('-'+cipher)
        cmd.extend(args)
        try: out, err = runcmd(cmd,input=key,stringio=stringio,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        if not stringio and outform=='pem': return out.decode('ascii')
        return out

    def extract_pkcs12(self,pkcs12,password=None,passout=None,
        cacert=True,client=True,private=True,args=[]):
        cmd = [self.openssl,'pkcs12']
        if not cacert:
            cmd.append('-clcerts' if client else '-nocerts')
        elif not client:
            cmd.append('-cacerts')
        if not private: cmd.append('-nokeys')
        elif passout:
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passout
        else: cmd.append('-nodes')
        env = {}
        if password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = password
        cmd.extend(args)
        try: pem, err = runcmd(cmd,input=pkcs12,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        return pem.decode('ascii')

    @classmethod
    def write_keys(cls,cmd,keys,tmpdir,prefix=''):
        if not keys: return cmd
        if not isinstance(keys,(tuple,list,set)):
            keys = [keys]
        if prefix: prefix='-'+prefix
        for key in keys:
            if prefix: cmd.append(prefix)
            cmd.append(tmpdir.generate(data=key))
        return cmd

    def sign(self,msg,public,private=[],password=None,certs=[],
        detach=False,compress=False,version=3,args=[]):
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        cmd = [self.openssl,('smime' if version==2 else 'cms'),'-sign']
        tmpdir = TmpDir()
        if isinstance(public,(tuple,list,set)) and len(public)>1:
            for i, key in enumerate(public):
                cmd += ['-signer',tmpdir.generate(data=key)]
                if not len(private): continue
                cmd += ['-inkey',tmpdir.generate(data=private[i])]
        else:
            cmd += ['-signer',tmpdir.generate(data=public)]
            if private:
                cmd += ['-inkey',tmpdir.generate(data=private)]
        cmd = self.write_keys(cmd,certs,tmpdir,'certfile')
        env = {}
        if password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = password
        if compress: cmd.append('-compress')
        if detach: cmd.append('-nodetach')
        cmd.extend(args)
        try: out, err = runcmd(cmd,input=msg,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out

    def encrypt(self,msg,recipients,
        sign=None,private=None,password=None,certs=[],
        cipher='des3',compress=False,version=3,args=[]):
        "cacerts must contain all intermediate and root CAs in chain"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        if sign:
            msg = self.sign(msg,sign,private,password,certs,
                compress=compress,version=version,args=args)
        cmd = [self.openssl,('smime' if version==2 else 'cms'),'-encrypt']
        if cipher: cmd.append('-'+cipher)
        tmpdir = TmpDir()
        cmd = self.write_keys(cmd,recipients,tmpdir)
        cmd.extend(args)
        try: out, err = runcmd(cmd,input=msg)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out

    def verify(self,msg,cacerts=[],certs=[],detach=None,
        compress=False,version=3,args=[]):
        """cacerts must contain all intermediate and root CAs in chain,
        must be filename or list of certs"""
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = [self.openssl,('smime' if version==2 else 'cms'),'-verify']
        tmpdir = TmpDir()
        signer = tmpdir.generate()
        cmd += ['-signer',signer]
        if detach:
            content = tmpdir.generate(data=detach)
            cmd += ['-content',content]
        cmd = self.write_keys(cmd,certs,tmpdir,'certfile')
        if cacerts:
            tmpca = isinstance(cacerts,(tuple,list,set))
            if tmpca:
                cacerts = tmpdir.generate(data=''.join(cacerts))
            cmd += ['-CAfile',cacerts]
        if compress: cmd.append('-uncompress')
        cmd.extend(args)
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
        compress=False,version=3,args=[]):
        "cacerts must be filename or list of trused CA certs"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = [self.openssl,('smime' if version==2 else 'cms'),'-decrypt']
        tmpdir = TmpDir()
        pubkey = tmpdir.generate(data=recipient)
        cmd += ['-recip',pubkey]
        if private:
            seckey = tmpdir.generate(data=private)
            cmd += ['-inkey',seckey]
        env = {}
        if password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = password
        if compress: cmd.append('-uncompress')
        cmd.extend(args)
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

    def generate_crl(self,days=None,args=[]):
        cmd = [self.openssl,'ca','-config','openssl.cnf','-batch',
            '-notext','-gencrl','-out','crls/crl.pem']
        if days: cmd += ['-crldays',str(days)]
        cmd.extend(args)
        env = {}
        if self.password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = self.password
        cmd2 = [self.openssl,'crl','-inform','pem','-outform','der',
            '-in','crls/crl.pem','-out','crls/crl.der']
        try:
            out, err = runcmd(cmd,cwd=self.dir,env=env)
            out, err = runcmd(cmd2,cwd=self.dir)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None

    def config_CA_default(self, **kwargs):
        digest = kwargs.get('digest','sha256')
        days = kwargs.get('days',365)
        crldays = kwargs.get('crldays',30)
        ext = kwargs.get('x509_extensions','v3_email')
        policy = kwargs.get('policy','policy_match')
        return OrderedDict([
            ("dir", "."), # Where everything is kept
            ("certs", "$dir/certs"),		# Where the issued certs are kept
            ("crl_dir", "$dir/crl"),		# Where the issued crl are kept
            ("database", "$dir/index.txt"),	# database index file.
            ("new_certs_dir", "$dir/newcerts"),		# default place for new certs.
            ("certificate", "$dir/cacert.pem"), 	# The CA certificate
            ("serial", "$dir/serial"), 		# The current serial number
            ("crlnumber", "$dir/crlnumber"),	# the current crl number
            ("crl", "$dir/crl.pem"), 		# The current CRL
            ("private_key", "$dir/private/cakey.pem"), # The private key
            ("RANDFILE", "$dir/private/.rand"),	# private random number file
            ("x509_extensions", ext),		# The extentions to add to the cert
            ("default_days", str(days)),			# how long to certify for
            ("default_crl_days", str(crldays)),			# how long before next CRL
            ("default_md", digest),		# use public key default MD
            ("preserve", "no"),			# keep passed DN ordering
            ("policy", policy),
        ])

    def config_policies(self):
        policy_match = OrderedDict([
            ("countryName", "match"),
            ("stateOrProvinceName", "match"),
            ("organizationName", "match"),
            ("organizationalUnitName", "optional"),
            ("commonName", "supplied"),
            ("emailAddress", "optional"),
        ])
        policy_anything = OrderedDict([
            ("countryName", "optional"),
            ("stateOrProvinceName", "optional"),
            ("localityName", "optional"),
            ("organizationName", "optional"),
            ("organizationalUnitName", "optional"),
            ("commonName", "optional"),
            ("emailAddress", "supplied"),
        ])
        return OrderedDict([
            ("policy_match", policy_match),
            ("policy_anything", policy_anything),
        ])

    def config_extra(self):
        crl_ext = OrderedDict([
            ("issuerAltName", "issuer:copy"),
            ("authorityKeyIdentifier", "keyid:always"),
        ])
        v3_OCSP = OrderedDict([
            ("basicConstraints", "CA:FALSE"),
            ("keyUsage", "nonRepudiation, digitalSignature, keyEncipherment"),
            ("extendedKeyUsage", "OCSPSigning"),
        ])
        return OrderedDict([
            ("crl_ext", crl_ext),
            ("v3_OCSP", v3_OCSP),
        ])

    def config_defaults(self, **kwargs):
        bits = kwargs.get('bits',2048)
        digest = kwargs.get('digest','sha256')
        req = self.config_req(digest=digest, bits=bits, attributed="req_attributes",
            # The extensions to add to a certificate request
            req_extensions=kwargs.get('req_extensions','v3_email'))
        ca = OrderedDict(default_ca="CA_default")	# The default ca section
        req_distinguished_name = OrderedDict([
            ("countryName", "Country Name (2 letter code)"),
            ("countryName_default", "Some Country"),
            ("countryName_min", "2"),
            ("countryName_max", "2"),
            ("stateOrProvinceName", "State or Province Name (full name)"),
            ("stateOrProvinceName_default", "Some State"),
            ("localityName", "Locality Name (eg, city)"),
            ("localityName_default", "Some Locality"),
            ("organizationalUnitName", "Organizational Unit Name (eg, section)"),
            ("organizationalUnitName_default", "Some Unit"),
            ("commonName", "Common Name (e.g. server FQDN or YOUR name)"),
            ("commonName_max", "64"),
            ("emailAddress", "Email Address"),
            ("emailAddress_max", "64"),
        ])
        req_attributes = OrderedDict([
            ("challengePassword", "A challenge password"),
            ("challengePassword_min", "4"),
            ("challengePassword_max", "20"),
        ])
        cfg = OrderedDict([
            ('ca', ca),
            ('CA_default', self.config_CA_default(digest=digest) ),
            ('req', req),
            ("req_distinguished_name", req_distinguished_name),
            ("req_attributes", req_attributes),
            ('v3_email', self.config_v3_email()),
        ])
        cfg.update(self.config_extra())
        cfg.update(self.config_policies())
        return cfg

    def generate_ca(self, subj, bits=4096,digest='sha256',days=3650,extra={},args=[]):
        dir = self.dir
        if not os.path.isdir(dir):
            os.makedirs(dir,0o777)
        for sub in ('certs','crls','private','newcerts'):
            subdir = os.path.join(dir,sub)
            if not os.path.isdir(subdir): os.mkdir(subdir)
        open(os.path.join(dir,'serial'),'wt').write('1000\n')
        open(os.path.join(dir,'crlnumber'),'wt').write('00\n')
        open(os.path.join(dir,'index.txt'),'wt').write('')
        config = generate_config(self.config_defaults(digest=digest),extra)
        open(os.path.join(dir,'openssl.cnf'),'wt').write(config)
        subj = create_subj(subj)
        reqcfg = self.config_req(digest=digest, bits=bits, x509_extensions='v3_ca')
        v3_ca = self.config_v3_ca()
        cfg = config_section('req',reqcfg) + config_section('v3_ca',v3_ca)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        seckey = os.path.join(dir,'private','cakey.pem')
        cmd = [self.openssl,'req','-config',config,'-batch','-x509','-new',
            '-keyout','private/cakey.pem','-out','cacert.pem','-days',str(days)]
        env = {}
        if self.password:
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = self.password
        else: cmd.append('-nodes')
        cmd.extend(args)
        try: out, error = runcmd(cmd,cwd=dir,env=env)
        except SubProcessError as e:
            print ('error', e.error)
            return None
        finally: os.unlink(config)
        self.generate_crl()
        self.cacert = open(os.path.join(dir,'cacert.pem'),'rt').read()
        return self.cacert

    def sign_key(self,csr,cacert=False,pubkey=None,days=365,policy=None,args=[]):
        req = tmpfname(data=csr)
        cmd = [self.openssl,'ca','-config','openssl.cnf','-batch','-notext','-in',req,'-days',str(days)]
        if policy: cmd += ['-policy',policy]
        env = {}
        if self.password:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = self.password
        cmd.extend(args)
        try: crt, err = runcmd(cmd,cwd=self.dir,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: os.unlink(req)
        if pubkey:
            with open(pubkey,'wt') as f: f.write(crt)
        if cacert: crt += self.cacert
        return crt
