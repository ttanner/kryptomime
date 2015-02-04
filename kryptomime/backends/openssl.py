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

from . import (tmpfname, TmpDir, runcmd, SubProcessError,
    ASN_abbrevations, create_DN, parse_DN, split_pem)
from collections import OrderedDict
import os

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
    def __init__(self,executable=None,timeout=None):
        from . import find_binary
        import re
        self.openssl = find_binary(executable, 'openssl')
        versionstr, error = runcmd([self.openssl,'version'],stringio=True)
        version = re.match(r'^OpenSSL (\d).(\d+).(\d+)',versionstr)
        assert not version is None, 'invalid openssl version '+versionstr
        version = [int(version.group(i)) for i in range(1,4)]
        no = version[0]*100+version[1]*10+version[2]
        assert no>=101, "obsolete openssl version "+versionstr
        self.version = version
        self.timeout = timeout

    def run(self, cmd, **kwargs):
        if not 'timeout' in kwargs: kwargs['timeout'] = self.timeout
        return runcmd([self.openssl]+cmd, **kwargs)

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
        if 'passphrase' in kwargs:
            req['output_password'] = kwargs['passphrase']
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

    def generate_selfsigned(self,email,subj=None,pubkey=None,seckey=None,passphrase=None,
        bits=2048,digest='sha256',days=365,args=[]):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_DN(subj,expand=True)
        reqcfg = self.config_req(digest=digest, bits=bits,
            passphrase=passphrase, x509_extensions="v3_email")
        v3_email = self.config_v3_email(selfsigned=True)
        cfg = config_section('req',reqcfg) + config_section('v3_email',v3_email)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        cmd = ['req','-x509','-config',config,'-new','-keyout',seckey,'-days',days,'-batch']
        if not passphrase: cmd.append('-nodes')
        cmd.extend(args)
        try:
            pub, error = self.run(cmd,stringio=True)
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

    def generate_key(self,email,subj=None,req=None,seckey=None,passphrase=None,
        bits=2048,digest='sha256',args=[]):
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        if not subj: subj = 'emailAddress='+email
        else: subj = create_DN(subj,expand=True)
        reqcfg = self.config_req(digest=digest, bits=bits, passphrase=passphrase)
        cfg = config_section('req',reqcfg)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        cmd = ['req','-config',config,'-new','-keyout',seckey,'-batch']
        if not passphrase: cmd.append('-nodes')
        cmd.extend(args)
        try:
            csr, error = self.run(cmd,stringio=True)
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
        passphrase=None,passout=None,cipher='des3',pubkey=False,args=[]):
        cmd = ['rsa','-inform',inform,'-outform',outform]
        env = {}
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        if passout and outform=='pem':
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passout
        if pubkey: cmd.append('-pubin')
        cmd.append('-'+cipher)
        cmd.extend(args)
        try: out, err = self.run(input=key,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        if outform=='pem': return out.decode('ascii')
        return out

    def convert_x509(self,cert,inform='pem',outform='pem',args=[]):
        cmd = ['x509','-inform',inform,'-outform',outform]
        cmd.extend(args)
        try: out, err = self.run(input=cert)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        if outform=='pem': return out.decode('ascii')
        return out

    def decode_x509(self,x509,inform='pem',digest='sha256',args=[]):
        from datetime import datetime
        cmd = ['x509','-noout','-nameopt','oneline','-'+digest,'-inform',inform]
        cmd+= ['-subject','-issuer','-dates','-fingerprint',
                '-subject_hash','-email']+args
        try: out, err = self.run(cmd,input=x509)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        out = out.decode('utf-8','replace').splitlines()
        names = ('subject','issuer')
        dates = ('notBefore','notAfter')
        extra = ('subjectHash','email')
        fields = names+dates+('fingerprint',)+extra
        res = {}
        for i, field in enumerate(fields):
            if field=='email' and i>=len(out): break
            v = out[i]
            if not field in extra:
                if field=='fingerprint':
                    prefix = digest.upper()+' Fingerprint'
                    res['digest'] = digest
                else: prefix = field
                assert v.startswith(prefix+'=')
                v = v[len(prefix)+1:].strip()
            if field in names:
                v = parse_DN(v,separator=', ')
            elif field in dates:
                v = datetime.strptime(v,'%b %d %H:%M:%S %Y %Z')
            res[field] = v
        now = datetime.utcnow()
        res['expired'] = now < res['notBefore'] or now > res['notAfter']
        return res

    def verify_x509(self,x509,cacerts=[],certs=[],args=[]):
        """cacerts must contain all trusted CAs, certs all intermediate CAs,
        must be filename or list of certs. x509 must be PEM format"""
        cmd = ['verify']
        tmpdir = TmpDir()
        if cacerts:
            if isinstance(cacerts,(tuple,list,set)):
                cacerts = tmpdir.generate(data=''.join(cacerts))
            cmd += ['-CAfile',cacerts]
        if certs:
            if isinstance(certs,(tuple,list,set)):
                certs = tmpdir.generate(data=''.join(certs))
            cmd += ['-untrusted',certs]
        cmd.extend(args)
        try: out, err = self.run(cmd,input=x509,stringio=True)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return False
        finally: tmpdir.destroy()
        valid = out.startswith('stdin: OK')
        return valid

    def load_pkcs12(self,pkcs12,passphrase=None,passout=None,
        cacert=True,client=True,private=True,strip=False,split=False,args=[]):
        from six import iteritems
        cmd = ['pkcs12']
        if not cacert:
            cmd.append('-clcerts' if client else '-nocerts')
        elif not client:
            cmd.append('-cacerts')
        env = {}
        if not private: cmd.append('-nokeys')
        elif passout:
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passout
        else: cmd.append('-nodes')
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        cmd.extend(args)
        try: out, err = self.run(cmd,input=pkcs12,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        pem, within = '',False
        if cacert or not split: strip = False
        out = split_pem(out.decode('ascii','ignore'),strip)
        if split: return out
        return ''.join((''.join(v) for k,v in iteritems(out)))

    def create_pkcs12(self,public=None,private=None,passin=None,certs=None,cacerts=None,
        fname=None,passphrase=None,chain=True,digest='sha256',args=[]):
        cmd = ['pkcs12','-export','-macalg',digest]
        if chain: cmd.append('-chain')
        tmpdir = TmpDir()
        if cacerts:
            if isinstance(cacerts,(tuple,list,set)):
                cacerts = tmpdir.generate(data=''.join(cacerts))
            cmd += ['-CAfile',cacerts]
        if certs:
            if isinstance(certs,(tuple,list,set)):
                certs = tmpdir.generate(data=''.join(certs))
            cmd += ['-certfile',certs]
        if private:
            cmd += ['-inkey',tmpdir.generate(data=private)]
        env = {}
        if passphrase:
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passphrase
        if passin:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passin
        if fname: cmd += ['-out',fname]
        cmd.extend(args)
        try: out, err = self.run(cmd,input=public,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        if fname: out = out.decode('ascii')
        return out

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

    def sign(self,msg,public,private=[],passphrase=None,certs=[],
        detach=False,compress=False,version=3,args=[]):
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        cmd = [('smime' if version==2 else 'cms'),'-sign']
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
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        if compress: cmd.append('-compress')
        if detach: cmd.append('-nodetach')
        cmd.extend(args)
        msg = msg.encode('ascii')
        try: out, err = self.run(cmd,input=msg,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out.decode('ascii')

    def encrypt(self,msg,recipients,
        sign=None,private=None,passphrase=None,certs=[],
        cipher='des3',compress=False,version=3,args=[]):
        "cacerts must contain all intermediate and root CAs in chain"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        if sign:
            msg = self.sign(msg,sign,private,passphrase,certs,
                compress=compress,version=version,args=args)
        cmd = [('smime' if version==2 else 'cms'),'-encrypt']
        if cipher: cmd.append('-'+cipher)
        tmpdir = TmpDir()
        cmd = self.write_keys(cmd,recipients,tmpdir)
        cmd.extend(args)
        msg = msg.encode('ascii')
        try: out, err = self.run(cmd,input=msg)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: tmpdir.destroy()
        return out.decode('ascii')

    def verify(self,msg,cacerts=[],certs=[],detach=None,
        compress=False,version=3,args=[]):
        """cacerts must contain all intermediate and root CAs in chain,
        must be filename or list of certs"""
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = [('smime' if version==2 else 'cms'),'-verify']
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
        msg = msg.encode('ascii')
        try:
            out, err = self.run(cmd,input=msg,env=env)
            pub = open(signer).read()
            valid = err.decode('ascii').startswith('Verification successful')
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None, None, None
        finally: tmpdir.destroy()
        return out.decode('ascii'), pub, valid

    def decrypt(self,msg,recipient,private=None,passphrase=None,
        verify=True,cacerts=[],certs=[],
        compress=False,version=3,args=[]):
        "cacerts must be filename or list of trused CA certs"
        from email.message import Message
        if isinstance(msg,Message): msg = msg.as_string()
        env = {}
        cmd = [('smime' if version==2 else 'cms'),'-decrypt']
        tmpdir = TmpDir()
        pubkey = tmpdir.generate(data=recipient)
        cmd += ['-recip',pubkey]
        if private:
            seckey = tmpdir.generate(data=private)
            cmd += ['-inkey',seckey]
        env = {}
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        if compress: cmd.append('-uncompress')
        cmd.extend(args)
        msg = msg.encode('ascii')
        try: out, err = self.run(cmd,input=msg,env=env)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            if not verify: return None
            return None, None, None
        finally: tmpdir.destroy()
        out = out.decode('ascii')
        if not verify: return out
        return self.verify(out,cacerts=cacerts,certs=certs,
            compress=compress,version=version,args=args)

class OpenSSL_CA(OpenSSL):
    def __init__(self,directory=None,passphrase=None,**kwargs):
        super(OpenSSL_CA,self).__init__(**kwargs)
        self.dir = os.path.abspath(directory or os.getcwd())
        self.passphrase = passphrase
        self.cacert = None
        fname = os.path.join(self.dir,'cacert.pem')
        if os.path.exists(fname):
            self.cacert = open(fname,'rt').read()

    def generate_crl(self,days=None,args=[]):
        cmd = ['ca','-config','openssl.cnf','-batch',
            '-notext','-gencrl','-out','crls/crl.pem']
        if days: cmd += ['-crldays',str(days)]
        cmd.extend(args)
        env = {}
        if self.passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = self.passphrase
        cmd2 = ['crl','-inform','pem','-outform','der',
            '-in','crls/crl.pem','-out','crls/crl.der']
        try:
            out, err = self.run(cmd,cwd=self.dir,env=env,stringio=True)
            out, err = self.run(cmd2,cwd=self.dir,stringio=True)
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

    def config_distinguished_name(self,defaults={}):
        from six import iteritems
        rdn = dict([
            ("countryName", "Some Country"),
            ("stateOrProvinceName", "Some State"),
            ("localityName", "Some Locality"),
            ("organizationalUnitName", "Some Unit"),
        ])
        for k,v in iteritems(defaults):
            rdn[ASN_abbrevations.get(k,k)] = v
        return OrderedDict([
            ("countryName", "Country Name (2 letter code)"),
            ("countryName_default", rdn["countryName"]),
            ("countryName_min", "2"),
            ("countryName_max", "2"),
            ("stateOrProvinceName", "State or Province Name (full name)"),
            ("stateOrProvinceName_default", rdn["stateOrProvinceName"]),
            ("localityName", "Locality Name (eg, city)"),
            ("localityName_default", rdn["localityName"]),
            ("organizationalUnitName", "Organizational Unit Name (eg, section)"),
            ("organizationalUnitName_default", rdn["organizationalUnitName"]),
            ("commonName", "Common Name (e.g. server FQDN or YOUR name)"),
            ("commonName_max", "64"),
            ("emailAddress", "Email Address"),
            ("emailAddress_max", "64"),
        ])

    def config_defaults(self, **kwargs):
        bits = kwargs.get('bits',2048)
        digest = kwargs.get('digest','sha256')
        req = self.config_req(digest=digest, bits=bits, attributed="req_attributes",
            # The extensions to add to a certificate request
            req_extensions=kwargs.get('req_extensions','v3_email'))
        ca = OrderedDict(default_ca="CA_default")	# The default ca section
        req_distinguished_name = self.config_distinguished_name()
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
        subj = create_DN(subj,expand=True)
        reqcfg = self.config_req(digest=digest, bits=bits, x509_extensions='v3_ca')
        v3_ca = self.config_v3_ca()
        cfg = config_section('req',reqcfg) + config_section('v3_ca',v3_ca)
        cfg+= "[req_distinguished_name]\n%s\n" % subj
        config = tmpfname(data=cfg)
        seckey = os.path.join(dir,'private','cakey.pem')
        cmd = ['req','-config',config,'-batch','-x509','-new',
            '-keyout','private/cakey.pem','-out','cacert.pem','-days',str(days)]
        env = {}
        if self.passphrase:
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = self.passphrase
        else: cmd.append('-nodes')
        cmd.extend(args)
        try: out, error = self.run(cmd,cwd=dir,env=env,stringio=True)
        except SubProcessError as e:
            print ('error', e.error)
            return None
        finally: os.unlink(config)
        self.generate_crl()
        self.cacert = open(os.path.join(dir,'cacert.pem'),'rt').read()
        return self.cacert

    def sign_key(self,csr,cacert=False,pubkey=None,days=365,policy=None,args=[]):
        req = tmpfname(data=csr)
        cmd = ['ca','-config','openssl.cnf','-batch','-notext','-in',req,'-days',str(days)]
        if policy: cmd += ['-policy',policy]
        env = {}
        if self.passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = self.passphrase
        cmd.extend(args)
        try: crt, err = self.run(cmd,cwd=self.dir,env=env,stringio=True)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally: os.unlink(req)
        if pubkey:
            with open(pubkey,'wt') as f: f.write(crt)
        if cacert: crt += self.cacert
        return crt
