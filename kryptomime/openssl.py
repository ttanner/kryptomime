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

from .utils import (tmpfname, TmpDir, runcmd, SubProcessError,
    ASN_abbrevations, create_DN, parse_DN, split_pem)
from collections import OrderedDict
import os

def config_section(name,cfg):
    from six import iteritems
    if not cfg: return ''
    s = '[ %s ]\n' % name if name else ''
    if isinstance(cfg,dict): cfg = cfg.items()
    subidx, subs = 1, []
    for k,v in cfg:
        if isinstance(v,dict):
            # {'critical':'','CA':'true','pathlen':0}
            sub = ''
            for sk,sv in iteritems(v):
                if sub: sub += ','
                sub += sk+(':'+str(sv) if sv!='' else '')
            s += '%s = %s\n' % (k,sub)
        elif isinstance(v,(list,tuple)):
            # ['critical',{'CA':'true','pathlen':0}]
            sub = ''
            for sv in v:
                if sub: sub += ','
                if isinstance(sv,(dict,list,tuple)):
                    subname = name+'_'+str(subidx)
                    subidx += 1
                    sub += '@'+subname
                    subs.append((subname,sv))
                else:
                    sub += str(sv)
            s += '%s = %s\n' % (k,sub)
        else:
            s += '%s = %s\n' % (k,v)
    for subname, sub in subs:
        s += config_section(subname,sub)
    return s

def merge_config(a,b):
    dicta, dictb = isinstance(a,dict), isinstance(b,dict)
    if dicta and dictb:
        c = a.copy()
        c.update(b.items())
        return c
    if dicta: a = a.items()
    elif dictb: b = b.items()
    return a + b

def generate_config(cfg,extra):
    from six import iteritems
    s = ''
    for k,v in iteritems(cfg):
        if k in extra:
            v = extra[k]
            if v is None: continue
        if s: s+='\n'
        s += config_section(k,v)
    for k,v in iteritems(extra):
        if k in cfg or not v: continue
        if s: s+='\n'
        s += config_section(k,v)
    return s

def _parse_text(lines,i,prefix):
    res, vals = OrderedDict(), []
    lastid = ''
    while i<len(lines):
        line = lines[i].rstrip()
        if not line:
            i += 1
            continue # ignore empty line
        sline = line.lstrip()
        pref = line[:-len(sline)]
        if not prefix: prefix = pref
        if len(pref)<len(prefix): break # move up
        if len(pref)>len(prefix): # move down
            sub, i = _parse_text(lines,i,pref)
            if sub=='<EMPTY>': sub = ''
            old = res[lastid]
            if old: sub = (old,sub)
            res[lastid] = sub
        else: # same level
            j = sline.find(':')
            jj = sline.find(':',j+1)
            xline = sline.split(', ')
            if j<0 or (j,jj)==(2,5): # raw or fingerprint
                vals.extend(xline)
            elif not res and len(xline)>1 and jj>j: # multiple values
                vals.extend([pair.split(':',1) for pair in xline])
            else: # key: values
                lastid = sline[:j]
                sline = sline[j+1:].lstrip().split(', ')
                if len(sline)==1: sline = sline[0]
                if lastid in res or lastid+'.1' in res:
                    if lastid in res:
                        res[lastid+'.1'] = res.pop(lastid)
                    k = 2
                    while True:
                        nid = lastid+'.%i' % k
                        if not nid in res:
                            lastid = nid
                            break
                        k += 1
                res[lastid] = sline
            i += 1
    if not res:
        if len(vals)==1: vals = vals[0]
        return vals, i
    return res, i

class OpenSSL(object):
    def __init__(self,executable=None,timeout=None):
        from .utils import find_binary
        import re
        self.openssl = find_binary(executable, 'openssl')
        versionstr, error = runcmd([self.openssl,'version'],stringio=True)
        version = re.match(r'^OpenSSL (\d).(\d+).(\d+)',versionstr)
        assert not version is None, 'invalid openssl version '+versionstr
        version = [int(version.group(i)) for i in range(1,4)]
        no = version[0]*100+version[1]*10+version[2]
        assert no>=101, 'obsolete openssl version '+versionstr
        self.version = version
        self.timeout = timeout

    def run(self, cmd, **kwargs):
        if not 'timeout' in kwargs: kwargs['timeout'] = self.timeout
        return runcmd([self.openssl]+cmd, **kwargs)

    def config_req(self, **kwargs):
        bits = kwargs.pop('bits',2048)
        digest = kwargs.pop('digest','sha256')
        req = [
            ('prompt', 'no'),
            ('default_bits', str(bits)),
            ('default_md', digest),
            ('distinguished_name', 'req_distinguished_name'),
            ('string_mask', 'utf8only'),
        ]
        if 'passphrase' in kwargs:
            req.append(('output_password',kwargs.pop('passphrase')))
        req.extend(kwargs.items())
        return req

    def _req_config(self,subj,altname=None,extensions=[],root=False,**kwargs):
        subj = create_DN(parse_DN(subj),expand=True)
        reqcfg = self.config_req(**kwargs)
        if altname:
            extensions = merge_config(extensions,self.config_altname(altname))
        cfg = config_section('',reqcfg)
        if extensions:
            cfg += config_section('ext',extensions)
        cfg+= '[ req_distinguished_name ]\n%s\n' % subj
        req = tmpfname(data=cfg)
        cmd = ['req','-config',req,'-batch','-new']
        if extensions:
            cmd += ['-extensions' if root else '-reqexts','ext']
        return cmd, req

    def generate_key(self,subj,altname=None,seckey=None,passphrase=None,
        bits=2048,digest='sha256',extensions=[],args=[]):
        "generate key and CSR for subj. The key is written to seckey if specified."
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        cmd, req = self._req_config(subj, altname, digest=digest, bits=bits,
             passphrase=passphrase, extensions=extensions)
        cmd += ['-keyout',seckey]
        if not passphrase: cmd.append('-nodes')
        cmd.extend(args)
        try:
            csr, error = self.run(cmd,input=req,stringio=True)
            sec = open(seckey,'rt').read()
        except SubProcessError as e:
            print ('error', e.error)
            return None, None
        finally:
            os.unlink(req)
            if tmpsec: os.unlink(seckey)
        return csr, sec

    def generate_request(self,key,subj,altname=None,passphrase=None,
        digest='sha256',extensions=[],args=[]):
        "generate CSR for key and subj."
        cmd, req = self._req_config(subj, altname, digest=digest, extensions=extensions)
        cmd += ['-key',key]
        env = {}
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        cmd.extend(args)
        try:
            csr, error = self.run(cmd,input=req,stringio=True,env=env)
        except SubProcessError as e:
            print ('error', e.error)
            return None, None
        finally: os.unlink(req)
        return csr

    def generate_private(self,bits=2048,seckey=None,passphrase=None,pkcs8=True,
        cipher=None,args=[]):
        "generate key and optionally encrypt it. It is written to seckey, if specified."
        tmpsec = pkcs8 or not seckey
        origsec = seckey
        if tmpsec: seckey = tmpfname()
        cmd = ['genrsa','-out',seckey]
        env = {}
        if not pkcs8 and cipher and passphrase:
            cmd +=['-'+cipher, '-passout','env:PASSOUT']
            env['PASSOUT'] = passphrase
        cmd.extend(args)
        cmd.append(str(bits))
        try:
            out, error = self.run(cmd,stringio=True)
            sec = open(seckey,'rt').read()
        except SubProcessError as e:
            print ('error', e.error)
            return None
        finally:
            if tmpsec: os.unlink(seckey)
        if pkcs8:
            sec = self.convert_key(sec,passout=passphrase,
                cipher=cipher,pkcs8=True,args=args)
            if origsec: open(origsec,'wt').write(sec)
        return sec

    def convert_key(self,key,inform='pem',outform='pem',
        passphrase=None,passout=None,cipher=None,
        pubkey=False,pkcs8=False,args=[]):
        if cipher: assert passout, 'passphrase missing'
        elif passout: cipher = 'des3'
        if pkcs8:
            cmd = ['pkcs8','-topk8']
            if cipher: cmd += ['-v2',cipher or 'des3']
            else: cmd.append('-nocrypt')
        else:
            cmd = ['rsa']
            if cipher: cmd += ['-'+cipher]
        cmd += ['-inform',inform,'-outform',outform]
        env = {}
        if passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = passphrase
        if passout and outform=='pem':
            cmd +=['-passout','env:PASSOUT']
            env['PASSOUT'] = passout
        if pubkey:
            assert not pkcs8, 'pubkey not supported for pkcs8 conversion'
            cmd.append('-pubin')
        cmd.extend(args)
        try: out, err = self.run(cmd, input=key,env=env)
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

    def _trust_x509(self,cert,use=None,reject=False,clear=False,alias=None,
        inform='pem',outform='pem',args=[]):
        cmd = ['x509','-inform',inform,'-outform',outform,'-trustout']
        if reject:
            if clear: cmd.append('-clrreject')
            if use: cmd += ['-addreject',use]
        else:
            if clear: cmd.append('-clrtrust')
            if use: cmd += ['-addtrust',use]
        if alias: cmd += ['-setalias',alias]
        cmd.extend(args)
        try: out, err = self.run(input=cert)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        if outform=='pem': return out.decode('ascii')
        return out

    def trust_x509(self,cert,use=None,clear=False,alias=None,
        inform='pem',outform='pem',args=[]):
        return self._trust_x509(cert,use,False,clear,alias,inform,outform,args)

    def reject_x509(self,cert,use=None,clear=False,alias=None,
        inform='pem',outform='pem',args=[]):
        return self._trust_x509(cert,use,True,clear,alias,inform,outform,args)

    def decode_x509(self,x509,inform='pem',digest='sha256',args=[]):
        from datetime import datetime
        cmd = ['x509','-noout','-nameopt','oneline','-'+digest,'-inform',inform]
        cmd+= ['-text','-subject','-issuer','-dates','-serial','-fingerprint',
                '-subject_hash','-email']
        cmd+= ['-certopt', 'no_issuer,no_subject,no_serial,no_validity,no_signame,no_sigdump,no_pubkey,ext_error']
        cmd.extend(args)
        try: out, err = self.run(cmd,input=x509)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        out = out.decode('utf-8','replace').splitlines()
        res, i = _parse_text(out,2,'')
        res['type'] = out[0][:-1]
        out = out[i:]
        names = ('subject','issuer')
        dates = ('notBefore','notAfter')
        extra = ('subjectHash','email')
        fields = names+dates+('serial','fingerprint',)+extra
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
                v = '' if v=='<EMPTY>' else parse_DN(v,separator=', ')
            elif field in dates:
                v = datetime.strptime(v,'%b %d %H:%M:%S %Y %Z')
            res[field] = v
        now = datetime.utcnow()
        res['expired'] = now < res['notBefore'] or now > res['notAfter']
        return res

    def decode_req(self,req,inform='pem',args=[]):
        from datetime import datetime
        cmd = ['req','-batch','-noout','-nameopt','oneline','-inform',inform,'-text','-subject']
        cmd+= ['-reqopt', 'no_issuer,no_subject,no_serial,no_validity,no_signame,no_sigdump,no_pubkey']
        cmd.extend(args)
        try: out, err = self.run(cmd,input=req)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        out = out.decode('utf-8','replace').splitlines()
        res, i = _parse_text(out,2,'')
        res['type'] = out[0][:-1]
        subj = out[i]
        res['subject'] = '' if subj=='<EMPTY>' else parse_DN(subj,separator=', ')
        return res

    def verify_x509(self,x509,cacerts=[],certs=[],args=[]):
        """cacerts must contain all trusted CAs, certs all intermediate CAs,
        must be filename or list of certs. x509 must be PEM format."""
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
            return False, e.error
        finally: tmpdir.destroy()
        return out.startswith('stdin: OK'), None

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

    def create_pkcs12(self,public=None,private=None,passin=None,
        certs=None,cacerts=None,fname=None,passphrase=None,
        name=None,caname=None,chain=True,digest='sha256',args=[]):
        cmd = ['pkcs12','-export','-macalg',digest]
        if chain: cmd.append('-chain')
        if name: cmd += ['-name',name]
        if caname: cmd += ['-caname',caname]
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

    def config_v3(self,req=False):
        c = [('subjectKeyIdentifier', 'hash')]
        if not req: c += [('issuerAltName', 'issuer:copy')]
        return c

    def config_altname(self, altname='email:copy'):
        return [('subjectAltName', altname)]

    def config_v3_email(self,selfsigned=False):
        return [
            ('basicConstraints', 'CA:'+str(selfsigned).upper()),
            ('authorityKeyIdentifier', 'keyid,issuer:always'),
            ('keyUsage', 'critical, digitalSignature, nonRepudiation, keyEncipherment'), # symmetric key
            ('extendedKeyUsage', 'emailProtection'),
        ]

    def config_v3_ssl(self,selfsigned=False):
        return [
            ('basicConstraints', 'CA:'+str(selfsigned).upper()),
            ('authorityKeyIdentifier', 'keyid,issuer:always'),
            ('keyUsage', 'critical, digitalSignature, keyEncipherment, keyAgreement'), # DH
            ('extendedKeyUsage', 'serverAuth, clientAuth'),
        ]

    def generate_selfsigned(self,subj,seckey=None,passphrase=None,
        bits=2048,digest='sha256',days=365,extensions='v3_email',args=[]):
        from six import iteritems
        tmpsec = not seckey
        if tmpsec: seckey = tmpfname()
        subj = create_DN(parse_DN(subj),expand=True)
        if extensions == 'v3_email':
            extensions = self.config_v3()+self.config_v3_email(selfsigned=True)
        elif extensions == 'v3_ssl':
            extensions = self.config_v3()+self.config_v3_ssl(selfsigned=True)
        reqcfg = self.config_req(digest=digest, bits=bits,
            passphrase=passphrase, x509_extensions=extensions)
        cfg = config_section('req',reqcfg)
        cfg+= '[req_distinguished_name]\n%s\n' % subj
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
        return pub, sec

class OpenSSL_CA(OpenSSL):
    def __init__(self,directory=None,passphrase=None,**kwargs):
        super(OpenSSL_CA,self).__init__(**kwargs)
        self.dir = os.path.abspath(directory or os.getcwd())
        self.passphrase = passphrase
        self.cacert = None # CA cert
        self.chain = None # chain to root CA
        fname = os.path.join(self.dir,'cacert.pem')
        if os.path.exists(fname):
            self.cacert = open(fname,'rt').read()
        fname = os.path.join(self.dir,'chain.pem')
        if os.path.exists(fname):
            self.chain = open(fname,'rt').read()

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

    def config_v3_ca(self, req=False):
        c = [
            ('basicConstraints', 'critical,CA:true'),
            ('keyUsage', 'cRLSign, keyCertSign'),
        ]
        if not req: c += [('authorityKeyIdentifier', 'keyid:always,issuer:always')]
        return c

    def config_v3_ocsp(self):
        return [
            ('basicConstraints', 'CA:false'),
            ('keyUsage', 'nonRepudiation, digitalSignature, keyEncipherment'),
            ('extendedKeyUsage', 'OCSPSigning'),
        ]

    def config_CA_default(self, **kwargs):
        digest = kwargs.get('digest','sha256')
        days = kwargs.get('days',365)
        crldays = kwargs.get('crldays',30)
        ext = kwargs.get('x509_extensions','v3_email')
        policy = kwargs.get('policy','policy_any')
        return [
            ('dir', '.'), # Where everything is kept
            ('certs', '$dir/certs'),		# Where the issued certs are kept
            ('crl_dir', '$dir/crl'),		# Where the issued crl are kept
            ('database', '$dir/index.txt'),	# database index file.
            ('new_certs_dir', '$dir/newcerts'),		# default place for new certs.
            ('certificate', '$dir/cacert.pem'), 	# The CA certificate
            ('serial', '$dir/cacert.srl'), 		# The current serial number
            ('crlnumber', '$dir/crlnumber'),	# the current crl number
            ('crl', '$dir/crl.pem'), 		# The current CRL
            ('private_key', '$dir/private/cakey.pem'), # The private key
            ('RANDFILE', '$dir/private/.rand'),	# private random number file
            ('x509_extensions', ext),		# The extentions to add to the cert
            ('default_days', str(days)),			# how long to certify for
            ('default_crl_days', str(crldays)),			# how long before next CRL
            ('default_md', digest),		# use public key default MD
            ('preserve', 'no'),			# keep passed DN ordering
            ('email_in_dn', 'no'),		# keep email only in altName
            ('policy', policy),
            ('copy_extensions', 'copy'),
        ]

    def config_policies(self):
        policy_match = [
            ('countryName', 'match'),
            ('stateOrProvinceName', 'match'),
            ('organizationName', 'match'),
            ('organizationalUnitName', 'optional'),
            ('commonName', 'supplied'),
            ('emailAddress', 'optional'),
        ]
        policy_any = [
            ('countryName', 'optional'),
            ('stateOrProvinceName', 'optional'),
            ('localityName', 'optional'),
            ('organizationName', 'optional'),
            ('organizationalUnitName', 'optional'),
            ('commonName', 'supplied'),
            ('emailAddress', 'optional'),
        ]
        return OrderedDict([
            ('policy_match', policy_match),
            ('policy_any', policy_any),
        ])

    def config_extensions(self):
        crl_ext = [
            ('issuerAltName', 'issuer:copy'),
            ('authorityKeyIdentifier', 'keyid:always'),
        ]
        return OrderedDict([
            ('v3_email', self.config_v3()+self.config_v3_email()),
            ('v3_ssl', self.config_v3()+self.config_v3_ssl()),
            ('v3_ca', self.config_v3()+self.config_v3_ca()),
            ('v3_ocsp', self.config_v3_ocsp()),
            ('crl_ext', crl_ext),
        ])

    def config_distinguished_name(self,defaults={}):
        from six import iteritems
        rdn = dict([
            ('countryName', 'Some Country'),
            ('stateOrProvinceName', 'Some State'),
            ('localityName', 'Some Locality'),
            ('organizationalUnitName', 'Some Unit'),
        ])
        for k,v in iteritems(defaults):
            rdn[ASN_abbrevations.get(k,k)] = v
        return [
            ('countryName', 'Country Name (2 letter code)'),
            ('countryName_default', rdn['countryName']),
            ('countryName_min', '2'),
            ('countryName_max', '2'),
            ('stateOrProvinceName', 'State or Province Name (full name)'),
            ('stateOrProvinceName_default', rdn['stateOrProvinceName']),
            ('localityName', 'Locality Name (eg, city)'),
            ('localityName_default', rdn['localityName']),
            ('organizationalUnitName', 'Organizational Unit Name (eg, section)'),
            ('organizationalUnitName_default', rdn['organizationalUnitName']),
            ('commonName', 'Common Name (e.g. server FQDN or YOUR name)'),
            ('commonName_max', '64'),
            ('emailAddress', 'Email Address'),
            ('emailAddress_max', '64'),
        ]

    def config_defaults(self, **kwargs):
        bits = kwargs.get('bits',2048)
        digest = kwargs.get('digest','sha256')
        req = self.config_req(digest=digest, bits=bits, attributes='req_attributes',
            # The extensions to add to a certificate request
            req_extensions=kwargs.get('req_extensions','v3_email'))
        ca = dict(default_ca='CA_default')	# The default ca section
        req_distinguished_name = self.config_distinguished_name(kwargs.get('dndefaults',{}))
        req_attributes = [
            ('challengePassword', 'A challenge password'),
            ('challengePassword_min', '4'),
            ('challengePassword_max', '20'),
        ]
        cfg = OrderedDict([
            ('ca', ca),
            ('CA_default', self.config_CA_default(digest=digest) ),
            ('req', req),
            ('req_distinguished_name', req_distinguished_name),
            ('req_attributes', req_attributes),
        ])
        cfg.update(self.config_extensions())
        cfg.update(self.config_policies())
        return cfg

    def _generate_ca(self, subj, altname=None, key=None, bits=4096,
        digest='sha256',days=3650,config=None,extra={},extensions=None,args=[], root=False):
        from six import iteritems
        dir = self.dir
        if not os.path.isdir(dir):
            os.makedirs(dir,0o700)
        for sub in ('certs','crls','private','newcerts'):
            subdir = os.path.join(dir,sub)
            if not os.path.isdir(subdir): os.mkdir(subdir)
        open(os.path.join(dir,'cacert.srl'),'wt').write('1000\n')
        open(os.path.join(dir,'crlnumber'),'wt').write('00\n')
        open(os.path.join(dir,'index.txt'),'wt').write('')
        if config is None:
            config = self.config_defaults(digest=digest)
        config = generate_config(config, extra)
        open(os.path.join(dir,'openssl.cnf'),'wt').write(config)
        # compile the request
        if extensions is None:
            extensions = self.config_v3(req=not root)+self.config_v3_ca(req=not root)
        cmd, req = self._req_config(subj, altname, digest=digest, bits=bits, extensions=extensions, root=root)
        cmd += ['-days',str(days)]
        seckey = os.path.join(dir,'private','cakey.pem')
        env = {}
        if key:
            open(seckey,'wt').write(key)
            cmd += ['-key',seckey]
            if self.passphrase:
                cmd +=['-passin','env:PASSIN']
                env['PASSIN'] = self.passphrase
        else:
            cmd += ['-keyout',seckey]
            if self.passphrase:
                cmd +=['-passout','env:PASSOUT']
                env['PASSOUT'] = self.passphrase
            else: cmd.append('-nodes')
        cmd.extend(args)
        try: out, error = self.run(cmd,input=req,cwd=dir,env=env,stringio=True)
        except SubProcessError as e:
            print ('error', e.error)
            return None
        finally: os.unlink(req)
        return out

    def generate_root_ca(self, subj, altname=None, key=None, bits=4096,
        digest='sha256',days=3650,config=None,extra={},extensions=None,args=[]):
        fname = os.path.join(self.dir,'cacert.pem')
        args = ['-x509','-out',fname] + args
        crt = self._generate_ca(subj, altname, key, bits, digest, days, config, extra, extensions, args, root=True)
        if crt is None: return None
        self.cacert = open(fname,'rt').read()
        self.generate_crl()
        return self.cacert

    def generate_ca_req(self, subj, altname=None, key=None, bits=4096,
        digest='sha256',days=730,config=None,extra={},extensions=None,args=[]):
        return self._generate_ca(subj, altname, key, bits, digest, days, config, extra, extensions, args)

    def set_cert(self, cert, chain=None):
        self.cacert = cert
        open(os.path.join(self.dir,'cacert.pem'),'wt').write(cert)
        self.chain = chain
        if chain:
            open(os.path.join(self.dir,'chain.pem'),'wt').write(chain)
        self.generate_crl()

    def get_chain(self):
        chain = self.cacert
        if self.chain: chain += self.chain
        return chain

    def sign_key(self,csr,cacert=False,chain=False,days=365,extensions=[],policy=None,args=[]):
        from six import string_types
        # todo multiple csrs
        req = tmpfname(data=csr)
        cmd = ['ca','-config','openssl.cnf','-batch','-notext','-in',req,'-days',str(days)]
        extra = None
        if not extensions: pass
        elif isinstance(extensions, string_types):
            cmd += ['-extensions',extensions]
        else:
            extfile = tmpfname(data=config_section('ext',extensions))
            cmd += ['-extfile',extfile,'-extensions','ext']
        if policy: cmd += ['-policy',policy]
        env = {}
        if self.passphrase:
            cmd +=['-passin','env:PASSIN']
            env['PASSIN'] = self.passphrase
        cmd.extend(args)
        cmd += ['-in',req]
        try: crt, err = self.run(cmd,cwd=self.dir,env=env,stringio=True)
        except SubProcessError as e:
            print ('error',e.error, e.output)
            return None
        finally:
            os.unlink(req)
            if extra: os.unlink(extfile)
        if cacert: crt += self.cacert
        if chain and self.chain: crt += self.chain
        return crt

    def generate_sub_ca(self, sub, subj, altname=None, key=None, bits=4096,
        digest='sha256',days=730,config=None,extra={},req_extensions=[],extensions='v3_ca',
        policy='policy_match',args=[]):
        from six import string_types
        assert isinstance(sub,OpenSSL_CA), 'sub CA required'
        if extensions and not isinstance(extensions, string_types): # override CA defaults
            if altname: extensions = merge_config(extensions,self.config_altname(altname))
            altname = None
        csr = sub._generate_ca(subj, altname, key, bits, digest, days, config, extra, req_extensions, args)
        if csr is None: return None
        cert = self.sign_key(csr,days=days,extensions=extensions,policy=policy)
        sub.set_cert(cert,self.get_chain())
        return cert

    def generate_signed_key(self,subj,altname=None,seckey=None,passphrase=None,
        bits=2048,digest='sha256',cacert=False,chain=False,days=365,
        req_extensions=[],extensions='v3_email',policy=None,args=[]):
        from six import string_types
        if extensions and not isinstance(extensions, string_types): # override CA defaults
            if altname: extensions = merge_config(extensions,self.config_altname(altname))
            altname = None
        csr, sec = self.generate_key(subj,altname,seckey,passphrase,bits,digest,req_extensions,args)
        if not csr: return None
        cert = self.sign_key(csr,cacert,chain,days,extensions,policy)
        return cert, sec
