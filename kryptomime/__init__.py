# -*- coding: utf-8 -*-
#
# EMail kryptography support
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

from .mail import KryptoMIME, ProtectedMessage, create_mail, protect_mail
from .pgp import GPGMIME
from .transport import IMAP4_TLS, SMTP_TLS
version = (0,2,0) # major (backwards incompatible), minor (backwards compatible, feature-level), implementation (bugfixes)
