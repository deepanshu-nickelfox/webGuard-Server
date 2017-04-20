# Copyright 2017 MakeMyTrip (Kunal Aggarwal, Avinash Jain)
#
# This file is part of WebGuard.
#
# WebGuard is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# WebGuard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WebGuard.  If not, see <http://www.gnu.org/licenses/>.

import ldap
import json

from django.conf import settings

def login(username, password):
	conn = ldap.initialize("ldap://%s:%s" % (settings.LOGIN_LDAP_SERVER, settings.LOGIN_LDAP_PORT))
	conn.protocol_version = 3
	conn.set_option(ldap.OPT_REFERRALS, 0)
	try:
		response = conn.simple_bind_s("%s@%s" % (username, settings.LOGIN_LDAP_DOMAIN_NAME), password)
		return {"status": True, "message": "Login Success"}
	except ldap.INVALID_CREDENTIALS:
		return {"status": False, "message": "Login Failed"}
		
