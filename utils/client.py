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

import json, socket
from base64 import b64encode

def query_instance(ip, command):
        PORT = 30115
        HOST = ip
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST,PORT))
        s.send(command)
        reply = s.recv(8192)
        s.close()
        return reply

def get_server_stats(ip):
        return json.loads(query_instance(ip, "STATS"))

def start_zap_instance(ip):
        response = query_instance(ip, "START")
        return response.split()

def stop_zap_instance(ip, port):
        return json.loads(query_instance(ip, "STOP %s" % port))

def get_zap_health(ip, port):
        return json.loads(query_instance(ip, "HEALTH %s" % port))

def write_zap_hosts(ip, port, data):
	data = b64encode(data)
	return json.loads(query_instance(ip, "WRITE %s %s" % (port, data)))

def get_zap_hosts(ip, port):
	return json.loads(query_instance(ip, "HOSTS %s" % port))
