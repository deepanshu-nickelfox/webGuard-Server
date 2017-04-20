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

from __future__ import unicode_literals

from django.db import models

# Create your models here.

class ZAPServer(models.Model):
	ip = models.CharField(max_length = 255, verbose_name = "IP")
	register_time = models.DateTimeField(auto_now_add = True, verbose_name = "Registration Time")
	unregister_time = models.DateTimeField(auto_now = True, verbose_name = "De-registration Time")
	enabled = models.BooleanField(verbose_name = "Enabled", default = True)
	
	def __unicode__(self):
                return self.ip

class ZAPInstance(models.Model):
	name = models.CharField(max_length = 255, verbose_name = "Name")
	server = models.ForeignKey(ZAPServer, verbose_name = "Server")
	port = models.IntegerField(verbose_name = "Port")
	api_key = models.CharField(max_length = 255, verbose_name = "API Key")
	user = models.CharField(max_length = 255, verbose_name = "Username")
	session = models.CharField(max_length = 255, verbose_name = "Session")
	pid = models.IntegerField(verbose_name = "PID")
	start_time = models.DateTimeField(auto_now_add = True, verbose_name = "Start Time")
	end_time = models.DateTimeField(auto_now = True, verbose_name = "End Time")
	enabled = models.BooleanField(verbose_name = "Enabled", default = True)
	
	def __unicode__(self):
                return "%s:%s" % (self.server.ip, self.port)

class ZAPScan(models.Model):
	instance = models.ForeignKey(ZAPInstance, verbose_name = "ZAP Instance")
	scanId = models.IntegerField(verbose_name = "Scan ID")
	user = models.CharField(max_length = 255, verbose_name = "Username")
	url = models.TextField(verbose_name = "URL")

	def __unicode__(self):
		return "%s - %s - %s" % (self.scanId, self.user, self.url)

class User(models.Model):
	username = models.CharField(max_length = 255, verbose_name = "Username", unique=True)
	password = models.TextField(verbose_name = "Password")
	enabled = models.BooleanField(verbose_name = "Enabled", default = True)
	created = models.DateTimeField(auto_now_add = True, verbose_name = "Created At")
	last_login = models.DateTimeField(auto_now = True, verbose_name = "Last Login")
	
	def __unicode__(self):
                return "%s" % self.username
