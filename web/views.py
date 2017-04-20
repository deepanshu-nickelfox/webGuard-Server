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

from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.conf import settings

from api.models import *
from api.views import list_active_zap

from utils import client, login_check

# Create your views here.

def index(request):
	return HttpResponseRedirect(reverse("web:home", kwargs={'zap_index': 0}))

def login(request):
	try:
		login_type = settings.LOGIN_METHOD
	except:
		login_type = "LOCAL"
	if login_check.is_logged_in(request):
		return HttpResponseRedirect(reverse("web:landing"))
	return render(request, 'login.html', {"login_type": login_type.upper()})

def landing(request):
	if not login_check.is_logged_in(request):
                return HttpResponseRedirect(reverse("web:login"))

	return HttpResponseRedirect(reverse("web:home", kwargs={'zap_index': 0}))

def home(request, zap_index):
	if not login_check.is_logged_in(request):
		return HttpResponseRedirect(reverse("web:login"))

	username = request.session['login_username']
	instances = list_active_zap(username)
	all_instances = instances

	zap_instances = []
	if instances:
		zap_index = int(zap_index)
		if not settings.ZAP_MULTIPLE_ALLOWED and not zap_index == 0:
			return HttpResponseRedirect(reverse("web:home", kwargs={'zap_index': 0}))
		try:
			instances = instances[zap_index]
		except:
			return HttpResponseRedirect(reverse("web:home", kwargs={'zap_index': 0}))

		if not settings.ZAP_MULTIPLE_ALLOWED:
			zap_instances = [instances]
		else:
			zap_instances = all_instances[:settings.ZAP_MULTIPLE_MAX_COUNT]

	return render(request, 'home.html', {"username": username, "instances": instances, "ZAP_MULTIPLE_ALLOWED": settings.ZAP_MULTIPLE_ALLOWED, "zap_instances": zap_instances, "ZAP_MULTIPLE_MAX_COUNT": settings.ZAP_MULTIPLE_MAX_COUNT})

