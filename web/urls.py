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

from django.conf.urls import url

from . import views

urlpatterns = [
	url(r'^login$', views.login, name = 'login'),
	url(r'^home/$', views.landing, name = 'landing'),
	url(r'^home/(?P<zap_index>\d+)', views.home, name = 'home'),
]
