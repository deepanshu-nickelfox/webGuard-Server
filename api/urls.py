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
	url(r'^logout$', views.logout, name = 'logout'),
	url(r'^register$', views.register, name = 'register'),
	url(r'^unregister$', views.unregister, name = 'unregister'),

	# ZAP INSTANCE API URLS
	url(r'^zap/list$', views.zap_list, name = 'zap_list'),
	url(r'^zap/start$', views.zap_start, name = 'zap_start'),
	url(r'^zap/stop/(?P<ip>[0-9.]+)/(?P<port>[0-9]+)$', views.zap_stop, name = 'zap_stop'),
	url(r'^zap/get/logs/(?P<ip>[0-9.]+)/(?P<port>[0-9]+)$', views.zap_get_logs, name = 'zap_get_logs'),

	# ZAP SCAN URLS
	url(r'^zap/scan/start$', views.zap_scan_start, name = 'zap_scan_start'),
	url(r'^zap/scan/stop$', views.zap_scan_stop, name = 'zap_scan_stop'),
	url(r'^zap/scan/list$', views.zap_scan_list, name = 'zap_scan_list'),
	url(r'^zap/scan/report$', views.zap_scan_report, name = 'zap_scan_report'),
	url(r'^zap/scan/report/email$', views.zap_scan_report_email, name = 'zap_scan_report_email'),
	url(r'^zap/scan/report/save$', views.zap_scan_report_save, name = 'zap_scan_report_save'),
	url(r'^zap/scan/url$', views.zap_scan_url, name = 'zap_scan_url'),

	# ZAP HOST FILE URLS
	url(r'^zap/hosts/list$', views.zap_hosts_list, name = 'zap_hosts_list'),
	url(r'^zap/hosts/write$', views.zap_hosts_write, name = 'zap_hosts_write'),
]
