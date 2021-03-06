# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-20 06:22
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_zapinstance_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='ZAPScan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scanId', models.IntegerField(verbose_name='Scan ID')),
                ('user', models.CharField(max_length=255, verbose_name='Username')),
                ('url', models.TextField(verbose_name='Username')),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.ZAPInstance', verbose_name='ZAP Instance')),
            ],
        ),
    ]
