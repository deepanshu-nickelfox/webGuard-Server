# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-19 11:05
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_zapinstance_session'),
    ]

    operations = [
        migrations.AddField(
            model_name='zapinstance',
            name='name',
            field=models.CharField(default='Orange Wave', max_length=255, verbose_name='Name'),
            preserve_default=False,
        ),
    ]
