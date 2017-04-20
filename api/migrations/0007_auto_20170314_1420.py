# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-14 08:50
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_zapscan'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=255, verbose_name='Username')),
                ('password', models.TextField(verbose_name='Password')),
                ('enabled', models.BooleanField(default=True, verbose_name='Enabled')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('last_login', models.DateTimeField(auto_now=True, verbose_name='Last Login')),
            ],
        ),
        migrations.AlterField(
            model_name='zapscan',
            name='url',
            field=models.TextField(verbose_name='URL'),
        ),
    ]