# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2018-03-12 23:35
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0006_auto_20180312_1501'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('token', models.CharField(max_length=250)),
            ],
            options={
                'db_table': 'tokens',
            },
        ),
        migrations.RemoveField(
            model_name='request',
            name='callback',
        ),
        migrations.DeleteModel(
            name='Request',
        ),
    ]
