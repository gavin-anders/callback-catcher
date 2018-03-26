# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2018-01-28 01:48
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Callback',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('sourceip', models.GenericIPAddressField()),
                ('sourceport', models.IntegerField(default=0)),
                ('serverip', models.GenericIPAddressField()),
                ('serverport', models.IntegerField(default=0)),
                ('protocol', models.CharField(default='tcp', max_length=3)),
                ('timestamp', models.DateTimeField()),
                ('datasize', models.IntegerField()),
                ('data', models.TextField()),
            ],
            options={
                'db_table': 'callback',
            },
        ),
        migrations.CreateModel(
            name='Fingerprint',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=50)),
                ('probe', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'fingerprint',
            },
        ),
        migrations.CreateModel(
            name='Handler',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('filename', models.CharField(max_length=200)),
                ('settings', models.TextField(null=True)),
            ],
            options={
                'db_table': 'handler',
            },
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('number', models.IntegerField()),
                ('protocol', models.CharField(max_length=200)),
                ('ssl', models.IntegerField(default=0)),
                ('enabled', models.IntegerField(default=0)),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('expire_time', models.DateTimeField()),
                ('pid', models.IntegerField()),
                ('handler', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='catcher.Handler')),
            ],
            options={
                'db_table': 'port',
            },
        ),
        migrations.AddField(
            model_name='callback',
            name='fingerprint',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='catcher.Fingerprint'),
        ),
        migrations.AlterUniqueTogether(
            name='port',
            unique_together=set([('number', 'protocol')]),
        ),
    ]
