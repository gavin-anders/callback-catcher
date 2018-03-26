# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2018-03-13 16:56
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0009_callback_description'),
    ]

    operations = [
        migrations.CreateModel(
            name='CallbackToken',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('callback', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catcher.Callback')),
            ],
            options={
                'db_table': 'callbacktoken',
            },
        ),
        migrations.RemoveField(
            model_name='token',
            name='callback',
        ),
        migrations.AddField(
            model_name='token',
            name='name',
            field=models.CharField(default='token', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='callbacktoken',
            name='token',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catcher.Token'),
        ),
    ]
