# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2018-03-14 12:10


from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0011_callbacktoken_found'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='callbacktoken',
            name='callback',
        ),
        migrations.RemoveField(
            model_name='callbacktoken',
            name='token',
        ),
        migrations.AddField(
            model_name='callback',
            name='token',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='catcher.Token'),
        ),
        migrations.DeleteModel(
            name='CallbackToken',
        ),
    ]
