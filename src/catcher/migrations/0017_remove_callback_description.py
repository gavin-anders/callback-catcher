# Generated by Django 2.0.7 on 2018-08-29 10:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0016_auto_20180829_0809'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='callback',
            name='description',
        ),
    ]
