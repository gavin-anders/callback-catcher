# Generated by Django 2.1.7 on 2019-04-16 14:29

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0007_auto_20190416_1419'),
    ]

    operations = [
        migrations.AlterField(
            model_name='token',
            name='expire_time',
            field=models.DateTimeField(default=datetime.datetime(2019, 5, 16, 14, 29, 23, 451054, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='token',
            name='token',
            field=models.CharField(max_length=100, unique=True),
        ),
    ]
