# Generated by Django 2.1.7 on 2019-04-16 14:19

import catcher.models
import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('catcher', '0006_auto_20190415_1748'),
    ]

    operations = [
        migrations.AlterField(
            model_name='token',
            name='expire_time',
            field=models.DateTimeField(default=datetime.datetime(2019, 5, 16, 14, 19, 17, 751159, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='token',
            name='token',
            field=models.CharField(default=catcher.models._gen_token_hash, max_length=100, unique=True),
        ),
    ]
