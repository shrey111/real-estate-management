# Generated by Django 2.1.1 on 2018-12-17 00:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eproperty', '0007_auto_20181209_2203'),
    ]

    operations = [
        migrations.AlterField(
            model_name='city',
            name='cityID',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='country',
            name='countryID',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='province',
            name='provinceID',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]