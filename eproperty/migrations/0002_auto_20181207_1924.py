# Generated by Django 2.1.1 on 2018-12-08 00:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eproperty', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='propertyimages',
            name='propertyImageID',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]