# Generated by Django 4.1.7 on 2023-04-20 06:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recipes', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='recipe',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='static/recipe/', verbose_name='Изображение к рецепту'),
        ),
    ]
