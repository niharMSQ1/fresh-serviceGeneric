# Generated by Django 5.1 on 2024-08-27 09:47

import freshserviceapp.models
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='TicketingServiceDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sq1VulId', models.IntegerField(null=True)),
                ('ticketId', models.IntegerField(null=True)),
                ('ticketServicePlatform', models.CharField(choices=[('jira', 'JIRA'), ('freshservice', 'Freshservice')], default='', max_length=20, null=True)),
                ('plannedStartDate', models.DateTimeField(null=True)),
                ('plannedEffort', models.TimeField(null=True)),
                ('subject', models.CharField(max_length=255, null=True)),
                ('group_id', models.IntegerField(default=None, null=True)),
                ('departmentId', models.IntegerField(default=None, null=True)),
                ('category', models.CharField(default=None, max_length=255, null=True)),
                ('subCategory', models.CharField(default=None, max_length=255, null=True)),
                ('itemCategory', models.CharField(default=None, max_length=255, null=True)),
                ('requesterId', models.IntegerField(null=True)),
                ('responderId', models.IntegerField(null=True)),
                ('emailConfigId', models.CharField(default=None, max_length=255, null=True)),
                ('fwdMails', models.TextField(default='[]', null=True)),
                ('isEscalated', models.BooleanField(default=False, null=True)),
                ('frDueBy', models.DateTimeField(null=True)),
                ('createdAt', models.DateTimeField(null=True)),
                ('updatedAt', models.DateTimeField(null=True)),
                ('workSpaceId', models.IntegerField(null=True)),
                ('requestedForId', models.BigIntegerField(validators=[freshserviceapp.models.validate_300_digit_max])),
                ('toEmails', models.EmailField(max_length=254, null=True)),
                ('type', models.CharField(max_length=255, null=True)),
                ('description', models.TextField(null=True)),
                ('descriptionHTML', models.TextField(null=True)),
                ('majorIncidentType', models.CharField(max_length=255, null=True)),
                ('businessImpact', models.CharField(max_length=255, null=True)),
                ('numberOfCustomersImpacted', models.IntegerField(null=True)),
                ('patchComplexity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='', max_length=20, null=True)),
                ('patchUrl', models.CharField(max_length=255, null=True)),
                ('patchOs', models.CharField(max_length=255, null=True)),
                ('exploitsName', models.CharField(max_length=255, null=True)),
                ('exploitsDescription', models.TextField(null=True)),
                ('exploitsComplexity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='', max_length=20, null=True)),
                ('exploitsDependency', models.CharField(choices=[('yes', 'Yes'), ('no', 'No')], default='', max_length=20, null=True)),
                ('tags', models.TextField(default='[]', null=True)),
                ('tasksDependencyType', models.IntegerField(null=True)),
                ('resolutionNotes', models.TextField(null=True)),
                ('resolutionNotesHTML', models.TextField(null=True)),
                ('attachments', models.TextField(default='[]', null=True)),
                ('exploitsList', models.TextField(default='', null=True)),
                ('patchesList', models.TextField(default='', null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Vulnerabilities',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('vulId', models.IntegerField()),
                ('createdTicketId', models.CharField(default=None, max_length=255)),
                ('organizationId', models.IntegerField(default=None)),
                ('ticketServicePlatform', models.CharField(choices=[('jira', 'JIRA'), ('freshservice', 'Freshservice')], default='', max_length=20)),
            ],
        ),
    ]
