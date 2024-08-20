from django.db import models
import json

PATCH_COMPLEXITY_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
    ('critical', 'Critical')
]

EXPLOITS_COMPLEXITY_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
    ('critical', 'Critical')
]

EXPLOITS_DEPENDENCY_CHOICES = [
    ('yes', 'Yes'),
    ('no', 'No')
]

TICKET_TYPE_CHOICES = [
    ('jira', 'JIRA'),
    ('freshservice', 'Freshservice')
]

class Vulnerabilities(models.Model):
    id = models.AutoField(primary_key=True)
    vulId = models.IntegerField()
    createdTicketId = models.CharField(max_length=255, default=None)
    organizationId = models.IntegerField(default=None)
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="")

class TicketingServiceDetails(models.Model):
    ticketId = models.IntegerField()
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="")
    plannedStartDate = models.DateTimeField()
    plannedEffort = models.TimeField()
    subject = models.CharField(max_length=255)
    group_id = models.IntegerField(default=None)
    departmentId = models.IntegerField(default=None)
    category = models.CharField(max_length=255, default=None)
    subCategory = models.CharField(max_length=255, default=None)
    itemCategory = models.CharField(max_length=255, default=None)
    requesterId = models.IntegerField()
    responderId = models.IntegerField()
    emailConfigId = models.CharField(max_length=255, default=None)
    fwdMails = models.TextField(default='[]')
    isEscalated = models.BooleanField(default=False)
    frDueBy = models.DateTimeField()
    createdAt = models.DateTimeField()
    updatedAt = models.DateTimeField()
    workSpaceId = models.IntegerField()
    requestedForId = models.IntegerField()
    toEmails = models.EmailField()
    type = models.CharField(max_length=255)
    description = models.TextField()
    descriptionHTML = models.TextField()
    majorIncidentType = models.CharField(max_length=255)
    businessImpact = models.CharField(max_length=255)
    numberOfCustomersImpacted = models.IntegerField()
    patchComplexity = models.CharField(max_length=20, choices=PATCH_COMPLEXITY_CHOICES, default="")
    patchUrl = models.CharField(max_length=255)
    patchOs = models.CharField(max_length=255)
    exploitsName = models.CharField(max_length=255)
    exploitsDescription = models.TextField()
    exploitsComplexity = models.CharField(max_length=20, choices=EXPLOITS_COMPLEXITY_CHOICES, default="")
    exploitsDependency = models.CharField(max_length=20, choices=EXPLOITS_DEPENDENCY_CHOICES, default="")
    tags = models.TextField(default='[]')
    tasksDependencyType = models.IntegerField()
    resolutionNotes = models.TextField()
    resolutionNotesHTML = models.TextField()
    attachments = models.TextField(default='[]')

    def save(self, *args, **kwargs):
        self.fwdMails = json.dumps(self.fwdMails)
        self.tags = json.dumps(self.tags)
        self.attachments = json.dumps(self.attachments)
        super(TicketingServiceDetails, self).save(*args, **kwargs)

    def get_fwd_mails(self):
        return json.loads(self.fwdMails)

    def get_tags(self):
        return json.loads(self.tags)

    def get_attachments(self):
        return json.loads(self.attachments)
