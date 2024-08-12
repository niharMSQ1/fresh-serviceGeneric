from django.urls import path
from .views import *

urlpatterns = [
    path('', test),
    path('create-ticket',create_ticket)
]
