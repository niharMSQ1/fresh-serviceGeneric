from django.urls import path
from .views import *

urlpatterns = [
    path('', test),
    path('delete-all-tickets/', delete_all_tickets, name='delete_all_tickets'),
]