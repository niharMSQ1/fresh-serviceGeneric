from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from decouple import config

from .dbUtils import get_connection
from .models import Vulnerabilities

import json
import requests

# Create your views here.
def test(request):
    return JsonResponse({
        "message":"Hello World!"
    })

@csrf_exempt
def delete_all_tickets(request):
    freshservice_domain = "secqureone509.freshservice.com" # Example: "yourcompany.freshservice.com"
    api_key = config('FRESHSERVICE_API_AUTH')  # Your Freshservice API Key
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {api_key}"
    }

    tickets_url = f"https://{freshservice_domain}/api/v2/tickets"
    params = {
        "per_page": 100  # Fetch 100 tickets per page (maximum limit)
    }

    try:
        while True:
            response = requests.get(tickets_url, headers=headers, params=params)
            if response.status_code != 200:
                return JsonResponse({"error": f"Failed to fetch tickets: {response.json()}"}, status=response.status_code)

            tickets = response.json().get("tickets", [])
            if not tickets:
                return JsonResponse({"message": "No tickets found or all tickets have been deleted."}, status=200)

            # Delete each ticket
            for ticket in tickets:
                ticket_id = ticket.get("id")
                delete_url = f"{tickets_url}/{ticket_id}"
                delete_response = requests.delete(delete_url, headers=headers)

                if delete_response.status_code == 204:
                    print(f"Ticket {ticket_id} deleted successfully.")
                else:
                    print(f"Failed to delete ticket {ticket_id}: {delete_response.json()}")

            # Check if there are more pages
            if "next_page" not in response.json():
                break

        return JsonResponse({"message": "All tickets have been deleted."}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    