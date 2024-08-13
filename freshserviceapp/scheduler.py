from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import requests
from decouple import config
from .dbUtils import get_connection
from .models import Vulnerabilities
from django.http import JsonResponse
import json


def call_create_ticket():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
            results = cursor.fetchall()

            # Fetch all existing vulnerability IDs in the Django model
            existing_vul_ids = set(Vulnerabilities.objects.values_list('vulId', flat=True))
            count = 0

            # If there are no existing vulnerabilities in the Django model
            if len(existing_vul_ids) == 0:
                for result in results:
                    vul_id = result.get("id")

                    # Create a ticket only if it doesn't already exist in the Django model
                    if vul_id not in existing_vul_ids:
                        priority_mapping = {
                            "low": 1,
                            "medium": 2,
                            "high": 3,
                            "critical": 4
                        }

                        priority = result.get("patch_priority", "").lower()
                        mapped_priority = priority_mapping.get(priority, 0)

                        combined_data = {
                            "description": result.get("description", "").replace("'", '"'),
                            "subject": result.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": mapped_priority,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3
                        }

                        url = config("FRESHSERVICE_API_URL")
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {config('FRESHSERVICE_API_AUTH')}"
                        }

                        response = requests.post(url, json=combined_data, headers=headers)
                        
                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id)
                            count += 1
                            print(f"Ticket created successfully for vulnerability {vul_id} (Count: {count})")
                        else:
                            print(f"Failed to create ticket for vulnerability {vul_id}: {response.json()}")

                return JsonResponse({"message": f"{count} tickets created successfully."}, status=200)

            # If there are existing vulnerabilities in the Django model
            else:
                latest_existing_id = max(existing_vul_ids)

                # Check if there are any new vulnerabilities that need tickets
                if results[0]["id"] == latest_existing_id:
                    return JsonResponse({"message": "Nothing to add"}, status=200)
                
                elif results[0]["id"] > latest_existing_id:
                    new_vulnerabilities = [vul for vul in results if vul["id"] > latest_existing_id]

                    for vul in new_vulnerabilities:
                        vul_id = vul.get("id")
                        priority_mapping = {
                            "low": 1,
                            "medium": 2,
                            "high": 3,
                            "critical": 4
                        }

                        priority = vul.get("patch_priority", "").lower()
                        mapped_priority = priority_mapping.get(priority, 0)

                        combined_data = {
                            "description": vul.get("description", "").replace("'", '"'),
                            "subject": vul.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": mapped_priority,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3
                        }

                        url = config("FRESHSERVICE_API_URL")
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {config('FRESHSERVICE_API_AUTH')}"
                        }

                        response = requests.post(url, json=combined_data, headers=headers)

                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id)
                            count += 1
                            print(f"Ticket created successfully for vulnerability {vul_id} (Count: {count})")
                        else:
                            print(f"Failed to create ticket for vulnerability {vul_id}: {response.json()}")

                    return JsonResponse({"message": f"{count} tickets created successfully."}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()


def check_closed_tickets():
    url = "https://secqureone509.freshservice.com/api/v2/tickets"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {config('FRESHSERVICE_API_AUTH')}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        tickets = response.json().get('tickets', [])
        print("Closed Tickets:")
        for ticket in tickets:
            print(f"Ticket ID: {ticket['id']}, Subject: {ticket['subject']}, Status: {ticket['status']}")
    else:
        print(f"Failed to retrieve tickets. Status code: {response.status_code}")
        print(response.json())

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(call_create_ticket, IntervalTrigger(minutes=0.5))
    # scheduler.add_job(check_closed_tickets, IntervalTrigger(minutes=0.25))
    scheduler.start()
