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

            if len(existing_vul_ids) == 0:
                for result in results:
                    vul_id = result.get("id")

                    if vul_id not in existing_vul_ids:
                        priority_mapping = {
                            "low": 1,
                            "medium": 2,
                            "high": 3,
                            "critical": 4
                        }

                        priority = result.get("patch_priority", "").lower()
                        mapped_priority = priority_mapping.get(priority, 0)

                        # Fetch associated data from exploits and patch tables
                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s", (vul_id,))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()
                        if len(patches) != 0:
                            # Assuming 'os' field in patches[0] contains a JSON string
                            os_data = json.loads(patches[0].get('os'))
                            if len(os_data) != 0:
                                patchos = ", ".join([f"{item['os_name']} - {item['os_version']}" for item in os_data])



                        combined_data = {
                            "description": result.get("description", "").replace("'", '"'),
                            "subject": result.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": mapped_priority,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3,
                            "custom_fields": {
                                "major_incident_type": None,
                                "business_impact": None,
                                "impacted_locations": None,
                                "patchcomplexity": patches[0].get("complexity") if patches else None,
                                "patchurl": patches[0].get("url") if patches else None,
                                "patchos": patchos if patches else None,
                                "exploitsname": exploits[0].get("name") if exploits else None,
                                "exploitsdescription": exploits[0].get("description", "").replace("'", '"') if exploits else None,
                                "exploitscomplexity": exploits[0].get("complexity") if exploits else None,
                                "exploitsdependency": exploits[0].get("dependency") if exploits else None
                            }
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

            else:
                latest_existing_id = max(existing_vul_ids)

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

                        # Fetch associated data from exploits and patch tables
                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s", (vul_id,))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()
                        if len(patches) != 0:
                            os_data = json.loads(patches[0].get('os'))
                            if len(os_data) != 0:
                                patchos = ", ".join([f"{item['os_name']} - {item['os_version']}" for item in os_data])

                        combined_data = {
                            "description": vul.get("description", "").replace("'", '"'),
                            "subject": vul.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": mapped_priority,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3,
                            "custom_fields": {
                                "major_incident_type": None,
                                "business_impact": None,
                                "impacted_locations": None,
                                "patchcomplexity": patches[0].get("complexity") if patches else None,
                                "patchurl": patches[0].get("url") if patches else None,
                                "patchos": patchos if patches else None,
                                "exploitsname": exploits[0].get("name") if exploits else None,
                                "exploitsdescription": exploits[0].get("description", "").replace("'", '"') if exploits else None,
                                "exploitscomplexity": exploits[0].get("complexity") if exploits else None,
                                "exploitsdependency": exploits[0].get("dependency") if exploits else None
                            }
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
    # scheduler.add_job(call_create_ticket, IntervalTrigger(minutes=0.5))
    # scheduler.add_job(check_closed_tickets, IntervalTrigger(minutes=0.25))
    scheduler.start()
