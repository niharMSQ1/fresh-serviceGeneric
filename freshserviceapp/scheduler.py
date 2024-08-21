from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import requests
from decouple import config
from .dbUtils import get_connection
from .models import *
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

            existing_vul_ids = set(Vulnerabilities.objects.values_list('vulId', flat=True))
            count = 0

            if len(existing_vul_ids) == 0:
                for result in results:
                    vul_id = result.get("id")
                    organization_id = result.get("organization_id")

                    if vul_id not in existing_vul_ids:
                        priority_mapping = {
                            "low": 1,
                            "medium": 2,
                            "high": 3,
                            "critical": 4
                        }

                        priority = result.get("severity", "").lower()
                        mapped_priority = priority_mapping.get(priority, 0)

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()

                        patchos = ""
                        if len(patches) != 0:
                            os_data = json.loads(patches[0].get('os'))
                            if len(os_data) != 0:
                                patchos = ", ".join([f"{item['os_name']} - {item['os_version']}" for item in os_data])

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        freshservice_url = ticketing_tool.get("url") + "/api/v2/tickets"
                        freshservice_key = ticketing_tool.get("key")

                        MAX_DESCRIPTION_LENGTH = 200
                        CONTACT_MESSAGE = "......please contact SQ1 support"

                        exploitsdescription = exploits[0].get("description", "").replace("'", '"') if exploits else ""
                        if len(exploitsdescription) > MAX_DESCRIPTION_LENGTH:
                            exploitsdescription = exploitsdescription[:MAX_DESCRIPTION_LENGTH] + CONTACT_MESSAGE

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
                                "exploitsdescription": exploitsdescription,
                                "exploitscomplexity": exploits[0].get("complexity") if exploits else None,
                                "exploitsdependency": exploits[0].get("dependency") if exploits else None
                            }
                        }



                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }

                        response = requests.post(freshservice_url, json=combined_data, headers=headers)

                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id,ticketServicePlatform =  [key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0] , organizationId = organization_id, createdTicketId =response.json()['ticket'].get("id") )
                            
                            ticket_data = (response.json()).get("ticket", {})

                            TicketingServiceDetails.objects.create(
                            ticketId=ticket_data.get("id", None),
                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0],
                            plannedStartDate=ticket_data.get("planned_start_date") or None,
                            plannedEffort=ticket_data.get("planned_end_date") or None,
                            subject=ticket_data.get("subject", ""),
                            group_id=ticket_data.get("group_id") or None,
                            departmentId=ticket_data.get("department_id") or None,
                            category=ticket_data.get("category") or None,
                            subCategory=ticket_data.get("sub_category") or None,
                            itemCategory=ticket_data.get("item_category") or None,
                            requesterId=ticket_data.get("requestor_id") or None,
                            responderId=ticket_data.get("responder_id") or None,
                            emailConfigId=ticket_data.get("email_config_id") or None,
                            fwdMails=ticket_data.get("fwd_mails", []),
                            isEscalated=ticket_data.get("is_escalated", False),
                            frDueBy=ticket_data.get("fr_due_by") or None,
                            createdAt=ticket_data.get("created_at") or None,
                            updatedAt=ticket_data.get("updated_at") or None,
                            workSpaceId=ticket_data.get("workspace_id") or None,
                            requestedForId=ticket_data.get("requested_for_id") or None,
                            toEmails=ticket_data.get("to_emails", None),
                            type=ticket_data.get("type", "Incident"),
                            description=ticket_data.get("description_text", ""),
                            descriptionHTML=ticket_data.get("description", ""),
                            majorIncidentType=ticket_data.get("major_incident_type") or None,
                            businessImpact=ticket_data.get("business_impact") or None,
                            numberOfCustomersImpacted=ticket_data.get("no_of_customers_impacted") or None,
                            patchComplexity=ticket_data.get("patchcomplexity") or None,
                            patchUrl=ticket_data.get("patchurl", ""),
                            patchOs=ticket_data.get("patchos", ""),
                            exploitsName=ticket_data.get("exploitsname", ""),
                            exploitsDescription=ticket_data.get("exploitsdescription", ""),
                            exploitsComplexity=ticket_data.get("exploitscomplexity") or None,
                            exploitsDependency=ticket_data.get("exploitsdependency") or None,
                            tags=ticket_data.get("tags", []),
                            tasksDependencyType=ticket_data.get("tasks_dependency_type") or None,
                            resolutionNotes=ticket_data.get("resolution_notes") or None,
                            resolutionNotesHTML=ticket_data.get("resolution_notes_html") or None,
                            attachments=ticket_data.get("attachments", [])
                            )
                            count += 1
                            print(f"Ticket created successfully for vulnerability {vul_id} (Count: {count})")
                        else:
                            print(f"Failed to create ticket for vulnerability {freshservice_url} {vul_id}: {response.json()}")

                return JsonResponse({"message": f"{count} tickets created successfully."}, status=200)

            else:
                latest_existing_id = max(existing_vul_ids)

                if results[0]["id"] == latest_existing_id:
                    return JsonResponse({"message": "Nothing to add"}, status=200)
                
                elif results[0]["id"] > latest_existing_id:
                    new_vulnerabilities = [vul for vul in results if vul["id"] > latest_existing_id]

                    for result in new_vulnerabilities:
                        vul_id = result.get("id")
                        organization_id = result.get("organization_id")

                        priority_mapping = {
                            "low": 1,
                            "medium": 2,
                            "high": 3,
                            "critical": 4
                        }

                        priority = result.get("severity", "").lower()
                        mapped_priority = priority_mapping.get(priority, 0)

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()

                        patchos = ""
                        if len(patches) != 0:
                            os_data = json.loads(patches[0].get('os'))
                            if len(os_data) != 0:
                                patchos = ", ".join([f"{item['os_name']} - {item['os_version']}" for item in os_data])

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        freshservice_url = ticketing_tool.get("url")+ "/api/v2/tickets"
                        freshservice_key = ticketing_tool.get("key")

                        MAX_DESCRIPTION_LENGTH = 200
                        CONTACT_MESSAGE = "......please contact SQ1 support"

                        exploitsdescription = exploits[0].get("description", "").replace("'", '"') if exploits else ""
                        if len(exploitsdescription) > MAX_DESCRIPTION_LENGTH:
                            exploitsdescription = exploitsdescription[:MAX_DESCRIPTION_LENGTH] + CONTACT_MESSAGE

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
                                "exploitsdescription": exploitsdescription,
                                "exploitscomplexity": exploits[0].get("complexity") if exploits else None,
                                "exploitsdependency": exploits[0].get("dependency") if exploits else None
                            }
                        }



                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }

                        response = requests.post(freshservice_url, json=combined_data, headers=headers)

                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id,ticketServicePlatform =  [key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0] , organizationId = organization_id, createdTicketId =response.json()['ticket'].get("id") )

                            ticket_data = (response.json()).get("ticket", {})

                            TicketingServiceDetails.objects.create(
                            ticketId=ticket_data.get("id", None),
                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0],
                            plannedStartDate=ticket_data.get("planned_start_date") or None,
                            plannedEffort=ticket_data.get("planned_end_date") or None,
                            subject=ticket_data.get("subject", ""),
                            group_id=ticket_data.get("group_id") or None,
                            departmentId=ticket_data.get("department_id") or None,
                            category=ticket_data.get("category") or None,
                            subCategory=ticket_data.get("sub_category") or None,
                            itemCategory=ticket_data.get("item_category") or None,
                            requesterId=ticket_data.get("requestor_id") or None,
                            responderId=ticket_data.get("responder_id") or None,
                            emailConfigId=ticket_data.get("email_config_id") or None,
                            fwdMails=ticket_data.get("fwd_mails", []),
                            isEscalated=ticket_data.get("is_escalated", False),
                            frDueBy=ticket_data.get("fr_due_by") or None,
                            createdAt=ticket_data.get("created_at") or None,
                            updatedAt=ticket_data.get("updated_at") or None,
                            workSpaceId=ticket_data.get("workspace_id") or None,
                            requestedForId=ticket_data.get("requested_for_id") or None,
                            toEmails=ticket_data.get("to_emails", None),
                            type=ticket_data.get("type", "Incident"),
                            description=ticket_data.get("description_text", ""),
                            descriptionHTML=ticket_data.get("description", ""),
                            majorIncidentType=ticket_data.get("major_incident_type") or None,
                            businessImpact=ticket_data.get("business_impact") or None,
                            numberOfCustomersImpacted=ticket_data.get("no_of_customers_impacted") or None,
                            patchComplexity=ticket_data.get("patchcomplexity") or None,
                            patchUrl=ticket_data.get("patchurl", ""),
                            patchOs=ticket_data.get("patchos", ""),
                            exploitsName=ticket_data.get("exploitsname", ""),
                            exploitsDescription=ticket_data.get("exploitsdescription", ""),
                            exploitsComplexity=ticket_data.get("exploitscomplexity") or None,
                            exploitsDependency=ticket_data.get("exploitsdependency") or None,
                            tags=ticket_data.get("tags", []),
                            tasksDependencyType=ticket_data.get("tasks_dependency_type") or None,
                            resolutionNotes=ticket_data.get("resolution_notes") or None,
                            resolutionNotesHTML=ticket_data.get("resolution_notes_html") or None,
                            attachments=ticket_data.get("attachments", [])
                            )
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


def get_all_tickets_and_update():
    url= "https://secqureone770.freshservice.com"+"/api/v2/tickets"
    api_key= "cXZwcWhEcVJYdTh3WkltUW9aTw=="

    headers = {
    'Authorization': f'Basic {api_key}'
    }

    # Make the GET request to fetch all tickets
    response = requests.get(url, headers=headers)
    idd = []
    for res in response.json()["tickets"]:
        idd.append((res))
    # idd.sort()
    return idd


# def check_closed_tickets():
#     url = "https://secqureone509.freshservice.com/api/v2/tickets"
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"Basic {config('FRESHSERVICE_API_AUTH')}"
#     }

#     response = requests.get(url, headers=headers)

#     if response.status_code == 200:
#         tickets = response.json().get('tickets', [])
#         print("Closed Tickets:")
#         for ticket in tickets:
#             print(f"Ticket ID: {ticket['id']}, Subject: {ticket['subject']}, Status: {ticket['status']}")
#     else:
#         print(f"Failed to retrieve tickets. Status code: {response.status_code}")
#         print(response.json())

def start_scheduler():
    scheduler = BackgroundScheduler()
    # scheduler.add_job(call_create_ticket, IntervalTrigger(minutes=0.5))
    # scheduler.add_job(check_closed_tickets, IntervalTrigger(minutes=0.25))
    scheduler.start()
