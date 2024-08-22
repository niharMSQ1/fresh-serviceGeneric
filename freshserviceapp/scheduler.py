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
                        

                        mapped_priority = None

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = 4
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = 3
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = 2
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = 1

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        freshservice_url = f"{ticketing_tool.get('url')}/api/v2/tickets"
                        freshservice_key = ticketing_tool.get("key")

                        detection_summary_table = ""

                        if result:
                            detection_summary_table = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Detection summary:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">CVE</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Severity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">First identified on</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Last identified on</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch priority</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td style="border: 1px solid black; padding: 8px;">{", ".join(json.loads((result['CVEs'].replace("'", '"')))["cves"])}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['severity'].replace("'", '"')}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['first_seen']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['last_identified_on']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['patch_priority']}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            detection_summary_table = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Detection Table:</strong> Nothing detected.
                                </div>
                                <br>
                            """

                        remediation_table = ""

                        if result:
                            remediation_table = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Remediation Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Solution Patch</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Solution workaround</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Preventive measure</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td style="border: 1px solid black; padding: 8px;">{result['solution_patch']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['solution_workaround']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['preventive_measure']}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            remediation_table = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Remediation Table:</strong>Kindly wait for remedies.
                                </div>
                                <br>
                            """
                        

                        exploits_table_html = ""

                        if exploits:
                            exploits_table_html = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Exploits Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits name</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits description</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits complexity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits dependency</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {"".join(
                                            f"<tr>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['name']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['description'].replace("'", '"')}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['complexity']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{'Dependent on other exploits' if exploit['dependency'].lower() == 'yes' else 'Self exploitable'}</td>"
                                            f"</tr>"
                                            for exploit in exploits
                                        )}
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            exploits_table_html = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Exploits Table:</strong> No exploits exist for this vulnerability.
                                </div>
                                <br>
                            """

                        patch_table_html = ""

                        if patches:
                            patch_table_html = f"""
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Patch Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch solution</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch description</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch complexity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch url</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch type</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch os</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {"".join(
                                            f"<tr>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['solution']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['description'].replace("'", '"')}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['complexity']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'><a href='{patch['url']}'>{patch['url']}</a></td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['type']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{', '.join([f'{os_item["os_name"]} {os_item["os_version"]}' for os_item in json.loads(patch['os'])])}</td>"
                                            f"</tr>"
                                            for patch in patches
                                        )}
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            patch_table_html = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Patch Table:</strong> No patches exist for this vulnerability.
                                </div>
                                <br>
                            """

                        combined_data = {
                            "description": result.get("description", "").replace("'", '"') + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html,
                            "subject": result.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": 4,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": mapped_priority,
                        }

                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }

                        response = requests.post(freshservice_url, json=combined_data, headers=headers)

                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id,ticketServicePlatform =  [key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0] , organizationId = organization_id, createdTicketId =response.json()['ticket'].get("id") )
                            
                            ticket_data = (response.json()).get("ticket", {})

                            TicketingServiceDetails.objects.create(
                            ticketId=ticket_data.get("id", None),
                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
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

                        mapped_priority = None

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = 4
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = 3
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = 2
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = 1

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        freshservice_url = f"{ticketing_tool.get('url')}/api/v2/tickets"
                        freshservice_key = ticketing_tool.get("key")

                        detection_summary_table = ""

                        if result:
                            detection_summary_table = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Detection summary:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">CVE</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Severity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">First identified on</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Last identified on</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch priority</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td style="border: 1px solid black; padding: 8px;">{", ".join(json.loads((result['CVEs'].replace("'", '"')))["cves"])}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['severity'].replace("'", '"')}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['first_seen']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['last_identified_on']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['patch_priority']}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            detection_summary_table = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Detection Table:</strong> Nothing detected.
                                </div>
                                <br>
                            """

                        remediation_table = ""

                        if result:
                            remediation_table = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Remediation Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Solution Patch</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Solution workaround</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Preventive measure</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td style="border: 1px solid black; padding: 8px;">{result['solution_patch']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['solution_workaround']}</td>
                                            <td style="border: 1px solid black; padding: 8px;">{result['preventive_measure']}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            remediation_table = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Remediation Table:</strong>Kindly wait for remedies.
                                </div>
                                <br>
                            """
                        

                        exploits_table_html = ""

                        if exploits:
                            exploits_table_html = f"""
                                <br><br>
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Exploits Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits name</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits description</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits complexity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Exploits dependency</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {"".join(
                                            f"<tr>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['name']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['description'].replace("'", '"')}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{exploit['complexity']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{'Dependent on other exploits' if exploit['dependency'].lower() == 'yes' else 'Self exploitable'}</td>"
                                            f"</tr>"
                                            for exploit in exploits
                                        )}
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            exploits_table_html = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Exploits Table:</strong> No exploits exist for this vulnerability.
                                </div>
                                <br>
                            """

                        patch_table_html = ""

                        if patches:
                            patch_table_html = f"""
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Patch Table:</strong>
                                </div>
                                <br>
                                <table style="border-collapse: collapse; width: 100%; border: 3px solid black; box-shadow: 0 0 5px blue; font-family: Arial, sans-serif; font-size: 16px;">
                                    <thead>
                                        <tr>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch solution</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch description</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch complexity</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch url</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch type</th>
                                            <th style="border: 1px solid black; font-weight: bold; padding: 8px; text-align: left;">Patch os</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {"".join(
                                            f"<tr>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['solution']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['description'].replace("'", '"')}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['complexity']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'><a href='{patch['url']}'>{patch['url']}</a></td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{patch['type']}</td>"
                                            f"<td style='border: 1px solid black; padding: 8px;'>{', '.join([f'{os_item["os_name"]} {os_item["os_version"]}' for os_item in json.loads(patch['os'])])}</td>"
                                            f"</tr>"
                                            for patch in patches
                                        )}
                                    </tbody>
                                </table>
                                <br>
                            """
                        else:
                            patch_table_html = """
                                <div dir="ltr" style="font-family: Arial, sans-serif; font-size: 16px;">
                                    <strong>Patch Table:</strong> No patches exist for this vulnerability.
                                </div>
                                <br>
                            """

                        combined_data = {
                            "description": result.get("description", "").replace("'", '"') + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html,
                            "subject": result.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": 4,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": mapped_priority,
                        }

                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }

                        response = requests.post(freshservice_url, json=combined_data, headers=headers)

                        if response.status_code == 201:
                            Vulnerabilities.objects.create(vulId=vul_id,ticketServicePlatform =  [key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0] , organizationId = organization_id, createdTicketId =response.json()['ticket'].get("id") )
                            
                            ticket_data = (response.json()).get("ticket", {})

                            TicketingServiceDetails.objects.create(
                            ticketId=ticket_data.get("id", None),
                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
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
