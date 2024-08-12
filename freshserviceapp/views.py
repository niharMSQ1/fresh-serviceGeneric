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
def create_ticket(request):
    try:
        if request.method != 'POST':
            return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)

        data = json.loads(request.body)

        connection = get_connection()
        if not connection or not connection.is_connected():
            return JsonResponse({"error": "Failed to connect to the database"}, status=500)

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
                result = cursor.fetchall()
                
                if not result:
                    return JsonResponse({"error": "No vulnerabilities found"}, status=404)

                last_entry = result[0]
                last_entry_id = last_entry.get("id")

                if not Vulnerabilities.objects.filter(vulId=last_entry_id).exists():
                    new_vul = Vulnerabilities(vulId=last_entry_id)
                    new_vul.save()

                    url = config("FRESHSERVICE_API_URL")
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Basic {config('FRESHSERVICE_API_AUTH')}"
                    }

                    response = requests.post(url, json=data, headers=headers)

                    if response.status_code >= 400:
                        return JsonResponse({
                            "error": "Failed to create ticket",
                            "status_code": response.status_code,
                            "response_data": response.json()
                        }, status=response.status_code)

                    return JsonResponse({
                        "status_code": response.status_code,
                        "response_data": response.json()
                    })
                else:
                    return JsonResponse({"message": "Vulnerability already exists"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"Database query failed: {str(e)}"}, status=500)
        finally:
            if connection.is_connected():
                connection.close()

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON in request body"}, status=400)
    except Exception as e:
        return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
