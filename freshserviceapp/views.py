from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .dbUtils import get_connection

import json

# Create your views here.
def test(request):
    return JsonResponse({
        "message":"Hello World!"
    })

@csrf_exempt
def create_ticket(request):
    data = json.loads(request.body)

    connection = get_connection()
    if connection and connection.is_connected():
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
                result = cursor.fetchall()
                last_entry = result[0]
                last_entry_id = last_entry.get("id")
                
                return JsonResponse({"data": result})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
