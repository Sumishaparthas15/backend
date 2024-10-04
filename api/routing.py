from django.urls import path
from api.consumers import NotificationConsumer

websocket_urlpatterns = [
    path('ws/notifications/hospital_<str:hospital_id>/', NotificationConsumer.as_asgi()),
]
