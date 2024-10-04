# consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get hospital_id from URL and create a unique group name
        self.hospital_id = self.scope['url_route']['kwargs']['hospital_id']
        self.group_name = f'notification_{self.hospital_id}'

        # Add this WebSocket connection to the hospital's notification group
        await self.channel_layer.group_add(self.group_name, self.channel_name)

        # Accept the WebSocket connection
        await self.accept()

    async def disconnect(self, close_code):
        # Remove this WebSocket connection from the group
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # Method to handle incoming notifications
    async def send_notification(self, event):
        message = event['message']

        # Send the notification to the WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))
