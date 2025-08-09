from django.urls import path
from .views import ConversationListCreateView, MessageListCreateView, ConversationMarkReadView

urlpatterns = [
    path("conversations/", ConversationListCreateView.as_view(), name="conversations_list_create"),
    path("conversations/<uuid:cid>/messages/", MessageListCreateView.as_view(), name="messages_list_create"),
    path("conversations/<uuid:cid>/read/", ConversationMarkReadView.as_view(), name="conversations_mark_read"),
]
