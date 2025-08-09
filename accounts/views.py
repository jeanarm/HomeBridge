from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from .models import Profile, Block,Report,Conversation,Message
from django.db import models
from django.shortcuts import get_object_or_404
from django.db.models import Q

from .serializers import (
    RegisterSerializer, MeSerializer, PublicProfileSerializer,ProfileSerializer,
    ProfileUpdateSerializer,BlockSerializer,BlockListItemSerializer,ReportSerializer,
    ConversationSerializer,ConversationCreateSerializer,
    MessageSerializer, MessageCreateSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,

)

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

class MeView(APIView):
    def get(self, request):
        prof = request.user.profile
        prof.last_active_at = timezone.now()
        prof.save(update_fields=["last_active_at"])
        return Response(MeSerializer(request.user).data)

class LogoutView(APIView):
    """
    Logout this device by blacklisting the provided refresh token.
    Body: {"refresh": "<REFRESH_TOKEN>"}
    """
    def post(self, request):
        refresh = request.data.get("refresh")
        if not refresh:
            return Response({"detail": "Missing refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh)
            token.blacklist()
        except Exception:
            return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_205_RESET_CONTENT)

class LogoutAllView(APIView):
    """
    Logout from all devices by blacklisting all outstanding tokens for the user.
    """
    def post(self, request):
        tokens = OutstandingToken.objects.filter(user=request.user)
        for t in tokens:
            BlacklistedToken.objects.get_or_create(token=t)
        return Response(status=status.HTTP_205_RESET_CONTENT)

class ProfileListView(generics.ListAPIView):
    """
    List other users with basic filters + free-text search.

    Query params:
      - q: space-separated terms matched across display_name, profession, bio, country, city, languages
      - country: exact (case-insensitive)
      - city: icontains
      - profession: icontains
      - language: icontains against JSON list
      - exclude_blocked: default true; set false to disable

    Sort: most recently active first, then user_id.
    """
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        me = self.request.user
        qs = (
            Profile.objects
            .select_related("user")
            .only(
                "user__id", "display_name", "country_of_origin", "current_city",
                "profession", "languages", "bio", "last_active_at"
            )
            .exclude(user=me)
        )

        # ---- structured filters ----
        qp = self.request.query_params
        country = qp.get("country")
        city = qp.get("city")
        profession = qp.get("profession")
        language = qp.get("language")

        if country:
            qs = qs.filter(country_of_origin__iexact=country.strip())
        if city:
            qs = qs.filter(current_city__icontains=city.strip())
        if profession:
            qs = qs.filter(profession__icontains=profession.strip())
        if language:
            qs = qs.filter(languages__icontains=language.strip())

        # ---- FREE-TEXT SEARCH (?q=) ----
        q = (qp.get("q") or "").strip()
        if q:
            # every term must match at least one field (AND across terms, OR within fields)
            for term in [t for t in q.split() if t]:
                t = term.strip()
                qs = qs.filter(
                    Q(display_name__icontains=t) |
                    Q(profession__icontains=t) |
                    Q(bio__icontains=t) |
                    Q(country_of_origin__icontains=t) |
                    Q(current_city__icontains=t) |
                    Q(languages__icontains=t)  # JSON list text match fallback
                )

        # ---- exclude blocked users (both directions) ----
        exclude_blocked = qp.get("exclude_blocked", "true").lower() != "false"
        if exclude_blocked:
            blocked_pairs = Block.objects.filter(Q(blocker=me) | Q(blocked=me)) \
                                         .values_list("blocker_id", "blocked_id")
            exclude_ids = set()
            for a, b in blocked_pairs:
                if a != me.id: exclude_ids.add(a)
                if b != me.id: exclude_ids.add(b)
            if exclude_ids:
                qs = qs.exclude(user_id__in=list(exclude_ids))

        return qs.order_by("-last_active_at", "user_id")


class ProfileDetailView(generics.RetrieveAPIView):
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "user_id"

    def get_queryset(self):
        return Profile.objects.select_related("user").all()

class BlockListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/blocks/       -> list all users I blocked
    POST /api/blocks/       -> block a user { "user_id": 123 }
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Block.objects.filter(blocker=self.request.user).select_related("blocked")

    def get_serializer_class(self):
        if self.request.method == "GET":
            return BlockListItemSerializer
        return BlockSerializer

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx


class BlockDeleteView(APIView):
    """
    DELETE /api/blocks/<user_id>/ -> unblock that user
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, user_id: int):
        deleted, _ = Block.objects.filter(blocker=request.user, blocked_id=user_id).delete()
        if deleted:
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)


# --- REPORTS ---

class ReportCreateView(generics.CreateAPIView):
    """
    POST /api/reports/ -> { "reported_user_id": 123, "reason": "harassment", "details": "..." }
    """
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx

class ConversationListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/conversations/           -> my conversations
    POST /api/conversations/ {user_id} -> create/get conversation with user
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        me = self.request.user
        return (Conversation.objects
                .filter(models.Q(user_a=me) | models.Q(user_b=me))
                .select_related("user_a", "user_b")
                .order_by("-last_message_at", "-created_at"))

    def get_serializer_class(self):
        return ConversationCreateSerializer if self.request.method == "POST" else ConversationSerializer

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx

    def perform_create(self, serializer):
        self.instance = serializer.save()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        convo = serializer.save()
        out = ConversationSerializer(convo, context={"request": request})
        return Response(out.data, status=status.HTTP_201_CREATED)


class MessageListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/conversations/<uuid:cid>/messages/
    POST /api/conversations/<uuid:cid>/messages/ {body}
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_conversation(self):
        cid = self.kwargs["cid"]
        convo = get_object_or_404(Conversation.objects.select_related("user_a", "user_b"), id=cid)
        me = self.request.user
        if me.id not in (convo.user_a_id, convo.user_b_id):
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        return convo

    def get_queryset(self):
        convo = self.get_conversation()
        if isinstance(convo, Response):
            return Message.objects.none()
        return (Message.objects
                .filter(conversation=convo)
                .select_related("sender")
                .order_by("created_at"))

    def get_serializer_class(self):
        return MessageCreateSerializer if self.request.method == "POST" else MessageSerializer

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        convo = self.get_conversation()
        if isinstance(convo, Response):
            return ctx
        ctx["request"] = self.request
        ctx["conversation"] = convo
        return ctx

    def create(self, request, *args, **kwargs):
        convo = self.get_conversation()
        if isinstance(convo, Response):
            return convo
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msg = serializer.save()
        return Response(MessageSerializer(msg).data, status=status.HTTP_201_CREATED)


class ConversationMarkReadView(APIView):
    """
    POST /api/conversations/<uuid:cid>/read/
      -> marks all messages from the other user as read
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, cid):
        convo = get_object_or_404(Conversation, id=cid)
        me = request.user
        if me.id not in (convo.user_a_id, convo.user_b_id):
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        # mark other-party messages as read
        qs = Message.objects.filter(conversation=convo).exclude(sender=me).filter(is_read=False)
        updated = qs.update(is_read=True, read_at=timezone.now())
        return Response({"updated": updated}, status=status.HTTP_200_OK)

class MyProfileView(generics.RetrieveUpdateAPIView):
    """
    GET   /api/profiles/me/     -> your profile
    PATCH /api/profiles/me/     -> update your profile (partial)
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileUpdateSerializer  # for writes

    def get_object(self):
        return self.request.user.profile

    def get(self, request, *args, **kwargs):
        # Use read serializer for output consistency
        prof = self.get_object()
        return Response(ProfileSerializer(prof).data)

class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        # Always return 200 for privacy
        return Response({"detail": "If an account with that email exists, a reset link has been sent."})


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response({"detail": "Password has been reset successfully."})
