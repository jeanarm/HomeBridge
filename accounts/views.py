from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import models
from django.db.models import Q
from django.shortcuts import get_object_or_404

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from .models import Profile, Block, Report, Conversation, Message
from .serializers import (
    RegisterSerializer, MeSerializer, PublicProfileSerializer, ProfileSerializer,
    ProfileUpdateSerializer, BlockSerializer, BlockListItemSerializer, ReportSerializer,
    ConversationSerializer, ConversationCreateSerializer,
    MessageSerializer, MessageCreateSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
)

User = get_user_model()

# =========================
# Auth
# =========================

class RegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

class AuthMeView(APIView):
    """
    GET /api/auth/me/ -> { id, username, email, profile:{...} }
    (Convenient for chat screens needing my user id/username quickly)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(MeSerializer(request.user, context={"request": request}).data)

class LogoutView(APIView):
    """
    POST /api/auth/logout/ -> body: {"refresh": "<REFRESH_TOKEN>"}
    Blacklists the provided refresh token.
    """
    permission_classes = [permissions.IsAuthenticated]

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
    POST /api/auth/logout_all/
    Blacklists all outstanding tokens for the user (all devices).
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user=request.user)
        for t in tokens:
            BlacklistedToken.objects.get_or_create(token=t)
        return Response(status=status.HTTP_205_RESET_CONTENT)

# =========================
# Profiles (Public lists + My profile)
# =========================

class ProfileListView(generics.ListAPIView):
    """
    GET /api/profiles/
      Filters:
        - q: free text across name, profession, bio, country, city, languages
        - country: exact (case-insensitive)
        - city: icontains
        - profession: icontains
        - language: icontains (JSON text match)
        - exclude_blocked=true (default)
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
                "profession", "languages", "bio", "last_active_at", "avatar"
            )
            .exclude(user=me)
        )

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

        q = (qp.get("q") or "").strip()
        if q:
            for term in [t for t in q.split() if t]:
                t = term.strip()
                qs = qs.filter(
                    Q(display_name__icontains=t) |
                    Q(profession__icontains=t) |
                    Q(bio__icontains=t) |
                    Q(country_of_origin__icontains=t) |
                    Q(current_city__icontains=t) |
                    Q(languages__icontains=t)
                )

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

    # Wrap as paginated object for the mobile client (even if not paginated server-side)
    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        ser = self.get_serializer(qs, many=True, context={"request": request})
        return Response({"count": qs.count(), "next": None, "previous": None, "results": ser.data})

class ProfileDetailView(generics.RetrieveAPIView):
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "user_id"

    def get_queryset(self):
        return Profile.objects.select_related("user").all()

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        ser = self.get_serializer(instance, context={"request": request})
        return Response(ser.data)

class MyProfileView(generics.RetrieveUpdateAPIView):
    """
    GET   /api/profiles/me/
    PATCH /api/profiles/me/
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileUpdateSerializer  # used for writes (PATCH)

    def get_object(self):
        return self.request.user.profile

    def get(self, request, *args, **kwargs):
        # bump last_active_at
        prof = self.get_object()
        prof.last_active_at = timezone.now()
        prof.save(update_fields=["last_active_at"])
        data = ProfileSerializer(prof, context={"request": request}).data
        return Response({"profile": data})

    def patch(self, request, *args, **kwargs):
        prof = self.get_object()
        ser = self.get_serializer(prof, data=request.data, partial=True, context={"request": request})
        ser.is_valid(raise_exception=True)
        ser.save()
        out = ProfileSerializer(prof, context={"request": request}).data
        return Response({"profile": out})

# =========================
# Blocks
# =========================

class BlockListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/blocks/
    POST /api/blocks/  {"user_id": <int>}
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
    DELETE /api/blocks/<user_id>/
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, user_id: int):
        deleted, _ = Block.objects.filter(blocker=request.user, blocked_id=user_id).delete()
        if deleted:
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

# =========================
# Reports
# =========================

class ReportCreateView(generics.CreateAPIView):
    """
    POST /api/reports/ -> { "reported_user_id": 123, "reason": "...", "details": "..." }
    """
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx

# =========================
# Conversations & Messages
# =========================

class ConversationListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/conversations/           -> my conversations (array)
    POST /api/conversations/ {user_id} -> create/get conversation with user
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        me = self.request.user
        return (
            Conversation.objects
            .filter(models.Q(user_a=me) | models.Q(user_b=me))
            .select_related("user_a", "user_b", "user_a__profile", "user_b__profile")
            .order_by("-last_message_at", "-created_at")
        )

    def get_serializer_class(self):
        return ConversationCreateSerializer if self.request.method == "POST" else ConversationSerializer

    def get_serializer_context(self):
        return {"request": self.request}

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        ser = ConversationSerializer(qs, many=True, context={"request": request})
        return Response(ser.data)

    def create(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user_id = ser.validated_data["user_id"]

        # ensure participant order (small helper on model, or inline)
        a, b = (request.user.id, user_id) if request.user.id < user_id else (user_id, request.user.id)
        convo, _ = Conversation.objects.get_or_create(user_a_id=a, user_b_id=b)

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
        convo = get_object_or_404(
            Conversation.objects.select_related("user_a", "user_b"),
            id=cid
        )
        me = self.request.user
        if me.id not in (convo.user_a_id, convo.user_b_id):
            return None
        return convo

    def get_queryset(self):
        convo = self.get_conversation()
        if convo is None:
            return Message.objects.none()
        return (
            Message.objects
            .filter(conversation=convo)
            .select_related("sender", "sender__profile")
            .order_by("created_at")
        )

    def get_serializer_class(self):
        return MessageCreateSerializer if self.request.method == "POST" else MessageSerializer

    def get_serializer_context(self):
        ctx = {"request": self.request}
        convo = self.get_conversation()
        if convo is not None:
            ctx["conversation"] = convo
        return ctx

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        ser = MessageSerializer(qs, many=True, context={"request": request})
        return Response({"count": qs.count(), "next": None, "previous": None, "results": ser.data})

    def create(self, request, *args, **kwargs):
        convo = self.get_conversation()
        if convo is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        # participant & block checks + save
        create_ser = MessageCreateSerializer(data=request.data, context={"request": request, "conversation": convo})
        create_ser.is_valid(raise_exception=True)
        msg = Message.objects.create(conversation=convo, sender=request.user, body=create_ser.validated_data["body"])

        # bump last_message_at
        Conversation.objects.filter(id=convo.id).update(last_message_at=timezone.now())

        out = MessageSerializer(msg, context={"request": request}).data
        return Response(out, status=status.HTTP_201_CREATED)

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

        updated = (
            Message.objects
            .filter(conversation=convo)
            .exclude(sender=me)
            .filter(is_read=False)
            .update(is_read=True, read_at=timezone.now())
        )
        return Response({"updated": updated}, status=status.HTTP_200_OK)

# =========================
# Password reset
# =========================

class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        # implement email sending in serializer.save() if desired
        return Response({"detail": "If an account with that email exists, a reset link has been sent."})

class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        # implement password update in serializer.save() if desired
        return Response({"detail": "Password has been reset successfully."})