from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

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

# helper
def is_blocked(u1_id: int, u2_id: int) -> bool:
    return Block.objects.filter(
        Q(blocker_id=u1_id, blocked_id=u2_id) | Q(blocker_id=u2_id, blocked_id=u1_id)
    ).exists()

# =========================
# Auth
# =========================

class RegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

class AuthMeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        return Response(MeSerializer(request.user, context={"request": request}).data)

class LogoutView(APIView):
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
    serializer_class = PublicProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        me = self.request.user
        qs = (
            Profile.objects.select_related("user")
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
            blocked_pairs = Block.objects.filter(Q(blocker=me) | Q(blocked=me)).values_list("blocker_id", "blocked_id")
            exclude_ids = set()
            for a, b in blocked_pairs:
                if a != me.id: exclude_ids.add(a)
                if b != me.id: exclude_ids.add(b)
            if exclude_ids:
                qs = qs.exclude(user_id__in=list(exclude_ids))

        return qs.order_by("-last_active_at", "user_id")

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
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileUpdateSerializer

    def get_object(self):
        return self.request.user.profile

    def get(self, request, *args, **kwargs):
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
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Block.objects.filter(blocker=self.request.user).select_related("blocked")

    def get_serializer_class(self):
        return BlockListItemSerializer if self.request.method == "GET" else BlockSerializer

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request
        return ctx

class BlockDeleteView(APIView):
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
        other_id = ser.validated_data["user_id"]

        if request.user.id == other_id:
            return Response({"detail": "Cannot create a conversation with yourself."},
                            status=status.HTTP_400_BAD_REQUEST)

        if is_blocked(request.user.id, other_id):
            return Response({"detail": "You cannot start a conversation with this user."},
                            status=status.HTTP_403_FORBIDDEN)

        a, b = (request.user.id, other_id) if request.user.id < other_id else (other_id, request.user.id)
        convo, _ = Conversation.objects.get_or_create(user_a_id=a, user_b_id=b)

        out = ConversationSerializer(convo, context={"request": request})
        return Response(out.data, status=status.HTTP_201_CREATED)

class MessageListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_conversation(self):
        cid = self.kwargs["cid"]
        convo = get_object_or_404(
            Conversation.objects.select_related("user_a", "user_b"), id=cid
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

        other_id = convo.user_b_id if request.user.id == convo.user_a_id else convo.user_a_id
        if is_blocked(request.user.id, other_id):
            return Response({"detail": "You cannot message this user."},
                            status=status.HTTP_403_FORBIDDEN)

        create_ser = MessageCreateSerializer(data=request.data, context={"request": request, "conversation": convo})
        create_ser.is_valid(raise_exception=True)
        msg = Message.objects.create(conversation=convo, sender=request.user, body=create_ser.validated_data["body"])

        Conversation.objects.filter(id=convo.id).update(last_message_at=timezone.now())

        out = MessageSerializer(msg, context={"request": request}).data
        return Response(out, status=status.HTTP_201_CREATED)

class ConversationMarkReadView(APIView):
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
    throttle_scope = "password_reset"  # needs DRF scoped throttle config

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()  # send email if user exists
        return Response({"detail": "If an account with that email exists, a reset link has been sent."})

class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()  # set password
        return Response({"detail": "Password has been reset successfully."})
