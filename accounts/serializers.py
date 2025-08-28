from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.db import transaction
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Profile, Block, Report, Conversation, Message

User = get_user_model()

# =========================
# Auth / Registration
# =========================

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(), message="Email already used.")]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all(), message="Username already used.")]
    )
    password = serializers.CharField(write_only=True, trim_whitespace=False)
    display_name = serializers.CharField(write_only=True, required=True)
    country_of_origin = serializers.CharField(write_only=True, max_length=100, required=False, allow_blank=True)
    current_city = serializers.CharField(write_only=True, max_length=80, required=False, allow_blank=True)
    languages = serializers.ListField(child=serializers.CharField(), required=False)

    class Meta:
        model = User
        fields = ("username", "email", "password", "display_name", "country_of_origin", "current_city", "languages")

    def validate_username(self, v): return v.strip()
    def validate_email(self, v): return v.strip().lower()
    def validate_password(self, value):
        validate_password(value)
        return value

    @transaction.atomic
    def create(self, validated_data):
        profile_fields = {k: validated_data.pop(k, None) for k in ["display_name", "country_of_origin", "current_city", "languages"]}
        user = User.objects.create_user(**validated_data)
        p = user.profile  # ensured by signal
        p.display_name = profile_fields.get("display_name") or user.username
        p.country_of_origin = profile_fields.get("country_of_origin") or ""
        p.current_city = profile_fields.get("current_city") or ""
        p.languages = profile_fields.get("languages") or []
        p.save()
        return user

# =========================
# Profile serializers
# =========================

class ProfileSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(read_only=True)

    class Meta:
        model = Profile
        fields = (
            "display_name",
            "country_of_origin",
            "current_city",
            "profession",
            "languages",
            "bio",
            "is_location_hidden",
            "last_active_at",
            "avatar",
        )

class MeSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()
    class Meta:
        model = User
        fields = ("id", "username", "email", "profile")

class PublicProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    avatar = serializers.ImageField(read_only=True)

    class Meta:
        model = Profile
        fields = (
            "user_id",
            "display_name",
            "country_of_origin",
            "current_city",
            "profession",
            "languages",
            "bio",
            "last_active_at",
            "avatar",
        )

# =========================
# Blocks / Reports
# =========================

class BlockSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(write_only=True)
    blocked_user = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Block
        fields = ("user_id", "blocked_user", "created_at")
        read_only_fields = ("created_at",)

    def get_blocked_user(self, obj):
        u = obj.blocked
        return {"id": u.id}

    def validate_user_id(self, value):
        request = self.context["request"]
        if value == request.user.id:
            raise serializers.ValidationError("You cannot block yourself.")
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value

    def create(self, validated_data):
        me = self.context["request"].user
        target_id = validated_data["user_id"]
        block, _ = Block.objects.get_or_create(blocker=me, blocked_id=target_id)
        return block

class BlockListItemSerializer(serializers.ModelSerializer):
    blocked_user = serializers.SerializerMethodField()

    class Meta:
        model = Block
        fields = ("blocked_user", "created_at")

    def get_blocked_user(self, obj):
        u = obj.blocked
        return {"id": u.id, "username": u.username}

class ReportSerializer(serializers.ModelSerializer):
    reported_user_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Report
        fields = ("reported_user_id", "reason", "details", "created_at")
        read_only_fields = ("created_at",)

    def validate_reported_user_id(self, value):
        request = self.context["request"]
        if value == request.user.id:
            raise serializers.ValidationError("You cannot report yourself.")
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value

    def create(self, validated_data):
        me = self.context["request"].user
        reported = User.objects.get(id=validated_data.pop("reported_user_id"))
        return Report.objects.create(reporter=me, reported_user=reported, **validated_data)

# =========================
# Tiny user payload for chat & conversations
# =========================

class UserTinySerializer(serializers.ModelSerializer):
    display_name = serializers.CharField(source="profile.display_name", read_only=True)
    avatar = serializers.ImageField(source="profile.avatar", read_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "display_name", "avatar")

# =========================
# Conversations & Messages
# =========================

class ConversationSerializer(serializers.ModelSerializer):
    other_user = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = ("id", "other_user", "created_at", "last_message_at", "unread_count")

    def get_other_user(self, obj):
        me = self.context["request"].user
        other = obj.user_b if obj.user_a_id == me.id else obj.user_a
        return UserTinySerializer(other, context=self.context).data

    def get_unread_count(self, obj):
        me = self.context["request"].user
        return obj.messages.filter(is_read=False).exclude(sender=me).count()

class ConversationCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

class MessageSerializer(serializers.ModelSerializer):
    sender = UserTinySerializer(read_only=True)

    class Meta:
        model = Message
        fields = ("id", "sender", "body", "created_at", "is_read", "read_at")

class MessageCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ("body",)

# =========================
# Profile update
# =========================

class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = (
            "display_name",
            "country_of_origin",
            "current_city",
            "profession",
            "languages",
            "bio",
            "is_location_hidden",
            "avatar",
        )

    def validate_display_name(self, v):
        v = (v or "").strip()
        if not v:
            raise serializers.ValidationError("Display name cannot be empty.")
        if len(v) > 80:
            raise serializers.ValidationError("Display name too long.")
        return v

    def validate_languages(self, v):
        if v is None:
            return []
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise serializers.ValidationError("Languages must be a list of strings.")
        return [s.strip() for s in v if s.strip()]

# =========================
# Password reset (request/confirm)
# =========================

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def save(self, **kwargs):
        email = self.validated_data["email"].strip().lower()
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return  # prevent user enumeration

        token = PasswordResetTokenGenerator().make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        from django.conf import settings
        base = getattr(settings, "FRONTEND_RESET_URL", "homebridge://reset-password")
        sep = "&" if "?" in base else "?"
        reset_link = f"{base}{sep}uid={uid}&token={token}"

        subject = "Reset your HomeBridge password"
        body = (
            f"Hello {getattr(user, 'username', 'there')},\n\n"
            f"Tap the link below to reset your password:\n{reset_link}\n\n"
            f"If you didn’t request this, you can ignore this email."
        )
        # DEFAULT_FROM_EMAIL will be used if sender is None
        send_mail(subject, body, None, [email], fail_silently=False)

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def save(self, **kwargs):
        try:
            uid_int = int(urlsafe_base64_decode(self.validated_data["uid"]).decode())
        except Exception:
            raise serializers.ValidationError({"uid": "Invalid uid"})

        try:
            user = User.objects.get(pk=uid_int)
        except User.DoesNotExist:
            raise serializers.ValidationError({"uid": "Invalid user"})

        token = self.validated_data["token"]
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"token": "Invalid or expired token"})

        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])
        return user
