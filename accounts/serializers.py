from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import Profile, Block, Report, Conversation,Message
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.core.mail import send_mail

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

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
        p = user.profile
        p.display_name = profile_fields.get("display_name") or user.username
        p.country_of_origin = profile_fields.get("country_of_origin") or ""
        p.current_city = profile_fields.get("current_city") or ""
        p.languages = profile_fields.get("languages") or []
        p.save()
        return user

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ("display_name","country_of_origin","current_city","profession","languages","bio","is_location_hidden","last_active_at")

class MeSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()
    class Meta:
        model = User
        fields = ("id","username","email","profile")

class PublicProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True)

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
        )

class BlockSerializer(serializers.ModelSerializer):
    """Create a block using a target user_id."""

    user_id = serializers.IntegerField(write_only=True)
    blocked_user = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Block
        fields = ("user_id", "blocked_user", "created_at")

    def get_blocked_user(self, obj):
        # small public payload for convenience
        return {"id": obj.blocked_id}

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
        # enforce uniqueness at app level (DB also has unique_together)
        block, _ = Block.objects.get_or_create(blocker=me, blocked_id=target_id)
        return block


class BlockListItemSerializer(serializers.ModelSerializer):
    blocked_user = serializers.SerializerMethodField()

    class Meta:
        model = Block
        fields = ("blocked_user", "created_at")

    def get_blocked_user(self, obj):
        # You can expand this to include display_name, etc.
        u = obj.blocked
        return {"id": u.id, "username": u.username}


class ReportSerializer(serializers.ModelSerializer):
    reported_user_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Report
        fields = ("reported_user_id", "reason", "details", "created_at")

    def validate_reported_user_id(self, value):
        request = self.context["request"]
        if value == request.user.id:
            raise serializers.ValidationError("You cannot report yourself.")
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value

    def create(self, validated_data):
        me = self.context["request"].user
        return Report.objects.create(
            reporter=me,
            reported_user_id=validated_data["reported_user_id"],
            reason=validated_data["reason"],
            details=validated_data.get("details", ""),
        )
    
class UserMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username")

class ConversationSerializer(serializers.ModelSerializer):
    other_user = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = ("id", "other_user", "created_at", "last_message_at", "unread_count")

    def get_other_user(self, obj):
        me = self.context["request"].user
        other = obj.user_b if obj.user_a_id == me.id else obj.user_a
        return UserMiniSerializer(other).data

    def get_unread_count(self, obj):
        me = self.context["request"].user
        return obj.messages.filter(is_read=False).exclude(sender=me).count()


class ConversationCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

    def validate_user_id(self, value):
        request = self.context["request"]
        if value == request.user.id:
            raise serializers.ValidationError("You cannot start a conversation with yourself.")
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User not found.")
        # block check (either direction)
        if Block.objects.filter(blocker_id=request.user.id, blocked_id=value).exists() or \
           Block.objects.filter(blocker_id=value, blocked_id=request.user.id).exists():
            raise serializers.ValidationError("Conversation not allowed (blocked).")
        return value

    def create(self, validated_data):
        me = self.context["request"].user
        other_id = validated_data["user_id"]
        convo = Conversation.for_users(me.id, other_id).first()
        if not convo:
            # Create with ordered pair
            a, b = (me.id, other_id) if me.id < other_id else (other_id, me.id)
            convo = Conversation.objects.create(user_a_id=a, user_b_id=b)
        return convo


class MessageSerializer(serializers.ModelSerializer):
    sender = UserMiniSerializer(read_only=True)

    class Meta:
        model = Message
        fields = ("id", "sender", "body", "created_at", "is_read", "read_at")


class MessageCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ("body",)

    def validate(self, attrs):
        request = self.context["request"]
        convo: Conversation = self.context["conversation"]
        # participant check
        if request.user.id not in (convo.user_a_id, convo.user_b_id):
            raise serializers.ValidationError("You are not a participant of this conversation.")
        # block checks
        other_id = convo.user_b_id if request.user.id == convo.user_a_id else convo.user_a_id
        from .models import Block
        if Block.objects.filter(blocker_id=request.user.id, blocked_id=other_id).exists() or \
           Block.objects.filter(blocker_id=other_id, blocked_id=request.user.id).exists():
            raise serializers.ValidationError("Messaging not allowed (blocked).")
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        convo: Conversation = self.context["conversation"]
        msg = Message.objects.create(
            conversation=convo,
            sender=request.user,
            body=validated_data["body"],
        )
        # update last_message_at
        Conversation.objects.filter(id=convo.id).update(last_message_at=timezone.now())
        return msg


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
        # Expect a list of strings
        if v is None:
            return []
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise serializers.ValidationError("Languages must be a list of strings.")
        return [s.strip() for s in v if s.strip()]
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value.strip().lower()

    def save(self, **kwargs):
        email = self.validated_data["email"]
        # Privacy: same response whether user exists or not
        for user in User.objects.filter(email=email):
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)
            reset_link = f"{settings.FRONTEND_RESET_URL}?uid={uidb64}&token={token}"
            send_mail(
                subject="Reset your HomeBridge password",
                message=(
                    "Hello,\n\n"
                    "Use this link to reset your password:\n"
                    f"{reset_link}\n\n"
                    "If you didn't request this, ignore this email."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=True,
            )
        return {"sent": True}


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        uid = attrs.get("uid")
        token = attrs.get("token")
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except Exception:
            raise serializers.ValidationError({"uid": "Invalid user id."})
        if not token_generator.check_token(user, token):
            raise serializers.ValidationError({"token": "Invalid or expired token."})
        attrs["user"] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        new_pw = self.validated_data["new_password"]
        user.set_password(new_pw)
        user.save(update_fields=["password"])
        return {"reset": True}
