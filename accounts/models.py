from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
import uuid


class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    display_name = models.CharField(max_length=80)
    country_of_origin = models.CharField(max_length=20, blank=True)  # ISO-3166-1
    current_city = models.CharField(max_length=80, blank=True)
    profession = models.CharField(max_length=80, blank=True)
    languages = models.JSONField(default=list)  # e.g. ["en", "fr"]
    bio = models.TextField(blank=True)
    is_location_hidden = models.BooleanField(default=True)
    avatar = models.ImageField(upload_to="profile_avatars/", blank=True, null=True)
    last_active_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.display_name or getattr(self.user, "username", str(self.user_id))


class Block(models.Model):
    blocker = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="blocks_made",
    )
    blocked = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="blocks_received",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("blocker", "blocked"),
                name="unique_block_pair",
            )
        ]

    def clean(self):
        if self.blocker_id == self.blocked_id:
            raise ValidationError("You cannot block yourself.")

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.blocker_id} -> {self.blocked_id}"


class Report(models.Model):
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports_made",
    )
    reported_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports_received",
    )
    reason = models.CharField(max_length=120)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report by {self.reporter_id} on {self.reported_user_id}: {self.reason}"


class Conversation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_a = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_a",
    )
    user_b = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_b",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_message_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user_a"]),
            models.Index(fields=["user_b"]),
            models.Index(fields=["-last_message_at"]),
        ]
        constraints = [
            # Uniqueness is enforced after we normalize (user_a, user_b) order in save()
            models.UniqueConstraint(
                fields=["user_a", "user_b"], name="unique_pair_ordered"
            ),
        ]

    def save(self, *args, **kwargs):
        # enforce ordering so the pair is unique regardless of order
        if self.user_a_id and self.user_b_id and self.user_a_id > self.user_b_id:
            self.user_a_id, self.user_b_id = self.user_b_id, self.user_a_id
        super().save(*args, **kwargs)

    @staticmethod
    def for_users(u1_id: int, u2_id: int):
        # normalize ordering
        a, b = (u1_id, u2_id) if u1_id < u2_id else (u2_id, u1_id)
        return Conversation.objects.filter(user_a_id=a, user_b_id=b)

    def __str__(self):
        return f"{self.user_a_id} ↔ {self.user_b_id}"


class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["conversation", "created_at"]),
            models.Index(fields=["sender", "created_at"]),
            models.Index(fields=["is_read"]),
        ]
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.conversation_id} · {self.sender_id} @ {self.created_at}"