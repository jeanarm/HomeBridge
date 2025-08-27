# accounts/auth_urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    RegisterView,
    AuthMeView,          
    LogoutView,
    LogoutAllView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
)

urlpatterns = [
    # Auth
    path("register/", RegisterView.as_view(), name="auth-register"),
    path("login/", TokenObtainPairView.as_view(), name="auth-login"),
    path("refresh/", TokenRefreshView.as_view(), name="auth-refresh"),
    path("me/", AuthMeView.as_view(), name="auth-me"),
    path("logout/", LogoutView.as_view(), name="auth-logout"),
    path("logout_all/", LogoutAllView.as_view(), name="auth-logout-all"),

    # Password reset
    path("password/reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]