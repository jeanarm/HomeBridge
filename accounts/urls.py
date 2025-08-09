# from django.urls import path
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from .views import RegisterView, MeView, LogoutView, LogoutAllView
# from .views import ProfileListView, ProfileDetailView, BlockListCreateView,BlockDeleteView,ReportCreateView

# urlpatterns = [
#     #Auth
#     path("register/", RegisterView.as_view(), name="register"),
#     path("login/", TokenObtainPairView.as_view(), name="login"),            # LOGIN (JWT)
#     path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
#     path("logout/", LogoutView.as_view(), name="logout"),                   # logout this device
#     path("logout/all/", LogoutAllView.as_view(), name="logout_all"),        # logout all devices
#     path("me/", MeView.as_view(), name="me"),

#      # Discovery
#     path("profiles/", ProfileListView.as_view(), name="profiles_list"),
#     path("profiles/<int:user_id>/", ProfileDetailView.as_view(), name="profile_detail"),

#     path("blocks/", BlockListCreateView.as_view(), name="blocks_list_create"),
#     path("blocks/<int:user_id>/", BlockDeleteView.as_view(), name="blocks_delete"),
#     # Reports
#     path("reports/", ReportCreateView.as_view(), name="reports_create"),
# ]
