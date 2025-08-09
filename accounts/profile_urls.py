from django.urls import path
from .views import ProfileListView, ProfileDetailView,MyProfileView

urlpatterns = [
    path("", ProfileListView.as_view(), name="profiles_list"),
    path("<int:user_id>/", ProfileDetailView.as_view(), name="profile_detail"),
    path("me/", MyProfileView.as_view(), name="profile_me"),
]
