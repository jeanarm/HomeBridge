from django.urls import path
from .views import BlockListCreateView, BlockDeleteView, ReportCreateView

urlpatterns = [
    path("blocks/", BlockListCreateView.as_view(), name="blocks_list_create"),
    path("blocks/<int:user_id>/", BlockDeleteView.as_view(), name="blocks_delete"),
    path("reports/", ReportCreateView.as_view(), name="reports_create"),
]
