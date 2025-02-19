from django.urls import path
from .views import FileUploadView, FileListView, FileDownloadView, AdminDashboardView, FileShareView, SharedToMeFilesView, SharedByMeFilesView, RevokeAccessView, AuditLogView, GenerateShareableLinkView, AccessFileViaLinkView, AdminFileListAPIView, AdminFileDeleteAPIView, ModifyPermissionView

urlpatterns = [
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('my-files/', FileListView.as_view(), name='my-files'),
    path('download/<int:file_id>/', FileDownloadView.as_view(), name='file-download'),
    path('admin-dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
    path('share/', FileShareView.as_view(), name='share-file'),
    path('shared-to-me/', SharedToMeFilesView.as_view(), name='shared-to-me'),
    path('shared-by-me/', SharedByMeFilesView.as_view(), name='shared-by-me'),
    path('revoke-access/', RevokeAccessView.as_view(), name='revoke-access'),
    path('modify-permission/', ModifyPermissionView.as_view(), name='modify-permission'), # New URL for modify permission
    path('share-link/generate/', GenerateShareableLinkView.as_view(), name='generate-shareable-link'),
    path('share-link/access/<uuid:link_uuid>/', AccessFileViaLinkView.as_view(), name='access-shareable-link'),

    path('admin/files/', AdminFileListAPIView.as_view(), name='admin-file-list'), 
    path('admin/file/<int:file_id>/', AdminFileDeleteAPIView.as_view(), name='admin-file-delete'),

    path('admin/audit-logs/', AuditLogView.as_view(), name='admin-audit-logs'),
]