from django.conf import settings
from storages.backends.azure_storage import AzureStorage
from azure.storage.blob import BlobServiceClient


blob_service_client = BlobServiceClient(
    account_url=f"https://{settings.AZURE_ACCOUNT_NAME}.blob.core.windows.net", 
    credential=settings.AZURE_ACCOUNT_KEY)

class AzureMediaStorage(AzureStorage):
    azure_container = settings.AZURE_CONTAINER_NAME

    def set_container_name(self, name):
        self.azure_container = name