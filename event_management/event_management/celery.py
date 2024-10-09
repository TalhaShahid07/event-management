# # import os
# # from celery import Celery, shared_task

# # os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'event_management.settings')

# # app = Celery('event_management')

# # app.config_from_object('django.conf:settings', namespace='CELERY')
# # # Set the time zone explicitly
# # app.conf.timezone = "US/Eastern"
# # app.autodiscover_tasks()
# # celery_task = shared_task
# # # Recommended settings for Windows
# # app.conf.worker_pool = 'solo'  # Use solo pool for Windows

# # @celery_task(bind=True)
# # def debug_task(self):
# #     print("Request: {0!r}".format(self.request))




# from _future_ import absolute_import
import os
from celery import Celery, shared_task
from django.conf import settings
# ---------------------------------------------------------------------
#
#
# ---------------------------------------------------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "event_management.settings")

app = Celery("event_management")
app.config_from_object("django.conf:settings", namespace="CELERY")

# Set the time zone explicitly
app.conf.timezone = "US/Eastern"

app.autodiscover_tasks()

# Create an alias for shared_task named celery_task
celery_task = shared_task


@celery_task(bind=True)
def debug_task(self):
    print("Request: {0!r}".format(self.request))

# import os
# from celery import Celery, shared_task
# from django.conf import settings

# # Set the default Django settings module for the 'celery' program.
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "event_management.settings")

# app = Celery("event_management")

# # Load task modules from all registered Django app configs.
# app.config_from_object("django.conf:settings", namespace="CELERY")

# # Set the time zone explicitly
# app.conf.timezone = "US/Eastern"

# # Automatically discover tasks in Django apps
# app.autodiscover_tasks()

# # Create an alias for shared_task named celery_task
# celery_task = shared_task

# # Optional: Debugging task to test the Celery setup
# @celery_task(bind=True)
# def debug_task(self):
#     print("Request: {0!r}".format(self.request))
