# ####################################

# from django.shortcuts import render, get_object_or_404
# from rest_framework import viewsets, status
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth import authenticate
# from rest_framework.decorators import action
# from django.utils.timezone import now
# from .models import CustomUser, Event, Registration
# from .serializers import CustomUserSerializer, EventSerializer, RegistrationSerializer
# from .tasks import generate_registration_report, send_event_registration_email  # Import the Celery tasks
# from celery.result import AsyncResult


# class RegisterUserView(APIView):
#     permission_classes = [AllowAny]  # Allow any user to register

#     def post(self, request):
#         user_data = {
#             'username': request.data.get('username'),
#             'password': request.data.get('password'),
#             'role': request.data.get('role'),  # Organizer or Attendee
#             'email': request.data.get('email')
#         }

#         # Create a CustomUser instance
#         serializer = CustomUserSerializer(data=user_data)
#         if serializer.is_valid():
#             user = serializer.save()
#             return Response({
#                 'detail': 'Successfully registered.'
#             }, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class LoginUserView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         username = request.data.get('username')
#         password = request.data.get('password')

#         # Print input data for debugging
#         print(f"Login attempt: Username={username}, Password={password}")

#         # Authenticate the user
#         user = authenticate(username=username, password=password)

#         if user is not None:
#             refresh = RefreshToken.for_user(user)  # Generate JWT tokens
#             return Response({
#                 'detail': 'Login successful.',
#                 'user_id': user.id,
#                 'username': user.username,
#                 'role': user.role,
#                 'access': str(refresh.access_token),  # Access token
#                 'refresh': str(refresh),  # Refresh token
#             }, status=status.HTTP_200_OK)

#         print("Authentication failed: Invalid username or password")
#         return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)


# class UserViewSet(viewsets.ModelViewSet):
#     queryset = CustomUser.objects.all()
#     serializer_class = CustomUserSerializer
#     permission_classes = [AllowAny]  # Allow any user to access user endpoints


# class EventViewSet(viewsets.ModelViewSet):
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer
#     permission_classes = [AllowAny]  # Allow any user to access event endpoints
#     def get_queryset(self):
#         # Return only events created by the logged-in organizer
#         return Event.objects.filter(organizer=self.request.user) 
#     def get_queryset(self):
#         # Return only upcoming events that are not full
#         return Event.objects.filter(capacity__gt=0)
    
#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def register(self, request, pk=None):
#         """Register the authenticated user for the event if there's capacity."""
#         event = self.get_object()  # Get the event instance
#         user = request.user

#     # Check if the user is already registered for the event
#         if Registration.objects.filter(event=event, user=user).exists():
#             return Response({'detail': 'You are already registered for this event.'}, status=status.HTTP_400_BAD_REQUEST)

#     # Check if the event has capacity
#         registered_count = Registration.objects.filter(event=event).count()
#         if registered_count >= event.capacity:
#             return Response({'detail': 'This event is full.'}, status=status.HTTP_400_BAD_REQUEST)

#     # Check if the user is an attendee
#         if user.role != 'Attendee':  # Assuming the role field is a string and case-sensitive
#             return Response({'detail': 'Only attendees can register for this event.'}, status=status.HTTP_403_FORBIDDEN)

#     # Register the user for the event
#         registration = Registration.objects.create(event=event, user=user)

#     # Send confirmation email asynchronously using Celery
#         send_event_registration_email.delay(user.email, event.title)  # Use event.title

#         return Response({'detail': 'Successfully registered for the event.'}, status=status.HTTP_201_CREATED)


#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def check_in(self, request, pk=None):
#         """Check in the authenticated user if they are registered."""
#         event = self.get_object()
#         user = request.user

#         registration = get_object_or_404(Registration, event=event, user=user)
#         if registration.checked_in:
#             return Response({'detail': 'You are already checked in.'}, status=status.HTTP_400_BAD_REQUEST)

#         # Mark the user as checked in
#         registration.checked_in = True
#         registration.save()
#         return Response({'detail': 'Successfully checked in.'}, status=status.HTTP_200_OK)

#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def cancel_registration(self, request, pk=None):
#         """Cancel registration if the event is in the future."""
#         event = self.get_object()

#         # Check if the event is in the future
#         if event.start_time <= now():
#             return Response({'error': 'You can only cancel registration for future events.'},
#                             status=status.HTTP_400_BAD_REQUEST)

#         user = request.user
#         try:
#             registration = Registration.objects.get(event=event, user=user)
#         except Registration.DoesNotExist:
#             return Response({'error': 'You are not registered for this event.'}, status=status.HTTP_404_NOT_FOUND)

#         # Delete the registration
#         registration.delete()

#         return Response({'message': 'Registration canceled successfully.'}, status=status.HTTP_200_OK)


# class RegistrationViewSet(viewsets.ModelViewSet):
#     queryset = Registration.objects.all()
#     serializer_class = RegistrationSerializer
#     permission_classes = [AllowAny]  # Allow any user to access registration endpoints


# class AvailableEventsView(APIView):
#     permission_classes = [AllowAny]  # Allow any user to view available events

#     def get(self, request):
#         available_events = Event.objects.filter(capacity__gt=0)  # Only list events that have available spots
#         serializer = EventSerializer(available_events, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)


# class RegistrationsReportView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request, event_id):
#         task = generate_registration_report.delay(event_id)  # Only pass event_id
#         return Response({
#             'task_id': task.id,
#             'detail': 'The registration report is being generated. You will be notified once it is ready.'
#         }, status=status.HTTP_202_ACCEPTED)


# class CapacityStatusView(APIView):
#     permission_classes = [AllowAny]  # Allow any user to access this view

#     def get(self, request, event_id):
#         event = get_object_or_404(Event, id=event_id)

#         total_capacity = event.capacity
#         registered_count = Registration.objects.filter(event=event).count()
#         remaining_capacity = total_capacity - registered_count

#         return Response({
#             'total_capacity': total_capacity,
#             'registered_count': registered_count,
#             'remaining_capacity': remaining_capacity
#         }, status=status.HTTP_200_OK)


# class ReportStatusView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request, task_id):
#         result = AsyncResult(task_id)

#         if result.ready():
#             return Response({
#                 'status': 'completed',
#                 'result': result.result  # This will return the report file path or any other info you want to return
#             }, status=status.HTTP_200_OK)
#         else:
#             return Response({
#                 'status': 'pending',
#                 'task_id': task_id
#             }, status=status.HTTP_202_ACCEPTED)

# ####################################






####################################

from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.decorators import action
from django.utils.timezone import now
from .models import CustomUser, Event, Registration
from .serializers import CustomUserSerializer, EventSerializer, RegistrationSerializer
from .tasks import generate_registration_report, send_event_registration_email  # Import the Celery tasks
from celery.result import AsyncResult
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied


class RegisterUserView(APIView):
    permission_classes = [AllowAny]  # Allow any user to register

    def post(self, request):
        user_data = {
            'username': request.data.get('username'),
            'password': request.data.get('password'),
            'role': request.data.get('role'),  # Organizer or Attendee
            'email': request.data.get('email')
        }

        # Create a CustomUser instance
        serializer = CustomUserSerializer(data=user_data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'detail': 'Successfully registered.'
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Print input data for debugging
        print(f"Login attempt: Username={username}, Password={password}")

        # Authenticate the user
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)  # Generate JWT tokens
            return Response({
                'detail': 'Login successful.',
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'access': str(refresh.access_token),  # Access token
                'refresh': str(refresh),  # Refresh token
            }, status=status.HTTP_200_OK)

        print("Authentication failed: Invalid username or password")
        return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)


class UserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]  # Allow any user to access user endpoints


class IsOrganizerPermission(IsAuthenticated):
    """Custom permission to allow only organizers to perform certain actions."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Organizer'

class IsAttendeePermission(IsAuthenticated):
    """Custom permission to allow only attendees to register and check-in for events."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Attendee'

class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Organizers should only see events they created
        if self.request.user.role == 'Organizer':
            return Event.objects.filter(organizer=self.request.user)
        # Attendees should only access available events (this is handled separately)
        raise PermissionDenied("You do not have permission to view this endpoint.")

    def create(self, request, *args, **kwargs):
        # Only organizers can create events
        if request.user.role != 'Organizer':
            raise PermissionDenied("Only organizers can create events.")
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        # Only organizers can update events
        if request.user.role != 'Organizer':
            raise PermissionDenied("Only organizers can update events.")
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        # Only organizers can delete events
        if request.user.role != 'Organizer':
            raise PermissionDenied("Only organizers can delete events.")
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'], permission_classes=[IsAttendeePermission])
    def register(self, request, pk=None):
        """Attendee registers for an event."""
        event = get_object_or_404(Event, pk=pk)
        user = request.user

        if user.role != 'Attendee':
            return Response({'detail': 'Only attendees can register for events.'}, status=status.HTTP_403_FORBIDDEN)

        if Registration.objects.filter(event=event, user=user).exists():
            return Response({'detail': 'You are already registered for this event.'}, status=status.HTTP_400_BAD_REQUEST)

        registered_count = Registration.objects.filter(event=event).count()
        if registered_count >= event.capacity:
            return Response({'detail': 'This event is full.'}, status=status.HTTP_400_BAD_REQUEST)

        Registration.objects.create(event=event, user=user)
        send_event_registration_email.delay(user.email, event.title)
        return Response({'detail': 'Successfully registered for the event.'}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], permission_classes=[IsAttendeePermission])
    def check_in(self, request, pk=None):
        """Attendee checks in to an event."""
        event = get_object_or_404(Event, pk=pk)
        user = request.user

        if user.role != 'Attendee':
            return Response({'detail': 'Only attendees can check-in for events.'}, status=status.HTTP_403_FORBIDDEN)

        registration = get_object_or_404(Registration, event=event, user=user)
        if registration.checked_in:
            return Response({'detail': 'You are already checked in.'}, status=status.HTTP_400_BAD_REQUEST)

        registration.checked_in = True
        registration.save()
        return Response({'detail': 'Successfully checked in.'}, status=status.HTTP_200_OK)

class AvailableEventsView(APIView):
    """View for attendees to see available events."""
    permission_classes = [IsAttendeePermission]

    def get(self, request):
        available_events = Event.objects.filter(capacity__gt=0)
        serializer = EventSerializer(available_events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



class RegistrationViewSet(viewsets.ModelViewSet):
    queryset = Registration.objects.all()
    serializer_class = RegistrationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Attendees can only see events they registered for
        if self.request.user.role == 'Attendee':
            return Registration.objects.filter(user=self.request.user)
        raise PermissionDenied("Only attendees can view their registrations.")

    def list(self, request, *args, **kwargs):
        # GET /registrations/: List all events the logged-in user (Attendee) has registered for
        if request.user.role != 'Attendee':
            raise PermissionDenied("Only attendees can view their registrations.")
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel_registration(self, request, pk=None):
        """POST /events/{event_id}/cancel-registration/: Allows the attendee to cancel registration if the event is in the future."""
        event = get_object_or_404(Event, pk=pk)
        user = request.user

        # Ensure the user is an Attendee
        if user.role != 'Attendee':
            return Response({'detail': 'Only attendees can cancel event registration.'}, status=status.HTTP_403_FORBIDDEN)

        # Ensure the user is registered for the event
        try:
            registration = Registration.objects.get(event=event, user=user)
        except Registration.DoesNotExist:
            return Response({'detail': 'You are not registered for this event.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the event is in the future
        if event.start_time <= now():
            return Response({'detail': 'You can only cancel registration for future events.'}, status=status.HTTP_400_BAD_REQUEST)

        # Cancel the registration by deleting it
        registration.delete()
        return Response({'detail': 'Registration canceled successfully.'}, status=status.HTTP_200_OK)




class RegistrationsReportView(APIView):
    permission_classes = [IsOrganizerPermission]  # Only organizers can generate reports

    def get(self, request, event_id):
        event = get_object_or_404(Event, pk=event_id)

        if event.organizer != request.user:
            return Response({'detail': 'You are not the organizer of this event.'}, status=status.HTTP_403_FORBIDDEN)

        task = generate_registration_report.delay(event_id)  # Generate the CSV asynchronously
        return Response({
            'task_id': task.id,
            'detail': 'The registration report is generated please check thed desired folder'
        }, status=status.HTTP_202_ACCEPTED)


class CapacityStatusView(APIView):
    permission_classes = [IsOrganizerPermission]  # Only organizers can access capacity status

    def get(self, request, event_id):
        event = get_object_or_404(Event, pk=event_id)

        if event.organizer != request.user:
            return Response({'detail': 'You are not the organizer of this event.'}, status=status.HTTP_403_FORBIDDEN)

        total_capacity = event.capacity
        registered_count = Registration.objects.filter(event=event).count()
        remaining_capacity = total_capacity - registered_count

        return Response({
            'total_capacity': total_capacity,
            'registered_count': registered_count,
            'remaining_capacity': remaining_capacity
        }, status=status.HTTP_200_OK)


class ReportStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id):
        result = AsyncResult(task_id)

        if result.ready():
            return Response({
                'status': 'completed',
                'result': result.result  # This will return the report file path or any other info you want to return
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': 'pending',
                'task_id': task_id
            }, status=status.HTTP_202_ACCEPTED)




####################################

# class EventViewSet(viewsets.ModelViewSet):
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         # Organizers should only see events they created
#         if self.request.user.role == 'Organizer':
#             return Event.objects.filter(organizer=self.request.user)
#         # Attendees should not access this view
#         return Event.objects.none()

#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def register(self, request, pk=None):
#         """Register the authenticated user for the event if there's capacity."""
#         event = self.get_object()  # Get the event instance
#         user = request.user

#         # Check if the user is an attendee
#         if user.role != 'Attendee':  
#             return Response({'detail': 'Only attendees can register for this event.'}, status=status.HTTP_403_FORBIDDEN)

#         # Check if the user is already registered
#         if Registration.objects.filter(event=event, user=user).exists():
#             return Response({'detail': 'You are already registered for this event.'}, status=status.HTTP_400_BAD_REQUEST)

#         # Check if the event has capacity
#         registered_count = Registration.objects.filter(event=event).count()
#         if registered_count >= event.capacity:
#             return Response({'detail': 'This event is full.'}, status=status.HTTP_400_BAD_REQUEST)

#         # Register the user for the event
#         registration = Registration.objects.create(event=event, user=user)
#         send_event_registration_email.delay(user.email, event.title)

#         return Response({'detail': 'Successfully registered for the event.'}, status=status.HTTP_201_CREATED)

#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def check_in(self, request, pk=None):
#         """Check in the authenticated user if they are registered."""
#         event = self.get_object()
#         user = request.user

#         registration = get_object_or_404(Registration, event=event, user=user)
#         if registration.checked_in:
#             return Response({'detail': 'You are already checked in.'}, status=status.HTTP_400_BAD_REQUEST)

#         registration.checked_in = True
#         registration.save()
#         return Response({'detail': 'Successfully checked in.'}, status=status.HTTP_200_OK)

#     @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
#     def cancel_registration(self, request, pk=None):
#         """Cancel registration if the event is in the future."""
#         event = self.get_object()

#         if event.start_time <= now():
#             return Response({'error': 'You can only cancel registration for future events.'},
#                             status=status.HTTP_400_BAD_REQUEST)

#         user = request.user
#         try:
#             registration = Registration.objects.get(event=event, user=user)
#         except Registration.DoesNotExist:
#             return Response({'error': 'You are not registered for this event.'}, status=status.HTTP_404_NOT_FOUND)

#         registration.delete()
#         return Response({'message': 'Registration canceled successfully.'}, status=status.HTTP_200_OK)


# class AvailableEventsView(APIView):
#     permission_classes = [AllowAny]  # Allow any user to view available events

#     def get(self, request):
#         available_events = Event.objects.filter(capacity__gt=0)  # List events that are not full
#         serializer = EventSerializer(available_events, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)


# # Organizer-specific endpoints
# class OrganizerEventViewSet(viewsets.ModelViewSet):
#     queryset = Event.objects.all()
#     serializer_class = EventSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         # Only organizers can see their own events
#         return Event.objects.filter(organizer=self.request.user)

#     def create(self, request, *args, **kwargs):
#         if request.user.role != 'Organizer':
#             return Response({'detail': 'Only organizers can create events.'}, status=status.HTTP_403_FORBIDDEN)
#         return super().create(request, *args, **kwargs)

#     def update(self, request, *args, **kwargs):
#         if request.user.role != 'Organizer':
#             return Response({'detail': 'Only organizers can update events.'}, status=status.HTTP_403_FORBIDDEN)
#         return super().update(request, *args, **kwargs)

#     def destroy(self, request, *args, **kwargs):
#         if request.user.role != 'Organizer':
#             return Response({'detail': 'Only organizers can delete events.'}, status=status.HTTP_403_FORBIDDEN)
#         return super().destroy(request, *args, **kwargs)
