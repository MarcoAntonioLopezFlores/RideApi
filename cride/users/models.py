"""User model"""
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

from cride.utils.models import RideModel

class User(RideModel, AbstractUser):
    """User model.
    Extend from Django's Abstract User, change the username field
    to email and add some extra fields.
    """

    email = models.EmailField(
        ("email address"),
        unique=True,
        error_messages={
            'unique':'A user with that email already exists.'
        }
    )

    phone_regex = RegexValidator(
        regex=r'\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: +99999999."
    )
    phone_number = models.CharField(
        validators=[phone_regex],
        max_length=17,
        blank=True
    )

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['username','first_name','last_name']

    is_client = models.BooleanField(
        'client status',
        default=True,
        help_text={
            'Helps easily distinguish users and perform queries.'
            'Clients are the main type of user'
        }
    )

    is_verified = models.BooleanField(
        'verified',
        default=False,
        help_text={
            'Helps to identificate if the user is verified'
        }
    )

    def __str__(self):
        return self.username

    def get_short_name(self):
        return self.username


    
