from typing import Match
from django.db import models

from cride.utils.models import RideModel


class Circle(RideModel):


    name = models.CharField(
        'circle name',
        max_length=140
    )

    slug_name = models.SlugField(
        unique=True,
        max_length=40
    )

    about= models.CharField(
        'circle description',
        max_length= 255
    )

    picture = models.ImageField(
        upload_to = 'circles/pictures',
        blank=True
    )


    rides_taken = models.PositiveIntegerField(
        default=0
    )

    rides_offered =models.PositiveIntegerField(
        default=0
    )

    is_verified = models.BooleanField(
        'verified circle',
        default=False,
        help_text={
            'Helps to identificate if the circle is verified'
        }
    )

    is_public = models.BooleanField(
        default=True,
        help_text='Public circles are listed in the page so everyone know about ther existence'
    )

    is_limited = models.BooleanField(
        'limited',
        default=True,
        help_text='Limited circles can grow up to a fixed number of members'
    )

    members_limit=models.PositiveIntegerField(
        default=0,
        help_text='if circle is limited, this will be the limit on the number of members'
    )

    def __str__(self):
        return self.name

    class Meta(RideModel.META):
        ordering = ['-rides_taken', '-rides_offered']
    

