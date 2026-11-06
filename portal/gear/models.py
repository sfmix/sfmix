"""Hardware pledges from the peering-gear wishlist.

A pledge is an offer, not a donation: admins follow up by email, and once the
part is installed it's recorded in NetBox (`donor` / `donated_on` on the module
or device), which is what the donations ledger reads. Opted-in pledges show on
the donor wall once an admin confirms them.
"""

from django.db import models


class Pledge(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        CONFIRMED = "confirmed", "Confirmed"
        RECEIVED = "received", "Received"
        DECLINED = "declined", "Declined"

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # What: a wishlist slug (analysis.wishlist) or blank for "something else".
    item_slug = models.CharField(max_length=80, blank=True)
    item_title = models.CharField(max_length=200, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    details = models.TextField(blank=True)

    # Who
    name = models.CharField(max_length=120)
    organization = models.CharField(max_length=160, blank=True)
    email = models.EmailField()
    # 501(c)(12): >=85% of income must come from members (networks connected to SFMIX).
    is_member = models.BooleanField(default=False)
    show_as_donor = models.BooleanField(default=True)
    credit_as = models.CharField(max_length=160, blank=True)
    url = models.URLField(blank=True)

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    submitted_by = models.CharField(max_length=254, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.display_name}: {self.quantity}× {self.item_title or 'other'}"

    @property
    def display_name(self) -> str:
        return self.credit_as or self.organization or self.name

    @property
    def is_open(self) -> bool:
        return self.status in (self.Status.NEW, self.Status.CONFIRMED)
