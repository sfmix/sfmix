from django import forms

from .models import Pledge

OTHER = ""


class PledgeForm(forms.ModelForm):
    item_slug = forms.ChoiceField(label="What can you give?", required=False)
    # Honeypot: hidden from people, filled by naive bots.
    website = forms.CharField(required=False, widget=forms.TextInput(attrs={"tabindex": "-1", "autocomplete": "off"}))

    class Meta:
        model = Pledge
        fields = ["item_slug", "quantity", "details", "name", "organization", "email",
                  "is_member", "show_as_donor", "credit_as", "url"]
        labels = {
            "quantity": "How many?",
            "details": "Details",
            "name": "Your name",
            "organization": "Organization (optional)",
            "email": "Email",
            "is_member": "I'm giving on behalf of a network connected to SFMIX (a member)",
            "show_as_donor": "List me on the donor wall",
            "credit_as": "Credit as (optional)",
            "url": "Link (optional)",
        }
        widgets = {
            "details": forms.Textarea(attrs={"rows": 3, "placeholder": "Part numbers, sizes, condition, when it could ship…"}),
            "quantity": forms.NumberInput(attrs={"min": 1, "max": 999}),
            "credit_as": forms.TextInput(attrs={"placeholder": "Defaults to your organization, else your name"}),
            "url": forms.URLInput(attrs={"placeholder": "https://"}),
        }

    def __init__(self, *args, wishlist=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.titles = {w["slug"]: w["title"] for w in wishlist}
        self.fields["item_slug"].choices = [
            (w["slug"], f"{w['title']} — {w['remaining']} wanted") for w in wishlist
        ] + [(OTHER, "Something else (tell us below)")]
        self.fields["quantity"].min_value = 1

    def clean(self):
        data = super().clean()
        if data.get("website"):
            raise forms.ValidationError("Something went wrong; please email us instead.")
        if not data.get("item_slug") and not (data.get("details") or "").strip():
            self.add_error("details", "Tell us what you'd like to give.")
        return data

    def save(self, commit=True):
        p = super().save(commit=False)
        p.item_title = self.titles.get(p.item_slug, "")
        if commit:
            p.save()
        return p
