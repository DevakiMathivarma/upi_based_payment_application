# core/forms.py
from django import forms
from django.contrib.auth import get_user_model
import phonenumbers
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

User = get_user_model()


def normalize_phone(raw_phone, default_region='IN'):
    """Return E.164 phone string or raise forms.ValidationError."""
    raw = (raw_phone or "").strip()
    if not raw:
        raise ValidationError(_("Phone number is required."))
    try:
        parsed = phonenumbers.parse(raw, default_region)
        if not phonenumbers.is_valid_number(parsed):
            raise ValidationError(_("Enter a valid phone number."))
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        raise ValidationError(_("Enter a valid phone number."))


class RegistrationForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        required=True,
        label=_("Username"),
        widget=forms.TextInput(attrs={"placeholder": "Choose a username"})
    )
    email = forms.EmailField(
        required=True,
        label=_("Email"),
        widget=forms.EmailInput(attrs={"placeholder": "you@example.com"})
    )
    phone = forms.CharField(
        max_length=32,
        required=True,
        label=_("Phone number"),
        widget=forms.TextInput(attrs={"placeholder": "+91 98765 43210"})
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if not username:
            raise forms.ValidationError(_("Username is required."))
        qs = User.objects.filter(username__iexact=username)
        if qs.exists():
            # Allow reuse if same phone will be used — view will handle that logic.
            raise forms.ValidationError(_("This username is already taken."))
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(_("This email is already registered."))
        return email

    def clean_phone(self):
        raw = self.cleaned_data.get('phone', '').strip()
        phone_e164 = normalize_phone(raw)
        existing = User.objects.filter(phone_number=phone_e164).first()
        if existing and getattr(existing, 'is_phone_verified', False):
            raise forms.ValidationError(_("Phone number already registered. Please login."))
        return phone_e164


class LoginOTPForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        required=True,
        label=_("Username"),
        widget=forms.TextInput(attrs={"placeholder": "Your username"})
    )
    otp = forms.CharField(
        max_length=10,
        required=True,
        label=_("OTP"),
        widget=forms.TextInput(attrs={"placeholder": "6-digit code"})
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if not User.objects.filter(username=username).exists():
            raise forms.ValidationError(_("Invalid username."))
        return username

    def clean_otp(self):
        otp = self.cleaned_data.get('otp', '').strip()
        if not otp.isdigit():
            raise forms.ValidationError(_("OTP must contain only numbers."))
        if len(otp) < 4:
            raise forms.ValidationError(_("Enter a valid OTP."))
        return otp


class ResendOTPForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        required=False,
        label=_("Username"),
        widget=forms.TextInput(attrs={"placeholder": "Your username (or leave blank to use phone)"})
    )
    phone = forms.CharField(
        max_length=32,
        required=False,
        label=_("Phone number"),
        widget=forms.TextInput(attrs={"placeholder": "+91 98765 43210"})
    )

    def clean(self):
        cleaned = super().clean()
        username = (cleaned.get('username') or '').strip()
        phone = (cleaned.get('phone') or '').strip()

        if not username and not phone:
            raise forms.ValidationError(_("Provide either username or phone to resend OTP."))

        user = None
        if username:
            user = User.objects.filter(username=username).first()
            if not user:
                raise forms.ValidationError(_("No user found with that username."))
            cleaned['user'] = user
            return cleaned

        # phone provided
        phone_e164 = normalize_phone(phone)
        user = User.objects.filter(phone_number=phone_e164).first()
        if not user:
            raise forms.ValidationError(_("No user found with that phone number."))
        cleaned['user'] = user
        cleaned['phone'] = phone_e164
        return cleaned
