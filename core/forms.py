from django import forms


def html_date_input() -> forms.DateInput:
    """Return a date widget whose value is valid for every HTML date control."""
    return forms.DateInput(format="%Y-%m-%d", attrs={"type": "date"})


def html_time_input() -> forms.TimeInput:
    """Return a minute-precision widget whose value is valid for HTML time controls."""
    return forms.TimeInput(format="%H:%M", attrs={"type": "time"})
