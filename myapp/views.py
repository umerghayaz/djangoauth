import importlib
from urllib.parse import urlparse

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import SignupForm, LoginForm

from django.contrib import messages
from django.contrib.auth import login
from django.http import HttpRequest, HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods

from django_google_sso import conf
from django_google_sso.main import GoogleAuth, UserHelper

# Create your views here.
# Home page
def index(request):
    return render(request, 'index.html')

# signup page
def user_signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

# login page
def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            admin_url = reverse("home")
            google = GoogleAuth(request)
            code = request.GET.get("code")
            state = request.GET.get("state")

            # Check if Google SSO is enabled
            if not conf.GOOGLE_SSO_ENABLED:
                messages.add_message(request, messages.ERROR, _("Google SSO not enabled."))
                return HttpResponseRedirect(admin_url)

            # First, check for authorization code
            if not code:
                messages.add_message(
                    request, messages.ERROR, _("Authorization Code not received from SSO.")
                )
                return HttpResponseRedirect(admin_url)

            # Then, check state.
            request_state = request.session.get("sso_state")
            next_url = reverse("home")

            if not request_state or state != request_state:
                messages.add_message(
                    request, messages.ERROR, _("State Mismatch. Time expired?")
                )
                return HttpResponseRedirect(admin_url)

            # Get Access Token from Google
            try:
                google.flow.fetch_token(code=code)
            except Exception as error:
                messages.add_message(request, messages.ERROR, str(error))
                return HttpResponseRedirect(admin_url)

            # Get User Info from Google
            user_helper = UserHelper(google.get_user_info(), request)

            # Check if User Info is valid to login
            if not user_helper.email_is_valid:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(
                        f"Email address not allowed: {user_helper.user_email}. "
                        f"Please contact your administrator."
                    ),
                )
                return HttpResponseRedirect(admin_url)

            # Get or Create User
            if conf.GOOGLE_SSO_AUTO_CREATE_USERS:
                user = user_helper.get_or_create_user()
            else:
                user = user_helper.find_user()

            if not user or not user.is_active:
                return HttpResponseRedirect(admin_url)

            # Run Pre-Login Callback
            module_path = ".".join(conf.GOOGLE_SSO_PRE_LOGIN_CALLBACK.split(".")[:-1])
            pre_login_fn = conf.GOOGLE_SSO_PRE_LOGIN_CALLBACK.split(".")[-1]
            module = importlib.import_module(module_path)
            getattr(module, pre_login_fn)(user, request)

            # Login User
            login(request, user, conf.GOOGLE_SSO_AUTHENTICATION_BACKEND)
            request.session.set_expiry(conf.GOOGLE_SSO_SESSION_COOKIE_AGE)

            return HttpResponseRedirect(next_url or admin_url)
            #
            # if user:
            #     login(request, user)
            #     return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

# logout page
def user_logout(request):
    logout(request)
    return redirect('login')