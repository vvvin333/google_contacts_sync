# -*- coding: utf-8 -*-
import json
import os
import flask
import requests
from google.auth.exceptions import RefreshError

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build, Resource

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "conf/credentials_people_api.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ["https://www.googleapis.com/auth/contacts"]
API_SERVICE_NAME = "people"
API_RESOURCE_ME = API_SERVICE_NAME + "/me"
API_VERSION = "v1"

USER_CREDENTIALS_FILE = "conf/user_creds.json"

app = flask.Flask(__name__)
# some real App secret
app.secret_key = "bla-bla"


@app.route("/")
def index():
    return print_index_table()


@app.route("/test")
def test_api_request():
    # If we have no user credentials so far,
    # initiate authorization flow.
    # TODO: In a production app, you likely want to save these
    #  credentials in a persistent database instead.
    if not os.path.exists(USER_CREDENTIALS_FILE):
        return flask.redirect("authorize")

    # Load user credentials.
    credentials: Credentials = Credentials.from_authorized_user_file(
        USER_CREDENTIALS_FILE,
        SCOPES,
    )

    service: Resource = build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    try:
        # Call the People API
        results = service.people().connections().list(
            resourceName=API_RESOURCE_ME,
            personFields="names,emailAddresses"
        ).execute()
    except RefreshError:
        # TODO: Check if credentials expired and refresh them.
        return flask.redirect("revoke")

    return flask.jsonify(**results)


@app.route("/authorize")
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a "redirect_uri_mismatch"
    # error.
    flow.redirect_uri = flask.url_for("oauth2callback", _external=True)

    authorization_url, state = flow.authorization_url(
        # TODO: Enable offline access so that you can refresh an access token without
        #  re-prompting the user for permission. Recommended for web server apps.
        access_type="offline",
        # Force the user to re-prompt permission.
        prompt="consent",
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes="true",
    )

    # Store the state so the callback can verify the auth server response.
    flask.session["state"] = state

    return flask.redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # be verified in the authorization server response.
    state = flask.session["state"]

    # Set flow with app (client) secret credentials
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )
    flow.redirect_uri = flask.url_for("oauth2callback", _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials.
    # TODO: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    creds_dict = credentials_to_dict(credentials)

    with open(USER_CREDENTIALS_FILE, "w") as creds_file:
        json.dump(creds_dict, creds_file)

    return "Authorization successful." + print_index_table()


@app.route("/revoke")
def revoke():
    # TODO: In a production app, you likely want to save these
    #  credentials in a persistent database instead.
    if not os.path.exists(USER_CREDENTIALS_FILE):
        return ("You need to <a href='/authorize'>authorize</a> before " +
                "testing the code to revoke credentials.")

    credentials: Credentials = Credentials.from_authorized_user_file(
        USER_CREDENTIALS_FILE, SCOPES
    )

    revoke_response = requests.post(
        "https://oauth2.googleapis.com/revoke",
        params={"token": credentials.token},
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    clear_credentials()

    status_code = getattr(revoke_response, "status_code")
    if status_code == 200:
        return "Credentials successfully revoked." + print_index_table()
    else:
        return "An error occurred." + print_index_table()


def print_index_table():
    return (
        "<table>" +
        "<tr><td><a href='/test'>Test an API request</a></td>" +
        "<td>Submit an API request and see a formatted JSON response. " +
        "    Go through the authorization flow if there are no stored " +
        "    credentials for the user.</td></tr>" +
        "<tr><td><a href='/authorize'>Test the auth flow directly</a></td>" +
        "<td>Go directly to the authorization flow.</td></tr>" +
        "<tr><td><a href='/revoke'>Revoke current credentials</a></td>" +
        "<td>Revoke the access token associated with the current user. " +
        "    Clear the access token currently stored. " +
        "    After revoking credentials, you need to reauthorize." +
        "</td></tr></table>"
    )


def clear_credentials():
    # TODO: In a production app, you likely want to save these
    #  credentials in a persistent database instead.
    if os.path.exists(USER_CREDENTIALS_FILE):
        os.remove(USER_CREDENTIALS_FILE)


def credentials_to_dict(credentials: Credentials) -> dict[str, str]:
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
        "expiry": credentials.expiry.isoformat(),
    }


if __name__ == "__main__":
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run("localhost", 8080, debug=True)
