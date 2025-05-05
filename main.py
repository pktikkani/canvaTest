from fasthtml.common import *
import os
import secrets
import base64
import hashlib
import requests
import json
from urllib.parse import urlencode, quote_plus

# Your Canva Connect API credentials
# These should be stored in environment variables in a production environment
CANVA_CLIENT_ID = os.getenv("CANVA_CLIENT_ID")  # Replace with your client ID
CANVA_CLIENT_SECRET = os.getenv("CANVA_CLIENT_SECRET")  # Replace with your client secret
REDIRECT_URI = "https://canvatest-production.up.railway.app/oauth/redirect"
CANVA_AUTH_URL = "https://www.canva.com/api/oauth/authorize"
CANVA_TOKEN_URL = "https://api.canva.com/rest/v1/oauth/token"

# Request scopes
SCOPES = [
    "brandtemplate:content:read",
    "brandtemplate:meta:read",
    "design:content:read",
    "design:content:write",
    "design:meta:read",
    "profile:read"
]

# Session storage (in-memory for demo only)
# In a production app, you would use a proper session management system
sessions = {}

# Header components
hdrs = (
    Meta(name="viewport", content="width=device-width, initial-scale=1.0"),
    Link(rel="stylesheet", href="/static/styles.css", type="text/css"),
)

app, rt = fast_app(hdrs=hdrs, pico=False, live=True)

# Helper functions for OAuth PKCE flow
def generate_code_verifier():
    """Generate a random code verifier string for PKCE."""
    return secrets.token_urlsafe(96)[:128]

def generate_code_challenge(code_verifier):
    """Generate a code challenge from the code verifier using SHA-256."""
    code_challenge = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(code_challenge).decode().rstrip('=')

def generate_state():
    """Generate a random state string for CSRF protection."""
    return secrets.token_urlsafe(32)

# Routes
@rt("/")
def index(request):
    """Home page with Connect to Canva button."""
    if 'session_id' in request.cookies and request.cookies['session_id'] in sessions:
        session = sessions[request.cookies['session_id']]
        if 'access_token' in session:
            # User is authenticated, show the dashboard
            return dashboard(request)
    
    # User is not authenticated, show login page
    return Body(
        Main(cls="container")(
            H1("Canva Connect API Test"),
            Div(cls="card")(
                H2("Connect to Canva"),
                P("Click the button below to connect to your Canva account and test the integration."),
                A("Connect to Canva", href=auth, cls="btn")
            )
        )
    )

@rt
def auth(request):
    """Start the OAuth authentication flow."""
    # Generate PKCE code verifier and challenge
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_state()
    
    # Create session
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        'code_verifier': code_verifier,
        'state': state
    }
    
    # Create authorization URL
    auth_params = {
        'client_id': CANVA_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': ' '.join(SCOPES),
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 's256'
    }
    
    auth_url = f"{CANVA_AUTH_URL}?{urlencode(auth_params, quote_via=quote_plus)}"
    
    # Set session cookie and redirect to Canva auth URL
    response = RedirectResponse(url=auth_url)
    response.set_cookie('session_id', session_id, max_age=3600, httponly=True)
    return response

@rt("/oauth/redirect")
def oauth_redirect(request):
    """Handle OAuth redirect from Canva."""
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return Body(
            Main(cls="container")(
                Div(cls="alert alert-danger")(
                    "Invalid session. Please try again."
                ),
                A("Back to Home", href="/", cls="btn")
            )
        )
    
    session = sessions[session_id]
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    
    # Verify state to prevent CSRF
    if not state or state != session['state']:
        return Body(
            Main(cls="container")(
                Div(cls="alert alert-danger")(
                    "Invalid state parameter. Possible CSRF attack."
                ),
                A("Back to Home", href="/", cls="btn")
            )
        )
    
    if not code:
        return Body(
            Main(cls="container")(
                Div(cls="alert alert-danger")(
                    "Authorization failed. No code received from Canva."
                ),
                A("Back to Home", href="/", cls="btn")
            )
        )
    
    # Exchange code for access token
    try:
        # Prepare credentials for Basic Auth
        credentials = base64.b64encode(f"{CANVA_CLIENT_ID}:{CANVA_CLIENT_SECRET}".encode()).decode()
        
        # Prepare form data
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'code_verifier': session['code_verifier']
        }
        
        # Print debug info before the request
        print(f"Token URL: {CANVA_TOKEN_URL}")
        print(f"Client ID: {CANVA_CLIENT_ID}")
        print(f"Redirect URI: {REDIRECT_URI}")
        print(f"Code length: {len(code) if code else 'None'}")
        print(f"Code verifier length: {len(session['code_verifier']) if 'code_verifier' in session else 'None'}")
        
        # Make the token request
        token_response = requests.post(
            CANVA_TOKEN_URL,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {credentials}'
            },
            data=data
        )
        
        # Debug information
        print(f"Status code: {token_response.status_code}")
        print(f"Response content: {token_response.content}")
        
        # Check if the response is valid JSON
        try:
            token_data = token_response.json()
        except json.JSONDecodeError as json_error:
            return Body(
                Main(cls="container")(
                    Div(cls="alert alert-danger")(
                        f"Invalid response from token endpoint: Status {token_response.status_code}, Content: {token_response.content}"
                    ),
                    A("Back to Home", href="/", cls="btn")
                )
            )
        
        if 'access_token' not in token_data:
            return Body(
                Main(cls="container")(
                    Div(cls="alert alert-danger")(
                        f"Failed to get access token: {token_data.get('error_description', 'Unknown error')}"
                    ),
                    A("Back to Home", href="/", cls="btn")
                )
            )
        
        # Store tokens in session
        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token')
        session['expires_in'] = token_data.get('expires_in')
        
        # Redirect to dashboard
        return RedirectResponse(url="/dashboard")
    
    except Exception as e:
        return Body(
            Main(cls="container")(
                Div(cls="alert alert-danger")(
                    f"Error exchanging code for tokens: {str(e)}"
                ),
                A("Back to Home", href="/", cls="btn")
            )
        )

@rt("/dashboard")
def dashboard(request):
    """Show user dashboard after successful authentication."""
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return RedirectResponse(url="/")
    
    session = sessions[session_id]
    if 'access_token' not in session:
        return RedirectResponse(url="/")
    
    access_token = session['access_token']
    
    # Get user profile from Canva
    try:
        profile_response = requests.get(
            "https://api.canva.com/v1/users/me/profile",
            headers={'Authorization': f'Bearer {access_token}'}
        )
        profile = profile_response.json()
        user_name = profile.get('displayName', 'User')
    except Exception:
        user_name = "User"
    
    return Body(
        Main(cls="container")(
            H1(f"Welcome, {user_name}!"),
            Div(cls="alert alert-success")(
                "Successfully connected to Canva!"
            ),
            Div(cls="card")(
                H2("Create a Design"),
                P("Create a new design in Canva using the API."),
                Form(method="post", action=create_design)(
                    Div(cls="form-group")(
                        Label("Design Title"),
                        Input(type="text", name="title", required=True, cls="form-control")
                    ),
                    Button("Create Design", type="submit", cls="btn")
                )
            ),
            A("Logout", href=logout, cls="btn")
        )
    )

@rt
def create_design(request, title: str):
    """Create a new design in Canva."""
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return RedirectResponse(url="/")
    
    session = sessions[session_id]
    if 'access_token' not in session:
        return RedirectResponse(url="/")
    
    access_token = session['access_token']
    
    # Create design API call
    try:
        # Correct endpoint URL based on documentation
        design_response = requests.post(
            "https://api.canva.com/rest/v1/designs",
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            },
            json={
                'title': title,
                'design_type': {
                    'type': 'preset',
                    'name': 'presentation'  # Options: "doc", "whiteboard", "presentation"
                }
            }
        )
        
        # Debug information
        print(f"Design creation status: {design_response.status_code}")
        print(f"Design creation response: {design_response.content}")
        
        # Check if we got a valid response
        if design_response.status_code != 200:
            return Body(
                Main(cls="container")(
                    Div(cls="alert alert-danger")(
                        f"Failed to create design: Status {design_response.status_code}, Response: {design_response.content}"
                    ),
                    A("Back to Dashboard", href="/dashboard", cls="btn")
                )
            )
        
        # Try to parse JSON response
        try:
            design_data = design_response.json()
        except json.JSONDecodeError:
            return Body(
                Main(cls="container")(
                    Div(cls="alert alert-danger")(
                        f"Invalid response from Canva: {design_response.content}"
                    ),
                    A("Back to Dashboard", href="/dashboard", cls="btn")
                )
            )
        
        # Process response according to API documentation
        if 'design' in design_data:
            design = design_data['design']
            design_id = design['id']
            
            # Get the edit URL from the URLs object
            if 'urls' in design and 'edit_url' in design['urls']:
                design_url = design['urls']['edit_url']
            else:
                design_url = f"https://www.canva.com/design/{design_id}"
            
            return Body(
                Main(cls="container")(
                    H1("Design Created!"),
                    Div(cls="alert alert-success")(
                        f"Successfully created design: {title}"
                    ),
                    Div(cls="card")(
                        H2("Design Details"),
                        P(f"Design ID: {design_id}"),
                        A("Edit Design in Canva", href=design_url, target="_blank", cls="btn"),
                    ),
                    A("Back to Dashboard", href="/dashboard", cls="btn")
                )
            )
        else:
            error_message = design_data.get('error', {}).get('message', 'Unknown error')
            return Body(
                Main(cls="container")(
                    Div(cls="alert alert-danger")(
                        f"Failed to create design: {error_message}"
                    ),
                    A("Back to Dashboard", href="/dashboard", cls="btn")
                )
            )
    
    except Exception as e:
        return Body(
            Main(cls="container")(
                Div(cls="alert alert-danger")(
                    f"Error creating design: {str(e)}"
                ),
                A("Back to Dashboard", href="/dashboard", cls="btn")
            )
        )

@rt
def logout(request):
    """Log out user and clear session."""
    session_id = request.cookies.get('session_id')
    if session_id and session_id in sessions:
        del sessions[session_id]
    
    response = RedirectResponse(url="/")
    response.delete_cookie('session_id')
    return response

serve()