import os
import sys
import requests
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from pymongo import MongoClient
from typing import Optional
from mcp.server.fastmcp import FastMCP
import git
# Load environment variables
load_dotenv(".env")

# MCP Server Initialization
mcp = FastMCP("github_oauth")

system_message = """

You are Rapid-Ops support Bot, a GitHub integration assistant. Your role is to assist users with secure GitHub authentication and data retrieval. Follow these guidelines:

Authentication Flow:
-When user need to authorize with github then immediately use get_authorization_url else show other options
-After getting the URL, ALWAYS display it in this format: "GitHub Authorization URL: [EXACT_URL_HERE]"
-Never proceed without explicitly showing the full URL

**User Interaction**  
- Identify authentication needs before operations.  
- Offer authorization help to new users.  
- Verify token status for returning users.  

**Capabilities**  
- Generate GitHub OAuth URLs.  
- Exchange codes for access tokens.  
- Fetch user profiles and repository listings.  
- Manage token storage securely.   

**Error Handling**  
- Provide actionable feedback.  
- Explain errors and resolution steps clearly.  
- Maintain a helpful, concise tone.  

Start by assessing user needs, then guide them step-by-step from authentication to data retrieval.

"""

# GitHub API Endpoints
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

# Environment Variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
MASTER_KEY = os.getenv("MASTER_KEY")  # Load the key from .env

# Check if the MASTER_KEY exists in .env
if not MASTER_KEY:
    print("Error: MASTER_KEY is not set in the .env file!")
    sys.exit(1)  # Exit if the key is missing

master_key = MASTER_KEY.encode()
master_cipher = Fernet(master_key)

# MongoDB Setup
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

def store_encrypted_token(username: str, github_token: str):
    """Encrypt and store GitHub access token in the database."""
    encrypted_token = master_cipher.encrypt(github_token.encode())
    collection.update_one(
        {"username": username},
        {"$set": {"encrypted_token": encrypted_token.decode()}},
        upsert=True
    )

def fetch_decrypted_token(username: str) -> Optional[str]:
    """Fetch and decrypt the GitHub access token from the database."""
    record = collection.find_one({"username": username})
    if record and "encrypted_token" in record:
        encrypted_token = record["encrypted_token"].encode()
        return master_cipher.decrypt(encrypted_token).decode()
    return None

def delete_token(username: str):
    """Delete the stored access token for a user."""
    collection.update_one({"username": username}, {"$unset": {"encrypted_token": ""}})

@mcp.tool()
def get_authorization_url() -> str:
    """Generate GitHub authorization URL."""
    return (
        f"{GITHUB_AUTH_URL}?client_id={CLIENT_ID}&scope=repo%20read:org"
    )

@mcp.tool()
def exchange_code_for_token(code: str) -> str:
    """Exchange authorization code for access token and store it securely in MongoDB."""
    url = GITHUB_TOKEN_URL
    headers = {"Accept": "application/json"}
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
    }

    # Exchange the code for an access token
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return "Failed to exchange code for an access token. Please try again."

    token_data = response.json()
    access_token = token_data.get("access_token")
    token_type = token_data.get("token_type")

    if not access_token:
        return "No access token returned. Please check your credentials."

    # Fetch the username using the access token
    user_data_response = requests.get(
        f"{GITHUB_API_URL}/user",
        headers={"Authorization": f"{token_type} {access_token}"},
    )
    if user_data_response.status_code != 200:
        return "Failed to fetch user details. Please reauthorize."

    user_data = user_data_response.json()
    username = user_data.get("login")

    if not username:
        return "Unable to retrieve username. Please try again."

    # Store the token in the database
    store_encrypted_token(username, access_token)
    return f"Authorization successful! Token saved for user '{username}'."

@mcp.tool()
def get_user_details(username: str) -> str:
    """Fetch GitHub user details."""
    access_token = fetch_decrypted_token(username)

    if not access_token:
        return "No access token found. Please reauthorize."

    response = requests.get(
        f"{GITHUB_API_URL}/user",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    if response.status_code == 401:
        delete_token(username)
        return "Access token is invalid or expired. Please reauthorize."

    if response.status_code == 200:
        user_data = response.json()
        return (
            f"Username: {user_data.get('login')}, Name: {user_data.get('name')}, "
            f"Email: {user_data.get('email')}, Public Repos: {user_data.get('public_repos')}"
        )

    return "Failed to fetch user details."

@mcp.tool()
def get_user_repositories(username: str) -> str:
    """Fetch the repositories of the authenticated user."""
    access_token = fetch_decrypted_token(username)

    if not access_token:
        return "No access token found. Please reauthorize."

    response = requests.get(
        f"{GITHUB_API_URL}/user/repos",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    if response.status_code == 401:
        delete_token(username)
        return "Access token is invalid or expired. Please reauthorize."

    if response.status_code == 200:
        repos = response.json()
        return "\n".join(repo["name"] for repo in repos)

    return "Failed to fetch repositories."

@mcp.tool()
def clone_repository(username: str, repo_name: str) -> str:
    """Clone a GitHub repository by its name for the authenticated user."""
    access_token = fetch_decrypted_token(username)

    if not access_token:
        return "No access token found. Please reauthorize."


    clone_dir = f"./{repo_name}"  # Local directory to clone into

    try:
        # Set up authentication with access token
        auth_repo_url = f"https://{username}:{access_token}@github.com/{username}/{repo_name}.git"
        
        # Clone the repository
        git.Repo.clone_from(auth_repo_url, clone_dir)
        return f"Repository '{repo_name}' has been successfully cloned to {clone_dir}."
    except git.exc.GitCommandError as e:
        return f"Failed to clone repository: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
