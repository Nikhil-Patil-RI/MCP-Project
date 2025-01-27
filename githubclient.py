import anthropic
import os
import dotenv

import json
from tools.github import (
    clone_repository,
    get_authorization_url,
    exchange_code_for_token,
    get_user_repositories,
    get_user_details,
    system_message
)

dotenv.load_dotenv()

# Initialize the Anthropics client
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Tools configuration
tools = [
    {
        "name": "get_authorization_url",
        "description": "Call the associate function to return URL To user",
        "input_schema": {
            "type": "object",
            "properties": {
                
            },
            "required": []
        }

    },

    {
        "name": "exchange_code_for_token",
        "description": "Exchange authorization code for access token and store it securely in MongoDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The authorization code provided by GitHub after user authorization."
                }
            },
            "required": ["code"]
        }
    },
    {
        "name": "get_user_repositories",
        "description": "Fetch the repositories of the authenticated user.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "The username of GitHub to find the token in the database and get info using the token."
                }
            },
            "required": ["username"]
        }
    },
    {
        "name": "get_user_profile",
        "description": "Fetch the authenticated user's GitHub profile.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "The username of GitHub to find the token in the database and get info using the token."
                }
            },
            "required": ["username"]
        }
    },

    {
    "name": "clone_repository",
    "description": "Clone a GitHub repository by its name for the authenticated user.",
    "input_schema": {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "description": "The GitHub username of the authenticated user."
                        },
            "repo_name": {
                "type": "string",
                "description": "The name of the repository to be cloned."
            }
        },
        "required": ["username","repo_name"]
    },
}

]

# Define a function to handle tool calls based on Claude's response
def process_tool_call(tool_name, tool_input):
    if tool_name == "get_authorization_url":
        return get_authorization_url()
    elif tool_name == "exchange_code_for_token":
        return exchange_code_for_token(tool_input["code"])
    elif tool_name == "get_user_repositories":
        return get_user_repositories(tool_input["username"])
    elif tool_name == "get_user_profile":
        return get_user_details(tool_input["username"])
    elif tool_name == 'clone_repository':
        return clone_repository(tool_input["username"],tool_input["repo_name"])



# messages =[{"role": "user", "content": "Give me profile details of username Nikhil-Patil-RI"}]
# # Set up the interaction with Claude
# response = client.messages.create(
#     model="claude-3-5-sonnet-20241022",
#     max_tokens=1024,
#     messages= messages,
#     tools=tools
# )

# # print(response)

# # Update messages to include Claude's response
# messages.append(
#     {"role": "assistant", "content": response.content}
# )

# #If Claude stops because it wants to use a tool:
# if response.stop_reason == "tool_use":
#     tool_use = response.content[-1] #Naive approach assumes only 1 tool is called at a time
#     tool_name = tool_use.name
#     tool_input = tool_use.input
#     print("Claude wants to use the {tool_name} tool")
#     print(f"Tool Input:")
#     print(json.dumps(tool_input, indent=2))

#     #Actually run the underlying tool functionality on our db
#     tool_result = process_tool_call(tool_name, tool_input)

#     print(f"\nTool Result:")
#     print(json.dumps(tool_result, indent=2))

#     #Add our tool_result message:
#     messages.append(
#         {
#             "role": "user",
#             "content": [
#                 {
#                     "type": "tool_result",
#                     "tool_use_id": tool_use.id,
#                     "content": str(tool_result),
#                 }
#             ],
#         },
#     )
# else: 
#     #If Claude does NOT want to use a tool, just print out the text reponse
#     print("\nTechNova Support:" + f"{response.content[0].text}" )


# print(messages)


# response2 = client.messages.create(
#     model="claude-3-5-sonnet-20241022",
#     max_tokens=4096,
#     tools=tools,
#     messages=messages
# )

# print(response2)



def simple_chat():
    user_message = input("\nUser: ")
    messages = [{"role": "user", "content": user_message}]
    while True:
        #If the last message is from the assistant, get another input from the user
        if messages[-1].get("role") == "assistant":
            user_message = input("\nUser: ")
            messages.append({"role": "user", "content": user_message})

        #Send a request to Claude
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            system=system_message,
            max_tokens=4096,
            tools=tools,
            messages=messages
        )
        # Update messages to include Claude's response
        messages.append(
            {"role": "assistant", "content": response.content}
        )

        #If Claude stops because it wants to use a tool:
        if response.stop_reason == "tool_use":
            tool_use = response.content[-1] #Naive approach assumes only 1 tool is called at a time
            tool_name = tool_use.name
            tool_input = tool_use.input
            print(f"======Claude wants to use the {tool_name} tool======")

            #Actually run the underlying tool functionality on our db
            tool_result = process_tool_call(tool_name, tool_input)

            #Add our tool_result message:
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use.id,
                            "content": str(tool_result),
                        }
                    ],
                },
            )
        else: 
            #If Claude does NOT want to use a tool, just print out the text reponse
            print("\nRapid-Ops Support: " + f"{response.content[0].text}" )

# Start the chat!!
simple_chat()

