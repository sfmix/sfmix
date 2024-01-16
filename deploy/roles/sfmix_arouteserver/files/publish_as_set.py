#!/usr/bin/env python3
import json
import os
import sys

import requests

"""
Publish an as-set to the ARIN IRR
"""

API_ENDPOINT = "https://reg.arin.net/rest/irr/as-set"
RPSL_HEADERS = {"Content-Type": "application/rpsl", "Accept": "application/rpsl"}


def read_input(file_name):
    """Reads content from a file or standard input."""
    try:
        if file_name:
            with open(file_name, "r") as file:
                return file.read()
        else:
            print("Reading from standard input. Please enter your data:")
            return sys.stdin.read()
    except Exception as e:
        sys.exit(f"Error reading input: {e}")


def post_data(arin_api_key, org_id, rpsl_text):
    """Makes a POST request to create a new object."""
    try:
        response = requests.post(
            API_ENDPOINT,
            headers=RPSL_HEADERS,
            params={"apikey": arin_api_key, "orgHandle": org_id},
            json=rpsl_text,
        )
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"POST request failed: {e}")
        return None


def put_data(arin_api_key, as_set_name, rpsl_text):
    """Makes a PUT request to update an existing object."""
    try:
        response = requests.put(
            API_ENDPOINT + f"/{as_set_name}",
            params={"apikey": arin_api_key},
            headers=RPSL_HEADERS,
            json=rpsl_text,
        )
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"PUT request failed: {e}")
        return None


def extract_as_set_name(rpsl_text):
    """
    Extracts the as-set name from an RPSL as-set object.

    Args:
    rpsl_text (str): The RPSL as-set object in textual form.

    Returns:
    str: The extracted as-set name, or an empty string if not found.
    """
    for line in rpsl_text.splitlines():
        if line.startswith("as-set:"):
            return line.split()[1].strip()
    raise Exception("as-set name not found in input")


def main():
    if len(sys.argv) < 3:
        sys.exit(f"Usage: publish_as_set.py <Input File (optional)>")

    arin_api_key = os.environ.get("ARIN_API_KEY")
    if not arin_api_key:
        sys.exit("The required environment variable ARIN_API_KEY wasn't found")

    org_id = os.environ.get("ARIN_ORG_HANDLE")
    if not org_id:
        sys.exit("The required environment variable ARIN_ORG_HANDLE wasn't found")

    input_file = sys.argv[1] if len(sys.argv) > 1 else None

    rpsl_text = read_input(input_file)
    try:
        rpsl_text = json.loads(rpsl_text)
    except json.JSONDecodeError:
        sys.exit("Invalid input format. Please provide valid JSON.")
    as_set_name = extract_as_set_name(rpsl_text)

    print("Attempting to create a new object...")
    post_response = post_data(arin_api_key, org_id, rpsl_text)

    if post_response:
        print(f"Object created successfully: {post_response.json()}")
    else:
        print("Attempting to update an existing object...")
        put_response = put_data(arin_api_key, as_set_name, rpsl_text)

        if put_response:
            print(f"Object updated successfully: {put_response.json()}")
        else:
            print("Error: Unable to create or update the object.")


if __name__ == "__main__":
    main()
