#!./bin/python3

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title commands
# @raycast.mode silent



# Optional parameters:
# @raycast.icon 🤖
# @raycast.argument1 { "type": "text", "placeholder": "command (e.g. fang, defang, upper, lower)"}

# raycast modes: silent, inline, fullOutput

import pyperclip
import sys
from datetime import datetime
import pytz
import dateutil.parser
import base64
import urllib.parse

# Define the timezones
MOUNTAIN_TZ = pytz.timezone('US/Mountain')
UTC_TZ = pytz.utc

# Define the tzinfos dictionary
tzinfos = {
    'MT': MOUNTAIN_TZ,
    'UTC': UTC_TZ
}

# add decorators
valid_commands = {}
shortcuts = {}

def command(shortcut=None):
    """Decorator to mark a function as a valid command."""
    def decorator(func):
        valid_commands[func.__name__] = func
        if shortcut:
            shortcuts[shortcut] = func.__name__
            valid_commands[shortcut] = func
        return func
    return decorator

@command(shortcut='d')
def defang(url):
    """
    changing https://example.com/malicious/link to hxxps[://]example[.]com/malicious/link
    """


    url = url.replace("http", "hxxp")
    url = url.replace("://", "[://]")
    url = url.replace(".", "[.]")

    return url

@command(shortcut='f')
def fang(url):
    """
    changing hxxps[://]example[.]com/malicious/link to https://example.com/malicious/link
    """


    url = url.replace("hxxp", "http")
    url = url.replace("[://]", "://")
    url = url.replace("[.]", ".")

    return url

@command(shortcut='l')
def lower(string):
    """
    changes whatever is copied to lowercase
    """


    string = string.lower()

    return string

@command(shortcut='u')
def upper(string):
    """
    changes whatever is copied to uppercase
    """


    string = string.upper()

    return string

@command(shortcut='utc')
def to_utc(timestamp, fmt=None):
    """Converts a given timestamp in Mountain Time to UTC.

    Args:
        timestamp (str): The input timestamp in Mountain Time with or without 'MT'.
        fmt (str, optional): The format of the input timestamp. If None, it tries to auto-detect.

    Returns:
        str: The converted timestamp in the format "Year-month-day hour:minute:second UTC".
    """
    if timestamp.endswith(' MT'):
        timestamp = timestamp[:-3]

    if fmt:
        local_time = datetime.strptime(timestamp, fmt)
        local_time = MOUNTAIN_TZ.localize(local_time)
    else:
        local_time = dateutil.parser.parse(timestamp, tzinfos=tzinfos)

    # Ensure the time is in Mountain Time before conversion
    if local_time.tzinfo is None:
        local_time = MOUNTAIN_TZ.localize(local_time)

    utc_time = local_time.astimezone(UTC_TZ)
    return utc_time.strftime('%Y-%m-%d %H:%M:%S UTC')

@command(shortcut='mdt')
def to_mountain_time(timestamp, fmt=None):
    """Converts a given timestamp in UTC to Mountain Time.

    Args:
        timestamp (str): The input timestamp in UTC with or without 'UTC'.
        fmt (str, optional): The format of the input timestamp. If None, it tries to auto-detect.

    Returns:
        str: The converted timestamp in the format "Year-month-day hour:minute:second MT".
    """
    if timestamp.endswith(' UTC'):
        timestamp = timestamp[:-4]

    if fmt:
        utc_time = datetime.strptime(timestamp, fmt)
        utc_time = UTC_TZ.localize(utc_time)
    else:
        utc_time = dateutil.parser.parse(timestamp, tzinfos=tzinfos)

    # Ensure the time is in UTC before conversion
    if utc_time.tzinfo is None:
        utc_time = UTC_TZ.localize(utc_time)

    mountain_time = utc_time.astimezone(MOUNTAIN_TZ)
    return mountain_time.strftime('%Y-%m-%d %H:%M:%S MT')

@command(shortcut='be')
def encode_base64(data: str) -> str:
    """
    Encodes the given string to Base64.

    Args:
        data (str): The string to be encoded.

    Returns:
        str: The Base64 encoded string.
    """
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

@command(shortcut='bd')
def decode_base64(encoded_data: str) -> str:
    """
    Decodes the given Base64 encoded string.

    Args:
        encoded_data (str): The Base64 encoded string.

    Returns:
        str: The decoded string.
    """
    # Add padding if necessary
    encoded_data += '=' * ((4 - len(encoded_data) % 4) % 4)
    try:
        return base64.b64decode(encoded_data.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError:
        # If UTF-8 decoding fails, return the raw bytes
        return base64.b64decode(encoded_data).decode('latin-1')

@command(shortcut='ue')
def encode_url(url):
    """
    URL encodes the given URL
    """

    return urllib.parse.quote(url)

@command(shortcut='ud')
def decode_url(url):
    """
    Decodes the given URL
    """
    return urllib.parse.unquote(url)

@command(shortcut='ei')
def encode_indicator(text):
    """
    Performs specific encoding for an indicator
    """

    text = encode_url(text)
    text = text.replace("%20", "+")
    return text

@command(shortcut='di')
def decode_indicator(text):
    """
    Performs specific decoding for an indicator
    """

    text = decode_url(text)
    text = text.replace("+", " ")

    return text

@command(shortcut="vtu")
def virustotal_url(url):
    """
    Returns the VirusTotal report for the given URL.
    """
    import credentials
    import requests

    body = {
        "url": url
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": credentials.VTapikey
    }

    response = requests.post("https://www.virustotal.com/api/v3/urls", json=body, headers=headers)
    if response.status_code != 200:
        return f"{response.status_code} Error checking URL in VT"

    url = response.json()["data"]["links"]["self"]

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "Error getting URL Analysis from VT"

    stats = response.json()["data"]["attributes"]["stats"]
    return f"""malicious: {stats["malicious"]},
suspicious: {stats["suspicious"]},
harmless: {stats["harmless"]},
undetected: {stats["undetected"]},
timeout: {stats["timeout"]}"""

@command(shortcut='vti')
def virustotal_ip(ip):
    """
    Returns the VirusTotal report for the given IP.
    """
    import credentials
    import requests

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": credentials.VTapikey
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"{response.status_code} Error checking IP in VT"

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return f"""malicious: {stats["malicious"]},
suspicious: {stats["suspicious"]},
harmless: {stats["harmless"]},
undetected: {stats["undetected"]},
timeout: {stats["timeout"]}"""

@command(shortcut='ipi')
def ipinfo_ip(ip):
    """
    Returns the IPInfo report for the given IP.
    """
    import requests
    url = f"https://ipinfo.io/widget/demo/{ip}"

    headers = {
        "content-type": "application/json"
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"{response.status_code} Error checking IP in IPInfo"
    data = response.json()["data"]
    return f"""ip: {data["ip"]},
city: {data["city"]},
region: {data["region"]},
country: {data["country"]},
loc: {data["loc"]},
org: {data["org"]}
company: {data["company"]}
privacy: {data["privacy"]}
asn: {data["asn"]}
"""

@command(shortcut='rw')
def remove_whitespace(text):
    """
    changing "    TEXT " to "TEXT"
    """

    return text.replace(" ", "").replace("\n\n", "\n")


@command(shortcut='cl')
def comma_list(text):
    """
    changing
    "TEXT
    TEXT
    TEXT" to
    "TEXT,TEXT,TEXT"
    """
    # Replace newlines with commas
    modified_text = text.replace('\n', ',')

    # Update the clipboard with the modified text
    return modified_text

@command(shortcut='ucl')
def uncomma_list(text):
    """
    changing
    "TEXT,TEXT,TEXT" to
    "TEXT
    TEXT
    TEXT"""

    return remove_whitespace(text).replace(",", "\n")

@command(shortcut='who')
def whois(domain):
    """
    Returns the whois information for the given domain.
    """
    import whois

    domain = "bookstoreresults.com"
    try:
        domain_info = whois.whois(domain)
    except Exception as e:
        return f"Error getting whois information for {domain}: {e}"

    return domain_info


@command(shortcut='h')
def help(parameter=None):
    """
    Returns a list of valid commands.
    """

    return "Valid commands/shortcuts are: " + ", ".join(valid_commands.keys()) + "."

def main():
    command = sys.argv[1].strip()
    clipboard = pyperclip.paste().strip()
    if command in valid_commands:
        clipboard = valid_commands[command](clipboard)
    else:
        clipboard = f"Invalid command: {command}"
    pyperclip.copy(clipboard)

if __name__ == "__main__":
    main()