"""
Sample script to add tags to a misp instance
"""
import requests


def add_tag(tag_name: str, tag_color: str, base_url: str, auth_key: str):
    """
    add_tag - calls the REST API endpoint to add a tag to a MISP instance

    _extended_summary_

    Arguments:
        tag_name -- name of the tag
        tag_color -- color of the tag (hex, eg: '#DAA520')
        base_url -- base url for the misp instance
        auth_key -- MISP authorization key
    """
    url = base_url + "/tags/add"
    body = {"name": tag_name, "colour": tag_color, "exportable": "false"}
    headers = {"Authorization": auth_key, "Accept": "application/json"}
    response = requests.post(url, json=body, headers=headers, verify=False)
    response.raise_for_status()
    print(response.text)


if __name__ == "__main__":
    auth_key = "-=INSERT MISP API KEY HERE=-"
    base_url = "https://localhost"

    tags = {
        "AWS": "#FF9900",
        "SSM": "#FF9900",
        "OrgConfig": "#FF9900",
        "CloudTrail": "#FF9900",
        "Waf": "#FFE135",
        "VPC": "#FF9900",
        "LoadBalancer": "#FFE135",
        "Google": "#4285F4",
        "GSuite": "#4285F4",
        "Okta": "#00297A",
        "Slack": "#36C5F0",
    }
    for tag, color in tags.items():
        add_tag(tag, color, base_url, auth_key)
