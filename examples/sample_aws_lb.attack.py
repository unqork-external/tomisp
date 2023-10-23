"""
Sample script to add parsed AWS LoadBalancer logs to a MISP instance
"""

import os
from datetime import datetime
from random import choice
from urllib.parse import urlparse

import sample_helper

from tomisp import MISPHelper
from tomisp.vendor.aws import from_load_balancer


def generate_lb_log_item(
    elb: str,
    client_ipport: str,
    target_ipport: str,
    status_code: str,
    http_method: str,
    url: str,
    user_agent: str,
) -> dict:
    """
    generate_lb_log_item - generates a sample AWS Load Balancer log dictionary

    Arguments:
        elb -- name of the ElasticLoadBalancer
        client_ipport -- client ip address and port (':' separated)
        target_ipport -- target ip address and port (':' separated)
        status_code -- HTTP status code
        http_method -- HTTP method
        url -- target URL
        user_agent -- User Agent
    """
    u = urlparse(url)
    dt_now = datetime.utcnow().isoformat() + "Z"
    return {
        "type": "https",
        "time": dt_now,
        "elb": elb,
        "client": client_ipport,
        "target": target_ipport,
        "request_processing_time": "0.019",
        "target_processing_time": "0.022",
        "response_processing_time": "0.000",
        "elb_status_code": status_code,
        "target_status_code": status_code,
        "recieved_bytes": "155",
        "sent_bytes": "616",
        "request": f"{http_method} {url} HTTP/1.1",
        "user_agent": user_agent,
        "ssl_cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "ssl_protocol": "TLSv1.2",
        "target_group_arn": f"arn:aws:elasticloadbalancing:us-east-2:blah:targetgroup/{elb}",
        "trace_id": "Root=1-650ae967-515acdd1120e634926a09a7b",
        "domain_name": u.hostname,
        "chosen_cert_arn": "arn:aws:acm:us-east-2:blah:certificate/blah",
        "matched_rule_priority": "1",
        "request_creation_time": dt_now,
        "actions_executed": "waf,forward",
        "redirect_url": "-",
        "error_reason": "-",
        "target_port_list": target_ipport,
        "target_status_code_list": status_code,
        "classification": "-",
        "classification_reason": "-",
        "request_method": http_method,
        "request_httpversion": "HTTP/1.1",
    }


if __name__ == "__main__":
    auth_key = os.environ["MISP_API_KEY"]
    base_url = os.environ["MISP_URL"]
    # As an example, we specify the auth key and base url,
    # but the MISPHelper class will automatically pull these
    # from these environment variables

    helper = MISPHelper(misp_url=base_url, misp_api_key=auth_key)

    elb_name = "foo/bar/baz"
    target = sample_helper.generate_ip_and_port()
    base_url = "https://example.com:443/"
    sample_lb_data = []
    for i in range(100):
        sample_lb_data.append(
            generate_lb_log_item(
                elb=elb_name,
                client_ipport=sample_helper.generate_ip_and_port(),
                target_ipport=target,
                status_code="200",
                http_method=choice(["GET", "GET", "POST", "PUT", "GET", "GET"]),
                url=base_url + sample_helper.generate_random_uri_path(),
                user_agent=sample_helper.generate_random_ua(),
            )
        )

    event = MISPHelper.create_event("Simulated Scan AWS LB Event")

    for data_item in sample_lb_data:
        from_load_balancer(data_item, event)

    misp_id = helper.save_new_event(event, sample_lb_data)
    print(misp_id)
