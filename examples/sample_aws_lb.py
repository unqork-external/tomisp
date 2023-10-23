"""
Sample script to add parsed AWS LoadBalancer logs to a MISP instance
"""
import os

from tomisp import MISPHelper
from tomisp.vendor.aws import from_load_balancer

if __name__ == "__main__":
    auth_key = os.environ["MISP_API_KEY"]
    base_url = os.environ["MISP_URL"]
    # As an example, we specify the auth key and base url,
    # but the MISPHelper class will automatically pull these
    # from these environment variables

    helper = MISPHelper(misp_url=base_url, misp_api_key=auth_key)

    sample_lb_data = {
        "type": "https",
        "time": "2023-09-20T12:45:27.251946Z",
        "elb": "app/blah/blah",
        "client": "1.2.3.4:36168",
        "target": "5.6.7.8:30312",
        "request_processing_time": "0.019",
        "target_processing_time": "0.022",
        "response_processing_time": "0.000",
        "elb_status_code": "200",
        "target_status_code": "200",
        "recieved_bytes": "155",
        "sent_bytes": "616",
        "request": "GET https://example.com:443/version HTTP/1.1",
        "user_agent": "python-requests/2.28.1",
        "ssl_cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "ssl_protocol": "TLSv1.2",
        "target_group_arn": "arn:aws:elasticloadbalancing:us-east-2:blah:targetgroup/blah/blah",
        "trace_id": "Root=1-650ae967-515acdd1120e634926a09a7b",
        "domain_name": "example.com",
        "chosen_cert_arn": "arn:aws:acm:us-east-2:blah:certificate/blah",
        "matched_rule_priority": "1",
        "request_creation_time": "2023-09-20T12:45:27.210000Z",
        "actions_executed": "waf,forward",
        "redirect_url": "-",
        "error_reason": "-",
        "target_port_list": "5.6.7.8:30312",
        "target_status_code_list": "200",
        "classification": "-",
        "classification_reason": "-",
        "datetime_fixed": "2023-09-20T12:45:27.251946Z",
        "request_method": "GET",
        "request_httpversion": "HTTP/1.1",
        "Account": "blah",
    }

    event = MISPHelper.create_event("Sample AWS LB Event")

    from_load_balancer(sample_lb_data, event)

    misp_id = helper.save_new_event(event, sample_lb_data)
    print(misp_id)
