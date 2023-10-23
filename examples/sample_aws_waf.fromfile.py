"""
Sample script for adding AWS WAF data to a MISP instance
"""
import json
import os.path

from tomisp import MISPHelper
from tomisp.vendor.aws import from_waf

if __name__ == "__main__":
    helper = MISPHelper()

    sample_data = []
    local_file = os.path.join(os.path.dirname(__file__), "sample_aws_waf.json")
    with open(local_file, "r") as f_in:
        sample_data = json.load(f_in)

    event = MISPHelper.create_event("Simulated Attack from AWS WAF Events")

    for sdata in sample_data:
        from_waf(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
