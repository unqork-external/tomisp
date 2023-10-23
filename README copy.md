# ToMisp

A module for helping with some of the heavy lifting when adding data into MISP. These classes and functions provide a uniform way to create objects in a MISP event, thus allowing better analysis inside MISP. By default it will deduplicate objects and relationships created so that the same object will NOT be created more than once in a given MISP event. The uniqueness of the object are based on the supplied required parameters of each object.

Bugs, Feature Requests, and Pull requests are welcome.

## MISPHelper ([misphelper.py](tomisp/misphelper.py))

The primary interface is the MISPHelper class. This class encapsulates connecting to and interacting with the MISP instance via pymisp. The class takes a ```misp_url``` and ```misp_api_key``` as keyword parameters, but these can also be specified via environment variables ```MISP_URL``` and ```MISP_API_KEY``` respectively.

Most of the functions in the MISPHelper class however are NOT instance methods, but static class methods. See the ```examples``` folder for examples.

## Generated ([generated.py](tomisp/generated.py))

These are a automatically generated functions for the creation of all available MISP Objects based on the misp-object repo definitions.

## Vendor ([vendor](tomisp/vendor/))

These are vendor specific functions for turning a vendor log item into a set of MISP objects in a MISP Event.

### AWS ([aws.py](tomisp/vendor/aws.py))

Functions for turning various AWS Logs into MISP Objects/Events. Currently supported/implemented:

* from_load_balancer - for loading AWS LoadBlancer logs (must be parsed)
* from_vpc - for loading AWS VPC logs
* from_waf - for loading AWS WAFv2 logs
* from_cloudtrail - for loading AWS CloudTrail logs
* from_orgconfig - for loading AWS OrgConfig logs
* from_ssm - for loading AWS SSM Logs

### GOOGLE ([google.py](tomisp/vendor/google.py))

Functions for turning various Google Logs (GSuite specifically) into MISP Objects/Events.

### OKTA ([okta.py](tomisp/vendor/okta.py))

Functions for turning Okta logs into MISP Objects/Events.

### SLACK ([slack.py](tomisp/vendor/slack.py))

Functions for turning Slack audit logs into MISP Objects/Events.
