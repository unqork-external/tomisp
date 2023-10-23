"""
Sample script for adding AWS WAF data to a MISP instance
"""

from tomisp import MISPHelper
from tomisp.vendor.aws import from_waf

if __name__ == "__main__":
    helper = MISPHelper()

    sample_data = [
        {
            "timestamp": 1697514746303,
            "formatVersion": 1,
            "webaclId": "arn:aws:wafv2:us-east-2:A0000000001:regional/webacl/FMManagedWebACLV2-Company-WAF-Policy1-1659540252938/4ae234eb-eb5b-429c-b25b-c20101be4d68",
            "terminatingRuleId": "PREFMManaged-Company_RuleGroupA-1689976399534",
            "terminatingRuleType": "GROUP",
            "action": "BLOCK",
            "terminatingRuleMatchDetails": [
                {
                    "conditionType": "REGEX",
                    "location": "HEADER",
                    "matchedData": None,
                    "matchedFieldName": "host",
                }
            ],
            "httpSourceName": "ALB",
            "httpSourceId": "A0000000001-app/environment-A1-88ab6a04d8/4e83fa0e7336783c",
            "ruleGroupList": [
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG1/05713998-9870-4a4f-b735-986932d9ee9c",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG2/efc49321-73e2-4c11-87b2-8855333c83e3",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG3/d677f323-a1cf-4b54-aa72-35a2892db802",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG4/b5f891ef-f731-4aeb-a4e1-250e31f40358",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RuleGroupA/1c008e49-c2b1-4296-a217-a2d129d7bf26",
                    "terminatingRule": {
                        "ruleId": "redirect-ip-direct",
                        "action": "BLOCK",
                        "ruleMatchDetails": None,
                    },
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
            ],
            "rateBasedRuleList": [],
            "nonTerminatingMatchingRules": [],
            "requestHeadersInserted": None,
            "responseCodeSent": 302,
            "httpRequest": {
                "clientIp": "192.51.100.10",
                "country": "GB",
                "headers": [
                    {"name": "Host", "value": "203.0.113.20"},
                    {"name": "Connection", "value": "keep-alive"},
                    {"name": "Accept-Encoding", "value": "gzip, deflate"},
                    {"name": "Accept", "value": "*/*"},
                    {
                        "name": "User-agent",
                        "value": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
                    },
                ],
                "uri": "/.env",
                "args": "",
                "httpVersion": "HTTP/1.1",
                "httpMethod": "GET",
                "requestId": "1-652e04fa-0c19aa5514b4523309e56b37",
                "host": "203.0.113.20",
                "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
            },
            "ja3Fingerprint": "834d18406c1a0ec51303dda2eb4ca4fe",
            "terminatingRuleName": "Company_RuleGroupA",
            "terminating_rule_group": "Company_RuleGroupA",
            "terminating_rule_name": "redirect-ip-direct",
        },
        {
            "timestamp": 1693944207584,
            "formatVersion": 1,
            "webaclId": "arn:aws:wafv2:us-east-2:A00000000003:regional/webacl/environment-B1/383ba078-c042-413f-ba6c-fd136c964eda",
            "terminatingRuleId": "Default_Action",
            "terminatingRuleType": "REGULAR",
            "action": "ALLOW",
            "terminatingRuleMatchDetails": [],
            "httpSourceName": "ALB",
            "httpSourceId": "A00000000003-app/app-16A-RF9QOKIDTYN3/608bcde250caf73f",
            "ruleGroupList": [
                {
                    "ruleGroupId": "AWS#AWSManagedRulesKnownBadInputsRuleSet",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesAmazonIpReputationList",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesLinuxRuleSet",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
            ],
            "rateBasedRuleList": [
                {
                    "rateBasedRuleId": "arn:aws:wafv2:us-east-2:A00000000003_MANAGED:regional/ipset/383ba078-c042-413f-ba6c-fd136c964eda_5681507a-3445-471e-b257-f570dd6a0a93_IPV4/5681507a-3445-471e-b257-f570dd6a0a93",
                    "rateBasedRuleName": "http-flood",
                    "limitKey": "IP",
                    "maxRateAllowed": 2000,
                    "limitValue": "198.51.100.20",
                }
            ],
            "nonTerminatingMatchingRules": [],
            "requestHeadersInserted": None,
            "responseCodeSent": None,
            "httpRequest": {
                "clientIp": "198.51.100.20",
                "country": "FR",
                "headers": [
                    {"name": "Host", "value": "203.0.113.42"},
                    {"name": "Content-Length", "value": "20"},
                    {"name": "Accept-Encoding", "value": "gzip, deflate"},
                    {"name": "Accept", "value": "*/*"},
                    {
                        "name": "User-agent",
                        "value": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
                    },
                    {"name": "Connection", "value": "keep-alive"},
                    {
                        "name": "Content-Type",
                        "value": "application/x-www-form-urlencoded",
                    },
                ],
                "uri": "/",
                "args": "",
                "httpVersion": "HTTP/1.1",
                "httpMethod": "POST",
                "requestId": "1-64f7898f-68e842a1268aa59c4c9722b2",
                "host": "203.0.113.42",
                "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
            },
            "requestBodySize": 20,
            "requestBodySizeInspectedByWAF": 20,
            "terminatingRuleName": "Unknown",
        },
        {
            "timestamp": 1697515066678,
            "formatVersion": 1,
            "webaclId": "arn:aws:wafv2:us-east-2:A00000000005:regional/webacl/FMManagedWebACLV2-Company-WAF-Policy1-1666117775248/31948d5f-ff73-463d-900f-87d97f697766",
            "terminatingRuleId": "Default_Action",
            "terminatingRuleType": "REGULAR",
            "action": "ALLOW",
            "terminatingRuleMatchDetails": [],
            "httpSourceName": "ALB",
            "httpSourceId": "A00000000005-app/environment-A2-7ea6fc9de1/481617825b77b79e",
            "ruleGroupList": [
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG1/05713998-9870-4a4f-b735-986932d9ee9c",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG2/efc49321-73e2-4c11-87b2-8855333c83e3",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG3/d677f323-a1cf-4b54-aa72-35a2892db802",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG4/b5f891ef-f731-4aeb-a4e1-250e31f40358",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [
                        {
                            "ruleId": "http-flood",
                            "action": "COUNT",
                            "ruleMatchDetails": [],
                        }
                    ],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RuleGroupA/1c008e49-c2b1-4296-a217-a2d129d7bf26",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG5/4a11f6b5-8925-4f2e-bad5-fe9dda34aedc",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "arn:aws:wafv2:us-east-2:A0000000002:regional/rulegroup/Company_RG_Verification/8112832d-1fbf-4fd8-826f-f854c5c8ad66",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesAmazonIpReputationList",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesAnonymousIpList",
                    "terminatingRule": {
                        "ruleId": "HostingProviderIPList",
                        "action": "BLOCK",
                        "ruleMatchDetails": None,
                    },
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesLinuxRuleSet",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
                {
                    "ruleGroupId": "AWS#AWSManagedRulesKnownBadInputsRuleSet",
                    "terminatingRule": None,
                    "nonTerminatingMatchingRules": [],
                    "excludedRules": None,
                    "customerConfig": None,
                },
            ],
            "rateBasedRuleList": [],
            "nonTerminatingMatchingRules": [
                {
                    "ruleId": "PREFMManaged-AWSManagedRulesAnonymousIpList-1689976367496",
                    "action": "COUNT",
                    "ruleMatchDetails": [],
                }
            ],
            "requestHeadersInserted": None,
            "responseCodeSent": None,
            "httpRequest": {
                "clientIp": "198.51.100.30",
                "country": "US",
                "headers": [
                    {"name": "Host", "value": "securesite.company.com"},
                    {
                        "name": "Authorization",
                        "value": "Bearer ABCDEFG",
                    },
                ],
                "uri": "/foo/bar/baz",
                "args": "",
                "httpVersion": "HTTP/1.1",
                "httpMethod": "GET",
                "requestId": "1-652e063a-0cf69e937c7235b80ad0dfaf",
                "host": "securesite.company.com",
            },
            "ja3Fingerprint": "46fa2ae08ea000a48fd867de8cbdf8aa",
            "labels": [
                {"name": "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList"}
            ],
            "terminatingRuleName": "Unknown",
            "terminating_rule_group": "Unknown",
            "terminating_rule_name": "HostingProviderIPList",
        },
    ]

    event = MISPHelper.create_event("Sample AWS WAF Event")

    for sdata in sample_data:
        from_waf(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
