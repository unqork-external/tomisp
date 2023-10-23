"""
ToMISP - MISPHelper
"""
import base64
import email.utils
import hashlib
import json
import logging
import os
from typing import Any
from typing import List

import pymisp

from .common import MissingArgumentException

_log = logging.getLogger(__name__)

_asn_lookup_func = None
# the ASN lookup function should take a single input parameter of an IP address
# and return a dictionary containing at minimum the following keys:
# * 'ASN'
# * 'country'
# * 'owner'

global _cache
_cache = {}


class MISPHelper:
    """
    MISPHelper - common helper functions for creating MISP objects
    """

    def __init__(self, **kwargs) -> None:
        # Setup MISP connection info

        if "misp_url" in kwargs:
            url = kwargs.get("misp_url")
        elif "MISP_URL" in os.environ:
            url = os.environ["MISP_URL"]
        else:
            url = None

        if "misp_api_key" in kwargs:
            apikey = kwargs.get("misp_api_key")
        elif "MISP_API_KEY" in os.environ:
            apikey = os.environ["MISP_API_KEY"]
        else:
            apikey = None

        if "ssl_verify" in kwargs:
            ssl_verify = bool(kwargs.get("ssl_verify"))
        else:
            ssl_verify = False

        if apikey and url:
            self.user_misp = pymisp.PyMISP(
                url, apikey, ssl_verify, False, tool="MISPHelper"
            )
        else:
            raise MissingArgumentException(
                requires=["misp_url", "misp_api_key"], supplied=kwargs
            )

    def save_new_event(self, event: pymisp.MISPEvent, alert: dict) -> str:
        """
        SaveNewEvent - Saves a new MISP event to the MISP Server

        Arguments:
            event -- MISP event
            alert -- alert data

        Returns:
            the MISP ID of the newly created event
        """
        MISPHelper.add_json_attachment(event, alert, "raw_data.json")
        if "AlertResponseURL" in alert:
            event.add_attribute(
                category="Support Tool",
                type="link",
                value=alert["AlertResponseURL"],
                disable_correlation=True,
            )
        saved_event = self.user_misp.add_event(event)
        self.user_misp.publish(event, alert=False)
        return saved_event.get("Event", {}).get("id")

    def get_event(self, misp_id: int, convert: bool = False) -> pymisp.MISPEvent:
        """
        GetEvent - retrieves a MISP event from the MISP Server

        Arguments:
            misp_id -- MISP ID

        Keyword Arguments:
            convert -- convert from dictionary to python object (default: {False})

        Returns:
            a MISP Event object (or dictionary)
        """
        try:
            event = self.user_misp.get_event(misp_id, pythonify=convert)
        except pymisp.MISPServerError:
            pass

        if isinstance(event, pymisp.MISPEvent):
            return event
        else:
            _log.warning(
                "MISP Event not returned",
                {"Requeted MispID": misp_id, "Response": event},
            )
            return None

    @staticmethod
    def create_event(info) -> pymisp.MISPEvent:
        """
        create_event - creates a MISP event

        _extended_summary_

        Arguments:
            info -- the "description" of the MISP event

        Returns:
            a pymisp.MISPEvent (or None if an error has occured)
        """
        try:
            event = pymisp.MISPEvent()
            # event.analysis = 0
            event.threat_level_id = 2
            event.info = info
            event.distribution = 0
            return event
        except Exception as e:
            _log.error(f"Failed to create MISP event - {e}")
            return None

    @staticmethod
    def _create_obj(event, misp_obj_type: str) -> pymisp.MISPObject:
        """
        Internal common function for creating a new MISP object
        """
        return event.add_object(name=misp_obj_type, strict=True)

    @staticmethod
    def _create_obj_cached(
        event, misp_obj_type: str, tuple_str: str
    ) -> pymisp.MISPObject:
        """
        Internal common function for using a cached MISP object, or create new
        """
        if tuple_str in _cache:
            return _cache[tuple_str], False
        else:
            obj = MISPHelper._create_obj(event, misp_obj_type)
            _cache[tuple_str] = obj
            return obj, True

    @staticmethod
    def _add_obj_attribute(
        misp_obj, relation: str, value: str, disable_correlation: bool = False
    ):
        """
        Internal common function for adding arbitrary attribute to MISP object
        """
        if value:
            # TODO - check if attribute already exists??
            misp_obj.add_attribute(
                object_relation=relation,
                value=value,
                disable_correlation=disable_correlation,
            )

    @staticmethod
    def tag_attributes(misp_object: pymisp.MISPObject, tags: List[str]):
        """
        tag_attributes - adds tags to attributes of a misp object

        Arguments:
            misp_object -- the misp object
            tags -- list of tags to add to the attributes
        """
        for attr in misp_object.Attribute:
            for tag in tags:
                attr.add_tag(tag)

    @staticmethod
    def create_relationship(
        obj1: pymisp.MISPObject, relationship: str, obj2: pymisp.MISPObject
    ):
        """
        create_relationship - creates a relationship between two MISP objects

        Arguments:
            obj1 -- the first MISP object
            relationship -- the relationship
            obj2 -- the second MISP object
        """
        relationship_tuple = obj1.uuid + "|" + relationship + "|" + obj2.uuid
        if relationship_tuple not in _cache:
            obj1.add_reference(obj2.uuid, relationship)
            _cache[relationship_tuple] = True

    @staticmethod
    def add_json_attachment(event: pymisp.MISPEvent, data: Any, filename: str):
        """
        add_json_attachment - adds data as a JSON file as an attachment to a MISP event

        Arguments:
            event -- MISP Event
            data -- data to add
            filename -- name of the file
        """
        event.add_attribute(
            category="Support Tool",
            type="attachment",
            value=filename,
            data=base64.b64encode(json.dumps(data).encode("utf-8")),
            disable_correlation=True,
        )

    @staticmethod
    def create_asn_obj(
        event: pymisp.MISPEvent, asn: str, country: str = None, owner: str = None
    ) -> pymisp.MISPObject:
        """
        create_asn_obj - creates a new MISP ASN object

        Arguments:
            event -- MISP Event
            asn -- ASN Number/Name

        Keyword Arguments:
            country -- ASN Country (default: {None})
            owner -- ASN Owner Name (default: {None})

        Returns:
            MISPObject representing an 'asn'
        """
        ans_tuple = str(asn) + "|asn"
        obj, isNew = MISPHelper._create_obj_cached(event, "asn", ans_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "asn", asn)
            MISPHelper._add_obj_attribute(obj, "description", owner)
            MISPHelper._add_obj_attribute(obj, "country", country)
        return obj

    @staticmethod
    def create_ip_obj(
        event: pymisp.MISPEvent,
        myip: str,
        isDst: bool = False,
        port=None,
        isDstPort: bool = False,
    ) -> pymisp.MISPObject:
        """
        create_ip_obj - creates a new MISP IP Object

        Arguments:
            event -- MISP Event
            myip -- IP Address

        Keyword Arguments:
            isDst -- is a Destination IP? (default: {False})
            port -- TCP Port (default: {None})
            isDstPort -- is a Destination Port? (default: {False})

        Returns:
            MISP Object representing an 'network-connection'
        """
        ip_relation = "ip-dst" if isDst else "ip-src"
        port_relation = "dst-port" if isDstPort else "src-port"
        iptuple = (
            str(myip) + ":" + str(port) + "|network-connection"
            if port
            else str(myip) + "|network-connection"
        )

        ip_obj, isNew = MISPHelper._create_obj_cached(
            event, "network-connection", iptuple
        )
        if isNew:
            MISPHelper._add_obj_attribute(ip_obj, ip_relation, myip)
            MISPHelper._add_obj_attribute(ip_obj, port_relation, port)

        if _asn_lookup_func and callable(_asn_lookup_func):
            try:
                asn = _asn_lookup_func(myip)
            except Exception:
                # Couldn't talk to ASN service...just keep going
                asn = None

            asn_obj = (
                MISPHelper.create_asn_obj(
                    event, asn["ASN"], asn["country"], asn["owner"]
                )
                if asn and asn["ASN"] != "0"
                else None
            )

            if ip_obj and asn_obj:
                MISPHelper.create_relationship(ip_obj, myip, "belongs-to", asn_obj, asn)

        return ip_obj

    @staticmethod
    def create_user_obj(
        event: pymisp.MISPEvent,
        username: str,
        displayname: str = None,
        account_type: str = None,
    ) -> pymisp.MISPObject:
        """
        create_user_obj - creates a MISP object representing a User

        Arguments:
            event -- MISP Event
            username -- username of user

        Keyword Arguments:
            displayname -- display name of the user (default: {None})
            account_type -- type of account (default: {None})

        Returns:
            a MISP object representing an 'user-account'
        """
        if not username or (username == "N/A"):
            user_tuple = str(displayname) + "|user-account"
        else:
            user_tuple = str(username) + "|user-account"
        user_obj, isNew = MISPHelper._create_obj_cached(
            event, "user-account", user_tuple
        )
        if isNew:
            MISPHelper._add_obj_attribute(user_obj, "account-type", account_type, True)
            MISPHelper._add_obj_attribute(user_obj, "display-name", displayname)
            MISPHelper._add_obj_attribute(user_obj, "username", username)
        return user_obj

    @staticmethod
    def create_annotation_obj(
        event: pymisp.MISPEvent, ann_type: str, ann_value: str
    ) -> pymisp.MISPObject:
        """
        create_annotation_obj - creates a MISP Annotation Object

        Arguments:
            event -- MISP Event
            ann_type -- type of annotation
            ann_value -- value of annotation

        Returns:
            a MISP object representing an 'annotation'
        """
        ann_tuple = str(ann_value) + "|" + str(ann_type)
        obj, isNew = MISPHelper._create_obj_cached(event, "annotation", ann_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "text", ann_value)
            MISPHelper._add_obj_attribute(obj, "type", ann_type, True)
        return obj

    @staticmethod
    def create_outcome_obj(event: pymisp.MISPEvent, mytype: str, outcome: str):
        """
        create_outcome_obj - creates a MISP annotation object representing an Outcome
        """
        return MISPHelper.create_annotation_obj(event, mytype, outcome)

    @staticmethod
    def create_useragent_obj(
        event: pymisp.MISPEvent, useragent: str
    ) -> pymisp.MISPObject:
        """
        create_useragent_obj - creates a MISP annotation object representing an UserAgent
        """
        return MISPHelper.create_annotation_obj(event, "User-Agent", useragent)

    @staticmethod
    def create_software_obj(
        event: pymisp.MISPEvent, software_name: str, software_version: str = None
    ) -> pymisp.MISPObject:
        """
        create_software_obj - creates a MISP object representing a peice of software

        Arguments:
            event -- MISP Event
            software_name -- name of the software

        Keyword Arguments:
            software_version -- version of the software (default: {None})

        Returns:
            a MISP Object representing 'software'
        """
        software_tuple = software_name + "|" + str(software_version) + "|software"
        obj, isNew = MISPHelper._create_obj_cached(event, "software", software_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "name", software_name)
            MISPHelper._add_obj_attribute(obj, "version", software_name)
        return obj
        # return MISPHelper.create_annotation_obj(event, "software", mysoftware)

    @staticmethod
    def create_querystring_obj(
        event: pymisp.MISPEvent, querystring: str
    ) -> pymisp.MISPObject:
        return MISPHelper.create_annotation_obj(event, "querystring", querystring)

    def create_tor_node_obj(
        event: pymisp.MISPEvent,
        raw_document: dict,
        address: str,
        fingerprint: str = None,
        version: str = None,
        published=None,
    ) -> pymisp.MISPObject:
        """
        create_tor_node_obj - creates a MISP object representing a tor-node


        Arguments:
            event -- the MISP event
            raw_document -- the raw full document
            address -- the ip address
            fingerprint -- fingerprint
            version -- version
            published -- published date

        Returns:
            a MISP object
        """
        obj_tuple = str(raw_document) + "|tornode"
        obj, isNew = MISPHelper._create_obj_cached(event, "tor-node", obj_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "document", raw_document)
            MISPHelper._add_obj_attribute(obj, "address", address)
            MISPHelper._add_obj_attribute(obj, "fingerprint", fingerprint)
            MISPHelper._add_obj_attribute(obj, "published", published)
            MISPHelper._add_obj_attribute(obj, "version", version)
        return obj

    @staticmethod
    def create_ddos_obj(
        event: pymisp.MISPEvent,
        target_protocol: str,
        target_domain: str,
        target_port: str = None,
        target_ip: str = None,
        src_ip: str = None,
        src_port: str = None,
        text: str = None,
    ) -> pymisp.MISPObject:
        obj_tuple = (
            target_protocol
            + "|"
            + target_domain
            + "|"
            + target_port
            + "|"
            + target_ip
            + "|"
            + src_ip
            + "|"
            + src_port
            + "|ddos"
        )
        obj, isNew = MISPHelper._create_obj_cached(event, "ddos", obj_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "domain-dst", target_domain)
            MISPHelper._add_obj_attribute(obj, "dst-port", target_port)
            MISPHelper._add_obj_attribute(obj, "ip-dst", target_ip)
            MISPHelper._add_obj_attribute(obj, "protocol", target_protocol)
            MISPHelper._add_obj_attribute(obj, "ip-src", src_ip)
            MISPHelper._add_obj_attribute(obj, "src-port", src_port)
            MISPHelper._add_obj_attribute(obj, "text", text)
        return obj

    @staticmethod
    def create_device_obj(
        event: pymisp.MISPEvent,
        mydevice: str,
        mac_address: str = None,
        os: str = None,
        description: str = None,
        device_type: str = None,
        status: str = None,
        version: str = None,
    ) -> pymisp.MISPObject:
        """
        create_device_obj - creates a MISP object representing a device

        Arguments:
            event -- MISP Event
            mydevice -- device name

        Keyword Arguments:
            mac_address -- MAC Address of device (default: {None})
            os -- OS of device (default: {None})
            description -- description of the device (default: {None})
            device_type -- type of device (default: {None})
            status -- status of device (default: {None})
            version -- version of the device (default: {None})

        Returns:
            a MISP object representing a 'device'
        """
        device_tuple = str(mydevice) + "|device"
        obj, isNew = MISPHelper._create_obj_cached(event, "device", device_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "name", mydevice)
            MISPHelper._add_obj_attribute(obj, "MAC-address", mac_address)
            MISPHelper._add_obj_attribute(obj, "OS", os)
            MISPHelper._add_obj_attribute(obj, "description", description)
            MISPHelper._add_obj_attribute(obj, "device-type", device_type)
            MISPHelper._add_obj_attribute(obj, "status", status)
            MISPHelper._add_obj_attribute(obj, "version", version)
        return obj

    @staticmethod
    def create_http_obj(
        event: pymisp.MISPEvent,
        url: str,
        user_agent: str = None,
        referer: str = None,
        method: str = None,
        host: str = None,
        headers: list = [],
        content_type: str = None,
    ) -> pymisp.MISPObject:
        """
        create_http_obj - creates a MISP object representing an HTTP request

        Arguments:
            event -- MISP Event
            url -- URL of the request

        Keyword Arguments:
            user_agent -- User-Agent of the request (default: {None})
            referer -- HTTP Refer of the request (default: {None})
            method -- HTTP method (default: {None})
            host -- Hostname against which this request was performed (default: {None})
            headers -- HTTP Headers (default: {[]})
            content_type -- HTTP Content-Type (default: {None})

        Returns:
            a MISP object representing an 'http-request'
        """
        http_tuple = str(url) + "|http-request"
        obj, isNew = MISPHelper._create_obj_cached(event, "http-request", http_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "uri", url)
            MISPHelper._add_obj_attribute(obj, "content-type", content_type)
            for header in headers:
                MISPHelper._add_obj_attribute(obj, "header", header)
            MISPHelper._add_obj_attribute(obj, "host", host)
            MISPHelper._add_obj_attribute(obj, "method", method)
            MISPHelper._add_obj_attribute(obj, "referer", referer)
            MISPHelper._add_obj_attribute(obj, "user-agent", user_agent)
        return obj

    @staticmethod
    def create_url_obj(
        event: pymisp.MISPEvent,
        url: str,
        host: str = None,
        port: str = None,
        scheme: str = None,
        query_string: str = None,
        tld: str = None,
    ) -> pymisp.MISPObject:
        """
        create_url_obj - creates a MISP object representing an URL

        Arguments:
            event -- MISP Event
            url -- url

        Keyword Arguments:
            host -- the host portion of the url (default: {None})
            port -- the port of the url (default: {None})
            scheme -- the HTTP scheme of the url (default: {None})
            query_string -- the query string of the URL (default: {None})
            tld -- the TLD of the URL (default: {None})

        Returns:
            _description_
        """
        url_tuple = str(url) + "|url"
        obj, isNew = MISPHelper._create_obj_cached(event, "url", url_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "url", url)
            MISPHelper._add_obj_attribute(obj, "host", host)
            MISPHelper._add_obj_attribute(obj, "port", port)
            MISPHelper._add_obj_attribute(obj, "scheme", scheme)
            MISPHelper._add_obj_attribute(obj, "query_string", query_string)
            MISPHelper._add_obj_attribute(obj, "tld", tld)
        return obj

    @staticmethod
    def create_infrastructure_obj(
        event: pymisp.MISPEvent, name: str, type: str = None
    ) -> pymisp.MISPObject:
        """
        create_infrastructure_obj - creates a MISP object representing infrastructure

        Arguments:
            event -- MISP Event
            name -- name of this infrastructure

        Keyword Arguments:
            type -- type of this infrastructure (default: {None})

        Returns:
            a MISP object representing 'infrastructure'
        """
        infra_tuple = str(name) + "|" + str(type) + "|infrastructure"
        obj, isNew = MISPHelper._create_obj_cached(event, "infrastructure", infra_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "name", name)
            MISPHelper._add_obj_attribute(obj, "infrastructure_type", type)
        return obj

    @staticmethod
    def create_certificate_obj(
        event: pymisp.MISPEvent,
        serial: str,
        issuer: str = None,
        subject: str = None,
        san: list = [],
        notafter: str = None,
        notbefore: str = None,
        signature_algo: str = None,
        key_algo: str = None,
    ) -> pymisp.MISPObject:
        """
        create_certificate_obj - creates a MISP object representing a X509 Certificate (or semi-equivalent)

        Arguments:
            event -- MISP event
            serial -- serial number of the certificate

        Keyword Arguments:
            issuer -- issuer of the certificate (default: {None})
            subject -- subject of the certificate (default: {None})
            san -- SAN of the certificate (default: {[]})
            notafter -- validity end of the certificate (default: {None})
            notbefore -- validity start of the certificate (default: {None})
            signature_algo -- signature algorithm of the certificate (default: {None})
            key_algo -- key algorightm of the certificate (default: {None})

        Returns:
            a MISP object representing a 'x509' certificate
        """
        cert_tuple = str(serial) + "|certificate"
        obj, isNew = MISPHelper._create_obj_cached(event, "x509", cert_tuple)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "serial-number", serial)
            MISPHelper._add_obj_attribute(obj, "issuer", issuer)
            MISPHelper._add_obj_attribute(obj, "subject", subject)
            for s in san:
                MISPHelper._add_obj_attribute(obj, "dns_names", s)
            MISPHelper._add_obj_attribute(obj, "validity-not-after", notafter)
            MISPHelper._add_obj_attribute(obj, "validity-not-before", notbefore)
            MISPHelper._add_obj_attribute(obj, "signature_algorithm", signature_algo)
            MISPHelper._add_obj_attribute(obj, "pubkey-info-algorithm", key_algo)
        return obj

    @staticmethod
    def create_group_obj(
        event: pymisp.MISPEvent, group_name: str, platform: str = None
    ) -> pymisp.MISPObject:
        """
        create_group_obj - creates a MISP object representing a group

        Arguments:
            event -- MISP Event
            group_name -- name of the group

        Keyword Arguments:
            platform -- platform where the group resides (default: {None})

        Returns:
            a MISP object representing an 'identity' group
        """
        tuple_str = group_name + "|group"
        obj, isNew = MISPHelper._create_obj_cached(event, "identity", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "name", group_name)
            MISPHelper._add_obj_attribute(obj, "identity_class", "group")
            MISPHelper._add_obj_attribute(obj, "description", platform)
        return obj

    @staticmethod
    def create_capalert_obj(
        event: pymisp.MISPEvent, msg_type: str, source: str = None, note: str = None
    ) -> pymisp.MISPObject:
        """
        create_capalert_obj - creates a MISP object representing an alert

        Arguments:
            event -- MISP Event
            msg_type -- type of message/alert

        Keyword Arguments:
            source -- source of the message/alert (default: {None})
            note -- additional note of/about the message/alert (default: {None})

        Returns:
            a MISP object representing a 'cap-alert'
        """
        tuple_str = msg_type + "|capalert"
        obj, isNew = MISPHelper._create_obj_cached(event, "cap-alert", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "msgType", msg_type)
            MISPHelper._add_obj_attribute(obj, "source", source)
            MISPHelper._add_obj_attribute(obj, "note", note)
        return obj

    @staticmethod
    def create_process_obj(
        event: pymisp.MISPEvent,
        image: str,
        pid: str = None,
        command_line: str = None,
        start: str = None,
    ) -> pymisp.MISPObject:
        """
        create_process_obj - creates a MISP object representing a execution of a computer program

        Arguments:
            event -- MISP event
            image -- image name of the program

        Keyword Arguments:
            pid -- PID (default: {None})
            command_line -- command line arguments when the program started (default: {None})
            start -- starting datetime (default: {None})

        Returns:
            a MISP object representing a 'process'
        """
        tuple_str = image + "|" + str(pid) + "|" + command_line + "|process"
        obj, isNew = MISPHelper._create_obj_cached(event, "process", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "image", image)
            MISPHelper._add_obj_attribute(obj, "pid", pid)
            MISPHelper._add_obj_attribute(obj, "command-line", command_line)
            MISPHelper._add_obj_attribute(obj, "start-time", start)
        return obj

    @staticmethod
    def create_domainip_obj(
        event: pymisp.MISPEvent,
        domain: str,
        ip: str = None,
        hostname: str = None,
        reg_date: str = None,
    ) -> pymisp.MISPObject:
        """
        create_domainip_obj - creates a MISP object representing an domain-ip combination

        Arguments:
            event -- MISP event
            domain -- domain name

        Keyword Arguments:
            ip -- IP address (default: {None})
            hostname -- hostname (default: {None})
            reg_date -- dns registration date (default: {None})

        Returns:
            a MISP object representing a 'domain-ip'
        """
        tuple_str = domain + "|domain"
        obj, isNew = MISPHelper._create_obj_cached(event, "domain-ip", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "domain", domain)
            MISPHelper._add_obj_attribute(obj, "ip", ip)
            MISPHelper._add_obj_attribute(obj, "hostname", hostname)
            MISPHelper._add_obj_attribute(obj, "registration-date", reg_date)
        return obj

    @staticmethod
    def create_file_obj(
        event: pymisp.MISPEvent,
        local_file_path: str,
        filename: str,
        isMalware: bool = False,
        state: str = None,
        mime_type: str = None,
    ) -> pymisp.MISPObject:
        """
        create_file_obj - creates a MISP object representing a file

        Arguments:
            event -- MISP Event
            local_file_path -- local file path
            filename -- name of the file

        Keyword Arguments:
            isMalware -- Is this file malicious? (default: {False})
            state -- state of the file (default: {None})
            mime_type -- MIME type of the file (default: {None})

        Returns:
            a MISP object representing a 'file'
        """
        raw_data = None
        if local_file_path:
            with open(local_file_path, "rb") as f_in:
                raw_data = f_in.read()
            hash = hashlib.sha256(raw_data).hexdigest()
            tuple_str = hash + "|file"
        else:
            tuple_str = filename + "|file"
            hash = None
            raw_data = None
        obj, isNew = MISPHelper._create_obj_cached(event, "file", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "filename", filename, True)
            MISPHelper._add_obj_attribute(obj, "sha256", hash)
            MISPHelper._add_obj_attribute(obj, "state", state, True)
            MISPHelper._add_obj_attribute(obj, "mimetype", mime_type, True)
            if raw_data:
                MISPHelper._add_obj_attribute(obj, "size-in-bytes", len(raw_data))
                if isMalware:
                    obj.add_attribute(
                        object_relation="malware-sample",
                        value=filename,
                        data=base64.b64encode(raw_data),
                        disable_correlation=True,
                    )
                else:
                    obj.add_attribute(
                        object_relation="attachment",
                        value=filename,
                        data=base64.b64encode(raw_data),
                        disable_correlation=True,
                    )
        return obj

    @staticmethod
    def create_email_obj(
        event: pymisp.MISPEvent,
        email_subject: str,
        message_id: str,
        from_str: str,
        to_str: str,
    ) -> pymisp.MISPObject:
        tuple_str = message_id + "|email"
        obj, isNew = MISPHelper._create_obj_cached(event, "email", tuple_str)
        if isNew:
            MISPHelper._add_obj_attribute(obj, "subject", email_subject)
            MISPHelper._add_obj_attribute(obj, "message-id", message_id)

            from_display_name, from_email = email.utils.parseaddr(from_str)
            MISPHelper._add_obj_attribute(obj, "from", from_email)
            if len(from_display_name) > 0:
                MISPHelper._add_obj_attribute(
                    obj, "from-display-name", from_display_name
                )
            to_display_name, to_email = email.utils.parseaddr(to_str)
            MISPHelper._add_obj_attribute(obj, "to", to_email)
            if len(to_display_name) > 0:
                MISPHelper._add_obj_attribute(obj, "to-display-name", to_display_name)
        return obj
