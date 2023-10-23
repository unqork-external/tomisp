"""
ToMISP - common/shared functions
"""
import uuid
from typing import Any
from typing import Dict
from typing import List


class MissingArgumentException(Exception):
    """
    MissingArgumentException - Exception class when expected/required arguments are missing
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args)
        self.RequiredOneOf = kwargs.get("requires")
        self.RequiredAll = kwargs.get("required")
        self.Supplied = kwargs.get("supplied")


def parse_ip_and_port(ip_port: str) -> (str, str | None):
    """
    parse_ip_and_port - parses a ip:port string into its parts

    Arguments:
        ip_port -- str of ip and port (eg. "1.2.3.4:5678)

    Returns:
        a tuple of ip and port
    """
    parts = ip_port.split(":")
    if len(parts) > 1:
        return parts[0], parts[1]
    else:
        return parts[0], None


def validate_args(requires: List[str], kwargs: Dict[str, Any]) -> bool:
    """
    validate_args - validates that the required fields are present in the given dictionary

    Arguments:
        requires -- list of str fields that are required (at least one)
        kwargs -- dict of given arguments

    Raises:
        MissingArgumentException: if the given dict does not have at least one of the given fields

    Returns:
        true IFF the dict has at least one of the given fields
    """
    has_an_arg = False
    for required_keyword_arg in requires:
        has_an_arg |= required_keyword_arg in kwargs
    if not has_an_arg:
        raise MissingArgumentException(required=requires, supplied=kwargs.values())
    return has_an_arg


def generate_uniq(args: List[str], kwargs: Dict[str, Any]) -> str:
    """
    generate_uniq - generates a unique str of the values of the given fields in the dict

    Arguments:
        args -- fields to pull from the dict
        kwargs -- the dict

    Returns:
        pipe seperated list of values as a single str
    """
    if len(args) == 0:
        return uuid.uuid4().hex()
    ans = []
    for arg in args:
        ans.append(kwargs.get(arg))
    return "|".join(ans)


def array_to_dict(
    array: List[Dict[str, str]],
    key_field: str,
    value_field: str,
    force_lowercase: bool = False,
    ignore_missing_value_fields: bool = True,
    ignore_missing_name_fields: bool = True,
) -> Dict[str, str]:
    """
    array_to_dict - turns an array of field definitions into a dictionary

    Arguments:
        array -- list of dictionaries
        key_field -- key field in single dictionary
        value_field -- value field in single dictionary
        ignore_missing_value_fields -- ignore an item if it doesn't have the value field (default: {True})
        ignore_missing_name_fields -- ignore an item if it doesn't have the name field (default: {True})

    Keyword Arguments:
        force_lowercase -- if true will force the keys to lowercase (default: {False})

    Returns:
        a dictionary of key value pairs
    """
    ans = {}
    for child in array:
        if key_field in child:
            if value_field in child:
                if force_lowercase:
                    ans[child[key_field].lower()] = child[value_field]
                else:
                    ans[child[key_field]] = child[value_field]
            elif not ignore_missing_value_fields:
                raise Exception("missing value field")
        elif not ignore_missing_name_fields:
            raise Exception("missing key field")
    return ans
