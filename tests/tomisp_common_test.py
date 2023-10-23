"""
ToMISP - Tests - Common - tests for the common/shared functions
"""
import unittest
import unittest.mock

from tomisp.common import MissingArgumentException
from tomisp.common import array_to_dict
from tomisp.common import generate_uniq
from tomisp.common import parse_ip_and_port
from tomisp.common import validate_args


class CommonTest(unittest.TestCase):
    """
    CommonTest - tests for the common/shared functions
    """

    def test_array2dict_simple(self):
        """
        test_array2dict_simple - testing the 'array2dict' fuction with simple inputs
        """
        test_array = [
            {"FieldOne": "foo", "FieldTwo": "bar"},
            {"FieldOne": "one", "FieldTwo": "a"},
            {"FieldOne": "two", "FieldTwo": "b"},
            {"FieldOne": "three", "FieldTwo": "c"},
            {"FieldOne": "four", "FieldTwo": "d"},
        ]
        expected_dict = {
            "foo": "bar",
            "one": "a",
            "two": "b",
            "three": "c",
            "four": "d",
        }

        actual_dict = array_to_dict(test_array, "FieldOne", "FieldTwo")
        self.assertIsNotNone(actual_dict)
        for key in expected_dict.keys():
            self.assertTrue(key in actual_dict)
            self.assertEqual(expected_dict[key], actual_dict[key])

    def test_array2dict_forcelower(self):
        """
        test_array2dict_simple - testing the 'array2dict' fuction with the 'forcelower' flag set to True
        """
        test_array = [
            {"FieldOne": "Foo", "FieldTwo": "bar"},
            {"FieldOne": "ONE", "FieldTwo": "a"},
            {"FieldOne": "tWo", "FieldTwo": "b"},
            {"FieldOne": "thRee", "FieldTwo": "c"},
            {"FieldOne": "Four", "FieldTwo": "d"},
        ]
        expected_dict = {
            "foo": "bar",
            "one": "a",
            "two": "b",
            "three": "c",
            "four": "d",
        }

        actual_dict = array_to_dict(test_array, "FieldOne", "FieldTwo", True)
        self.assertIsNotNone(actual_dict)
        for key in expected_dict.keys():
            self.assertTrue(key in actual_dict)
            self.assertEqual(expected_dict[key], actual_dict[key])

    def test_ParseIPAndPort_simple(self):
        """
        test_ParseIPAndPort_simple - testing the 'parse_ip_and_port' function with 'normal' arguments
        """
        input_str = "1.2.3.4:1234"
        ip, port = parse_ip_and_port(input_str)
        self.assertEqual("1.2.3.4", ip)
        self.assertEqual("1234", port)

    def test_ParseIPAndPort_noport(self):
        """
        test_ParseIPAndPort_simple - testing the 'parse_ip_and_port' function with no port given
        """
        input_str = "1.2.3.4"
        ip, port = parse_ip_and_port(input_str)
        self.assertEqual("1.2.3.4", ip)
        self.assertIsNone(port)

    def test_ValidateArgs_simple_true(self):
        """
        test_ValidateArgs_simple_true - testing the 'validate_args' function with 'normal' arguments
        """
        requires_one_of = ["A", "B", "C"]
        args = {"B": "foo"}
        actual = validate_args(requires_one_of, args)
        self.assertTrue(actual)

    def test_ValidateArgs_simple_false(self):
        """
        test_ValidateArgs_simple_true - testing the 'validate_args' function with an expected failure
        """
        requires_one_of = ["A", "B", "C"]
        args = {"D": "foo"}
        self.assertRaises(
            MissingArgumentException, validate_args, requires_one_of, args
        )

    def test_GenerateUniq_simple(self):
        """
        test_GenerateUniq_simple - testing the 'generate_uniq' function with 'normal' arguments
        """
        args = ["A", "B", "C"]
        kwargs = {"A": "foo", "B": "bar", "C": "baz"}
        expected = "foo|bar|baz"

        actual = generate_uniq(args, kwargs)

        self.assertEqual(expected, actual)

    @unittest.mock.patch("uuid.uuid4")
    def test_GenerateUniq_emptyArgs(self, mock_uuid4: unittest.mock.MagicMock):
        """
        test_GenerateUniq_simple - testing the 'generate_uniq' function with no given first list
        """
        expected = "12345"
        mock_uuid4.return_value.hex.return_value = expected
        args = []
        kwargs = {"A": "foo", "B": "bar", "C": "baz"}

        actual = generate_uniq(args, kwargs)

        self.assertEqual(expected, actual)
