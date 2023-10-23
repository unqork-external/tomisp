"""
ToMISP - Tests - MISPHelper - tests for the MISPHelper class
"""
import unittest
import unittest.mock

from pymisp import MISPEvent

from tomisp import MISPHelper
from tomisp.common import MissingArgumentException


class MISPHelperTest(unittest.TestCase):
    """
    MISPHelperTest - class for testing the MISPHelper class
    """

    @unittest.mock.patch("pymisp.PyMISP")
    def test_cTor_basic(self, mock_pyMISP: unittest.mock.MagicMock):
        """
        test_cTor_basic - basic test of the MISPHelper constructor
        """
        arg1 = "foo"
        arg2 = "bar"
        o = MISPHelper(misp_url=arg1, misp_api_key=arg2)
        self.assertIsNotNone(o)
        mock_pyMISP.assert_called_once_with(arg1, arg2, False, False, tool="MISPHelper")

    def test_cTor_noargs(self):
        """
        test_cTor_noargs - testing calling the MISPHelper constructor with no arguments
        """
        self.assertRaises(MissingArgumentException, MISPHelper)

    @unittest.mock.patch("pymisp.PyMISP")
    def test_cTor_withSSLVerify(self, mock_pyMISP: unittest.mock.MagicMock):
        """
        test_cTor_withSSLVerify - test of the MISPHelper constructor with the extra ssl_verify parameter
        """
        arg1 = "foo"
        arg2 = "bar"
        arg3 = True
        o = MISPHelper(misp_url=arg1, misp_api_key=arg2, ssl_verify=arg3)
        self.assertIsNotNone(o)
        mock_pyMISP.assert_called_once_with(arg1, arg2, arg3, False, tool="MISPHelper")

    def test_CreateEvent_simple(self):
        """
        test_CreateEvent_simple - testing the 'create_event' method
        """
        info = "test"
        o = MISPHelper.create_event(info)
        self.assertIsNotNone(o)
        self.assertTrue(
            isinstance(o, MISPEvent), "Returned object not of the expected type"
        )
        self.assertEqual(o.info, info)
