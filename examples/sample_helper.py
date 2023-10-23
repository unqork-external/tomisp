"""
Helper functions for the samples
"""

from random import choice
from random import randint
from string import ascii_letters
from typing import Any
from typing import Callable

_IP_PREFIXES = ["192.0.2", "198.51.100", "203.0.113", "233.252.0"]
_URI_PATHS = [
    "conf.swp",
    "guestbook/guestbookdat",
    "html",
    "swfupload",
    ".remote-sync.json",
    "_vti_cnf",
    "admin/_logs/err.log",
    "source_gen.caches",
    "mhadmin",
    "fckeditor/editor/filemanager/upload/php/upload.php",
    ".htusers",
    "config/database.yml.pgsql",
    "usr-bin/",
    "directory",
    "admin0",
    "WEB-INF/spring-config/services-remote-config.xml",
    "dvwa/",
    "j2ee/servlet/SnoopServlet",
    "doc/en/changes.html",
    ".idea/modules.xml",
    "AddressBookW2JE/services/AddressBook",
    "forms.%EXT%",
    ".admin/",
    ".db.xml",
    "php-cgi.core",
    "media.zip",
    "delete.php",
    "changelog.md",
    "typo3",
    "archive.7z",
    "users.%EXT%",
    ".vscode/launch.json",
    ".ackrc",
    "rootadmin",
    "administracja",
    "eudora.ini",
    "maintenance.php",
    "bower.json",
    "backend/",
    "a_gauche",
    ".bower-cache",
    "xprober.php",
    "lib/flex/varien/.project",
    "save",
    ".postcssrc.js",
    "Office/",
    "detail",
    "phpMyAdmin-2.6.3-rc1",
    "admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php",
    "%ff",
    "UPGRADE.txt",
    "payment.log",
    "secure",
    ".ensime",
    "WEB-INF/spring-configuration/filters.xml",
    "newsletter/",
    "reviews",
    "db__.init.php",
    ".idea/modules.xml",
    "jsp/viewer/snoop.jsp",
    "administrateur",
    "VirtualEms/Login.aspx",
    "images_upload/",
    "atom",
    "checkuser",
    "start.sh",
    "eula_en.txt",
    ".travisci.yml",
    "actuator/loggers",
    ".gitconfig",
    "authtoken",
    "getior",
    "www.zip",
    "_baks.%EXT%",
    ".gitignore.swp",
    "admin/phpMyAdmin/",
    "wp-config.php.new",
    "rest-api/",
    "actuators/health",
    "login.html",
    "_vti_inf.html",
    ".verb.md",
    "htaccess.old",
    "phpmyadmin2016/",
    "jira/",
    "fonts",
    "training",
    "phpMyAdmin-2.6.0-pl3/",
    "files.php",
    "a4j/s/3_3_3.Finalorg/richfaces/renderkit/html/css/basic_classes.xcss/DATB/",
    "log/authorizenet.log",
    "bea_wls_internal/HTTPClntSend",
    "phpMyAdmin-2.5.5/",
    "admin/sxd/",
    "auth.rb",
    "maintenance.php",
    "passwd/",
    ".vim.custom",
    ".functions",
    "admin/files.php",
    ".config/karma.conf.js",
    "control/login",
    "site/common.xml",
    "maintenance/test2.php",
    "log.html",
    ".ssh/google_compute_engine",
    "backups.tar",
    "sxdpro/",
    "~fwadmin",
    "config.txt",
    ".tool-versions",
    "cowadmin",
    "adminlocales.%EXT%",
    ".modgit/",
    "webstats",
    "phpMyAdmin-2.11.9/",
    "adminresources",
    "Http/DataLayCfg.xml",
    "web.config",
    ".idea/misc.xml",
    ".concrete/DEV_MODE",
    "JTAExtensionsSamples/docs/",
    "mmadmin",
    "s",
    "bootstrap/data",
    "sxdpro/",
    "sphinx",
    "Version.%EXT%",
    "PMA2/index.php",
    "%EXT%",
    "account/login.shtml",
    "ipython/tree",
    "swagger",
    "93",
    "actuator/;/status",
    "storage",
    "tmp/dz.php",
    "PMA/index.php",
    "phpMyAdmin-3.3.4/",
    "administation",
    "accessories",
    "phpMyAdmin-2.5.6-rc2",
    "bbadmin",
    "signin.jsp",
    "file_upload.htm",
    "typo3conf/ext/crawler/ext_tables.sql",
    "sendmail",
    ".mozilla/firefox/logins.json",
    "members/login.html",
    ".msync.yml",
    "vendor-data.txt",
    "admin_area/admin",
    "agent_admin",
    ".SyncIgnore",
    "symfony/apps/frontend/config/routing.yml",
    ".venv",
    "MySQLadmin",
    "creo_admin",
    "history",
    ".java-version",
    "database_credentials.inc",
    "phpMyAdmin-2.5.5-rc1",
    "templates_admin",
    "actuator/;/threaddump",
    "reports",
    "artifacts/",
    "piwik/",
    "estore/index.html",
    "60",
    "ccct-admin",
    "cal",
    "bea_wls_internal/iiop/ClientSend",
    "swagger/v1/swagger.json",
    "WEB-INF/ejb-jar.xml",
    ".s3cfg",
    ".fontconfig/",
    "typo3conf/ext/yag_themepack_jquery/ext_tables.sql",
    ".pass",
    ".well-known/repute-template",
    "fileadmin.php",
    "admin_main",
    "documents",
    "Remote_Execution/",
    "53",
    "agadmin",
    "phppgadmin/",
    "actuator/;/auditLog",
    "app/config/database.yml.pgsql",
    ".settings/org.eclipse.php.core.prefs",
    "orders.csv",
    ".prettierrc.js",
    "html2pdf",
    "classes_gen",
    "osCadmin",
    ";/admin",
    "uploadfile.php",
    "ur-admin.php",
    "graphql.php",
    "91",
    "phpMyAdmin-2.6.1-rc2",
]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/537.36 (KHTML, like Gecko, Mediapartners-Google) Chrome/117.0.5938.132 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.112 Mobile/15E148 Safari/604.",
    "Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/537.36 (KHTML, like Gecko; Mediapartners-Google) Chrome/117.0.5938.132 Mobile Safari/537.3",
]


def generate_ip() -> str:
    """
    generate_ip - generates a random IP in the example subnets
    """
    prefix = choice(_IP_PREFIXES)
    return ".".join([prefix, str(randint(1, 254))])


def generate_ip_and_port() -> str:
    """
    generate_ip_and_port - generates a random IP and port
    """
    return generate_ip() + ":" + str(randint(20000, 30000))


def generate_random_uri_path() -> str:
    """
    generate_random_uri_path - generates a random path for a URI (based on a list of random paths)
    """
    return choice(_URI_PATHS)


def generate_random_ua() -> str:
    """
    generate_random_ua - picks a random user agent from a list
    """
    return choice(_USER_AGENTS)


def generate_random_str(charset: str = ascii_letters, length: int = 5) -> str:
    """
    generate_random_str - generates a random string based on a given character set

    Keyword Arguments:
        charset -- string of characters to pick from (default: {string.ascii_letters})
        length -- length of the generated string (default: {5})
    """
    return "".join([choice(charset) for x in range(length)])


def get_parts_from_ua(user_agent: str) -> (str, str):
    """
    get_parts_from_ua - returns a tuple of browser and os from a given user agent string

    uses 'user-agent' library

    Arguments:
        user_agent -- user agent

    Returns:
        browser, os
    """
    from user_agents import parse

    ua = parse(user_agent)
    return ua.browser.family, ua.os.family


class CachedGenerator:
    """
    CachedGenerator - a class for fixed random generation
    """

    def __init__(
        self,
        new_value_function: Callable[[str, int], Any],
        existing_cache: dict = None,
        counter_start: int = 0,
    ) -> None:
        self.new_value = new_value_function
        if existing_cache:
            self.cache = existing_cache
        else:
            self.cache = {}
        self.counter = counter_start

    def Generate(self, v: str) -> Any:
        """
        Generate - generates a new item, based on the input; repeated input will result in repeated output
        """
        if v not in self.cache:
            self.cache[v] = self.new_value(v, self.counter)
            self.counter += 1
        return self.cache[v]
