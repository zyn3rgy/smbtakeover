import sys
import logging
import json

from impacket.dcerpc.v5.dtypes import NULL

ERROR_MSG = {
    0:"The request was accepted.",
    1:"The request is not supported.",
    2:"The user did not have the necessary access.",
    3:"The service cannot be stopped because other services that are running are dependent on it.",
    4:"The requested control code is not valid, or it is unacceptable to the service.",
    5:"The requested control code cannot be sent to the service because the state of the service (State property of the Win32_BaseService class) is equal to 0, 1, or 2.",
    6:"The service has not been started.",
    7:"The service did not respond to the start request in a timely fashion.",
    8:"Unknown failure when starting the service.",
    9:"The directory path to the service executable file was not found.",
    10:"The service is already running.",
    11:"The database to add a new service is locked.",
    12:"A dependency this service relies on has been removed from the system.",
    13:"The service failed to find the service needed from a dependent service.",
    14:"The service has been disabled from the system.",
    15:"The service does not have the correct authentication to run on the system.",
    16:"This service is being removed from the system.",
    17:"The service has no execution thread.",
    18:"The service has circular dependencies when it starts.",
    19:"A service is running under the same name.",
    20:"The service name has invalid characters.",
    21:"Invalid parameters have been passed to the service.",
    22:"The account under which this service runs is either invalid or lacks the permissions to run the service.",
    23:"The service exists in the database of services available from the system.",
    24:"The service is currently paused in the system."
}

class Service_Toolkit:
    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom

    @staticmethod
    def checkError(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
        if call_status != 0:
            from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
        else:
            logging.info('%s - OK' % banner)

    def check_Service(self, serviceName, iWbemServices=None):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            Service_ClassObject,_ = iWbemServices.GetObject('Win32_Service.Name="%s"' %serviceName)
        except Exception as e:
            if "WBEM_E_NOT_FOUND" in str(e):
                print("[-] Service not found!")
            else:
                print("[-] Unknown error: %s" %str(e))
            self.dcom.disconnect()
            sys.exit(1)
        else:
            record = dict(Service_ClassObject.getProperties())
            # Refactored print logic using values directly from the record variable
            print("[*] {}".format(record.get('Name', {}).get('value', 'Unknown')))
            print("      |------- state:     {}".format(record.get('State', {}).get('value', 'Unknown')))
            print("      |------- starttype: {}".format(record.get('StartMode', {}).get('value', 'Unknown')))
            print("      |------- path:      {}".format(record.get('PathName', {}).get('value', 'Unknown')))
            print("")
            
            if not record:
                print("[-] Error occurred while fetching service info")
                sys.exit(1)

            if record.get('State', {}).get('value', 'Unknown') == "Running":
                return True
            else:
                return False

            
        
    def control_Service(self, action, serviceName, iWbemServices=None):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            Service_ClassObject,_ = iWbemServices.GetObject('Win32_Service.Name="%s"' %serviceName)
        except Exception as e:
            if "WBEM_E_NOT_FOUND" in str(e):
                print("[-] Service not found!")
            else:
                print("[-] Unknown error: %s" %str(e))
            self.dcom.disconnect()
            sys.exit(1)
        else:
            if action == "start":
                resp = Service_ClassObject.StartService()
                if resp.ReturnValue == 0 :
                    print("[*] {}".format(f"{serviceName}"))
                    print("     |--- action: Started")
            elif action == "stop":
                resp = Service_ClassObject.StopService()
                if resp.ReturnValue == 0 :
                    print("[*] {}".format(f"{serviceName}"))
                    print("     |--- action: Stopped")
            elif action == "disable":
                resp = Service_ClassObject.ChangeStartMode("Disabled")
                if resp.ReturnValue == 0 :
                    print("[*] {}".format(f"{serviceName}"))
                    print("     |--- action: starttype=Disabled")
            elif action == "auto-start":
                resp = Service_ClassObject.ChangeStartMode("Automatic")
                if resp.ReturnValue == 0 :
                    print("[*] {}".format(f"{serviceName}"))
                    print("     |--- action: starttype=auto-start")
            elif action == "manual-start":
                resp = Service_ClassObject.ChangeStartMode("Manual")
                if resp.ReturnValue == 0 :
                    print("[*] {}".format(f"{serviceName}"))
                    print("     |--- action: starttype=manual")

            try:
                if resp.ReturnValue == 0 :
                    print("")
                else:
                    print("[-] Return value: {}, reason: {}".format(
                                                            str(resp.ReturnValue),
                                                            ERROR_MSG[resp.ReturnValue]
                                                            ))
            except:
                pass
    
    # Todo: modify moudles