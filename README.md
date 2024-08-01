# smbtakeover

A technique to unbind and rebind 445/tcp on Windows without loading a driver, loading a module into LSASS, or rebooting the target machine. Implemented to ease the burden of SMB-based NTLM relays while operating over C2. Technical analysis of the technique is dicussed in more detail during the [Relay Your Heart Away: An OPSEC Concious Approach to 445 Takeover](https://www.youtube.com/watch?v=iBqOOkQGJEA) presentation at [x33fcon](https://x.com/x33fcon).

PoCs written in both Python and BOF format. Both utilize RPC over TCP (ncacn_ip_tcp) as transport when targeting remote machines.

### Operational Usage Notes

Please see [this section](updatethis) of the associated blog post for an overview of operational usage considerations. The highlights include:
1. Disabling these services effectively disables the target's ability to leverage namedpipes and and the server-side of SMB-based communication (CIFS, etc). Understand what the target machine is used for, especially if the target is critical / production infrastructure. The services will resume normal functionality once re-enabled.
2. Occasionally there is slightly different series of services that need to be disabled. I've seen this occur in some version of Windows Server, as well as if certain third-party networking drivers are installed. This won't prevent you from using this technique. You can enumerate service dependencies backwards from `srvnet` and see if there are additional dependents to consider.
3. You don't have to use this PoC to abuse this technique! Your favorite tool to interact with service control manager (SCM) should work.
    - Make sure you understand if the tool of your choice leverages `ncacn_ip_tcp` or `ncacn_np` as transport for RPC. If it uses the latter (named pipes) then you won't be able to communicate remotely with the target to re-enable.

### Setup (for Python implementation)
Create a Python virtual environment and `pip install` impacket.
1. `git clone https://github.com/zyn3rgy/smbtakeover.git`
2. `cd smbtakeover`
3. `python3 -m virtualenv venv`
4. `source venv/bin/activate`
5. `python3 -m pip install impacket`
6. `python3 smbtakeover.py -h`


### Example Usage
#### Python 
- `python3 smbtakeover.py atlas.lab/josh:password1@10.0.0.21 check`
- `python3 smbtakeover.py atlas.lab/josh:password1@10.0.0.21 stop`
- `python3 smbtakeover.py atlas.lab/josh:password1@10.0.0.21 start`

#### BOF
1. `bof_smbtakeover localhost check`
2. `bof_smbtakeover 10.0.0.21 stop`
3. `bof_smbtakeover localhost start`

### Credits
- Python implementation is heavily based on the [wmiexec-Pro](https://github.com/XiaoliChan/wmiexec-Pro) project by [@Memory_before](https://x.com/Memory_before)
- BOF implementation is heavily based on the [CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF/tree/main/src/Remote) repository, such as [sc_config](https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/src/Remote/sc_config/entry.c), from the great folks at [@TrustedSec](https://x.com/trustedsec)
