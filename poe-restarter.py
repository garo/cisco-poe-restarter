from pysnmp.hlapi import *
from pysnmp import hlapi
from pprint import pprint
import time
import sys
from pysnmp.entity.rfc3413.oneliner import cmdgen


# How many seconds to keep power off when toggling power off and back on
POWER_SLEEP_DELAY = 2
# Magic keyword which needs to be in the port description so that the power is toggled
MAGIC_KEYWORD = "poe"

# Configure snmp-server in cisco with these two commands:
# snmp-server group poe-restarter v3 auth write v1default
# snmp-server user poe-restarter-user poe-restarter v3 auth sha secret-password
SNMP_AUTH = UsmUserData('poe-restarter-user', 'secret-password', None, cmdgen.usmHMACSHAAuthProtocol)

# Or if you want to test without any authentication
#SNMP_AUTH = hlapi.CommunityData('public')

# This tool uses code from https://www.ictshore.com/sdn/python-snmp-tutorial/ written by Alessandro Maggio (2018),
# licensed under MIT license.

def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types

def fetch(handler, count):
    result = []
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    items[str(var_bind[0])] = cast(var_bind[1])
                result.append(items)
            else:
                raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break
    return result

def cast(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        try:
            return float(value)
        except (ValueError, TypeError):
            try:
                return str(value)
            except (ValueError, TypeError):
                pass
    return value

def construct_value_pairs(list_of_pairs):
    pairs = []
    for key, value in list_of_pairs.items():
        pairs.append(hlapi.ObjectType(hlapi.ObjectIdentity(key), value))
    return pairs

def set_one(target, oid, value, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.setCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        hlapi.ObjectType(hlapi.ObjectIdentity(oid), value)
    )
    return fetch(handler, 1)[0]

def get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.getCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_object_types(oids)
    )
    return fetch(handler, 1)[0]

def get_one(target, oid, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    data = get(target, [oid], credentials)
    return data[oid]

def get_bulk(target, oids, credentials, count, start_from=0, port=161,
             engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.bulkCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        start_from, count,
        *construct_object_types(oids)
    )
    return fetch(handler, count)

def get_bulk_auto(target, oids, credentials, count_oid, start_from=0, port=161,
                  engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    count = get(target, [count_oid], credentials, port, engine, context)[count_oid]
    return get_bulk(target, oids, credentials, count, start_from, port, engine, context)

def walk(target, oids, credentials):
    results = []
    for (errorIndication,errorStatus,errorIndex,varBinds) in \
        nextCmd(SnmpEngine(), credentials, UdpTransportTarget((target, 161)), ContextData(), \
                *construct_object_types(oids), lexicographicMode=False):
        if errorIndication:
            print(errorIndication, file=sys.stderr)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), 
                                file=sys.stderr)
            break
        else:   
            items = {}       
            for varBind in varBinds:
                items[str(varBind[0])] = cast(varBind[1])
            results.append(items)
    return results


OID_HOSTNAME = '1.3.6.1.2.1.1.5.0'
OID_INTERFACE_COUNT = '1.3.6.1.2.1.2.1.0'
OID_POE_STATUS = '1.3.6.1.2.1.105.1.1.1.3.1'
OID_INTERFACE_DESCRIPTION = '1.3.6.1.2.1.31.1.1.1.18' # ...mib-2.ifMIB.ifMIBObjects.ifXTable.ifXEntry.ifAlias
OID_INTERFACE_INDEX = '1.3.6.1.2.1.2.2.1.1' # ...mib-2.interfaces.ifTable.ifIndex
OID_INTERFACE_NAME = '1.3.6.1.2.1.2.2.1.2' # ...mib-2.interfaces.ifTable.ifDescr
OID_ENT_ALIAS_MAPPING_IDENTIFIER = '1.3.6.1.2.1.47.1.3.2.1.2'
OID_CPE_EXT_PSE_PORT_ENT_PHY_INDEX = '1.3.6.1.4.1.9.9.402.1.2.1.11'

def get_value_by_oid(map, oid_prefix):
    for k, v in map.items():
        #print("%s is %s" % (k,v))
        if k.startswith(oid_prefix + '.'):
            return v
    return None

def buildIfIndexToPhysicalIndexMap(ip, credentials=None):
    """
    Returns a map from entPhyIndex to ifIndex for each physical interface
    """
    if credentials == None:
        credentials = hlapi.CommunityData('public')
    items = walk(ip, [OID_ENT_ALIAS_MAPPING_IDENTIFIER], credentials)
    phyMap = {}
    for item in items:
        for k, v in item.items():
            if k.startswith(OID_ENT_ALIAS_MAPPING_IDENTIFIER):
                # k is now "1.3.6.1.2.1.47.1.3.2.1.2.1062.0" where "1062" is what we want
                # So trim the beginning before "1062" away
                phy = k[len(OID_ENT_ALIAS_MAPPING_IDENTIFIER)+1:]            
                # And remove the trailing ".0"
                phy = phy[:-len('.0')]
                # v is now the ifIndex, eg "1.3.6.1.2.1.2.2.1.1.123" where 123 is what we want
                # So trim the ifIndex away
                ifIndex = v[len('1.3.6.1.2.1.2.2.1.1')+1:]
                phyMap[ifIndex] = phy
    return phyMap

def getPoeStatus(ip, credentials=None):
    if credentials == None:
        credentials = hlapi.CommunityData('public')
    items = walk(ip, [OID_POE_STATUS, OID_CPE_EXT_PSE_PORT_ENT_PHY_INDEX], credentials)
    poe_status = {}
    for item in items:
        phyIndex = None
        poeStatus = None
        poeStatusOid = None
        for k, v in item.items():
            if k.startswith(OID_CPE_EXT_PSE_PORT_ENT_PHY_INDEX):
                phyIndex = v
            if k.startswith(OID_POE_STATUS):
                poeStatus = v
                poeStatusOid = k
        if phyIndex != None and poeStatus != None:
            poe_status[str(phyIndex)] = (poeStatus, poeStatusOid)
    return poe_status

POE_OFF = Integer(2)
POE_ON = Integer(1)

def handle(ip):
    credentials = SNMP_AUTH
    hostname = get_one(ip, OID_HOSTNAME, credentials)
    phyMap = buildIfIndexToPhysicalIndexMap(ip)
    poeStatusMap = getPoeStatus(ip)
    its = get_bulk_auto(ip, [OID_INTERFACE_NAME, OID_INTERFACE_DESCRIPTION, OID_INTERFACE_INDEX], credentials, OID_INTERFACE_COUNT)
    print("Checking switch %s" % (hostname))
    ports_to_toggle_power = []
    for it in its:
        name = get_value_by_oid(it, OID_INTERFACE_NAME)
        description = get_value_by_oid(it, OID_INTERFACE_DESCRIPTION)
        ifIndex = get_value_by_oid(it, OID_INTERFACE_INDEX)
        if MAGIC_KEYWORD not in description:
            continue
        phyIndex = phyMap[str(ifIndex)]
        poe_status = poeStatusMap[phyIndex]
        if poe_status[0] == 2:
            poe_status_str = "Administratively disabled"
        elif poe_status[0] == 1:
            poe_status_str = "Allowed"
        else:
            poe_status_str = ("Unknown (%d)" % (poe_status[0]))
        print("Port #%d: %s (%s) poe status is %s" % (ifIndex, name, description, poe_status_str))
        ports_to_toggle_power.append(poe_status[1])

    print("Going to power-toggle %d ports off and again back on" % len(ports_to_toggle_power))
    for oid in ports_to_toggle_power:     
        set_one(ip, oid, POE_OFF, credentials)
    print("Sleeping a few seconds")
    time.sleep(POWER_SLEEP_DELAY)
    print("Turning power back on")
    for oid in ports_to_toggle_power:
        set_one(ip, oid, POE_ON, credentials)
    print("All done for switch %s\n" % hostname)

#handle()
if len(sys.argv) != 2:
    print("Usage: \"poe-restarter <ip or filename.txt>\" where filename.txt is a file which contains one ip/hostname per line")
    sys.exit(1)

switches = []
if not sys.argv[1].endswith(".txt"):
    switches.append(sys.argv[1])
else:
    print("Reading list of switches from file %s" % sys.argv[1])
    f = open(sys.argv[1], "r")
    for x in f:
        line = x.rstrip()
        if line != "":
            switches.append(line)

print("Checking these %d switches: %s" % (len(switches), ', '.join(switches)))
for switch in switches:
    handle(switch)
