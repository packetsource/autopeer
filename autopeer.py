#!/usr/bin/env python

"""
autopeer.py - automatically add IBGP peers to an appropriate BGP group when
we observe incoming TCP from the peer with MD5. This tool is designed to
compensate for the fact that in JUNOS it is not possible to write:

protocols {
    bgp {
        group INTERNAL {
            type internal;
            authentication-key SECRET;
            passive;
            allow 192.0.2.0/24; /* allowed peers */
        }
    }
}

If there is no TCP MD5 configured, then this confguration will quite happily
accept peers from anyone in the allow list, creating a low-maintenance route
server/reflector type setup.

But this configuration is not permitted with the TCP MD5 authentication-key
directive because JUNOS cannot seed the underlying BSD TCP stack with the
appropraite MD5 secret without an explicit peer. (It's hard to deletegate
TCP MD5 to rpd userland, because RFC2385 changes the semantics for answering
TCP if the digest doesn't validate)

To compensate, we detect the resulting syslog event from the kernel when
an MD5 TCP segment is received unexpectedly, and setup an event handler to
respond and configure a BGP peer.

event-options {
    policy ADD-BGP-PEER {
        events KERNEL;
        attributes-match {
            KERNEL.message matches tcp_auth_ok;
        }
        then {
            event-script autopeer.py;
        }
    }
    event-script {
        file autopeer.py {
            python-script-user adamc; /* localise: must be a super-user to exec(python) - wtf! */
        }
    }
}
system {
    scripts {
        language python;
    }
}

We determine which BGP group to configre the peer, by synthesising a
variation of the "allow" stanza using apply-macro. This allows a list
of CIDR-notation network prefixes to be nominated per group, and if an 
incoming peer source address matches this, he is added to that group.

protocols {
    bgp {
        group INTERNAL {
            apply-macro autopeer {
                source-address "212.23.38.0/24 212.23.39.0/24";
            }
            type internal;
            local-address 212.23.38.2;
            family inet-vpn {
                unicast;
            }
        }    
    }
}

"""

import sys
import os
import re
import time
from lxml import etree

from junos import Junos_Context
from junos import Junos_Trigger_Event
from junos import Junos_Received_Events

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError, CommitError

import jcs

# need to parse event, event-script-input/trigger-event/message
# using Junos_Received_Events, to extract IP address of connecting
# peer.
#
# Then analyse configurations to find a BGP group for that source

# General error handling
LOGFILE="/var/log/autopeer.log"
def onError(exception_type, exception, traceback):
    sys.stderr.write("%s: %s\n" % (exception_type.__name__, exception))
sys.excepthook = onError

# Diagnostic logging direct to a file, which is a little
# easier than picking apart escript.log
def logmsg(fmt, *args):
    sys.stderr.write(time.strftime("%Y-%m-%d %T") + ": " + (fmt % args) + "\n")

# Rotate to .old after approx 1Mb
def openlog(logfile):
    try:
        filestat = os.stat(logfile)
        if filestat.st_size > 1E6:
            os.rename(logfile, logfile + ".old")
    except:
        pass
    sys.stderr = open(logfile, "a")

# Check if neighbor IP address matches a CIDR/plen prefix,
# returning True or False respectively
def check_group_acl(acl, neighbor):
    acl = jcs.parse_ip(acl)
    neighbor = jcs.parse_ip(neighbor + "/" + acl[2])
    result = (acl[3] == neighbor[3])
    #logmsg("check_group_acl: acl=%s, neighbor=%s: OK=%s", acl, neighbor, result)
    return result

# Configure the peer within the specified group
def add_peer(dev, group, neighbor):
    logmsg("adding neighbor %s to group %s", neighbor, group)
    try:
        with Config(dev, mode="private") as peer_config:
            peer_config.load("set protocols bgp group %s neighbor %s\n" % (group, neighbor), format="set")
            peer_config.commit(comment="autopeer added neighbor %s to BGP group %s" % (neighbor, group))
    except (ConfigLoadError, CommitError) as error:
        logmsg("Unable to commit BGP peer configuration for neighbor %s to group %s", neighbor, group)
        logmsg("Exception: %s", error)

# Main routine
def main():
    openlog(LOGFILE)

    # Look for the trigger event message.
    #
    # In this case, we have no useful metadata because it's a message from the
    # kernel's TCP stack rather than rpd, so we must use a regular expression
    # to extract the peer IP that is attempting TCP MD5 connection. 
    #
    # Note: there is an assumption here that TCP MD5 must be BGP, although no
    # peers will be added unless they match the group's configured source-address allow
    # list.
    msg = Junos_Trigger_Event.xpath('/event-script-input/trigger-event/message')[0].text
    m = re.match("tcp_auth_ok: Packet from (.*):\d+ unexpectedly has (MD5|AUTH) digest", msg)
    if m == None:
        logmsg("WARNING: Couldn't find IP address in event input: ignoring");
        exit(0)
    else:
        neighbor = m.group(1)

        # Extract current committed configuration
        with Device() as dev:
            config = dev.rpc.get_config(options={'database' : 'committed'},
                filter_xml=etree.fromstring('<configuration><protocols><bgp/></protocols></configuration>'))

            # Check BGP peer with IP address DOES NOT already exist
            if config.xpath(('count(//configuration/protocols/bgp/group/neighbor[name="%s"])' % neighbor)) > 0:
                logmsg("Neighbor %s is already configured: ignoring", neighbor)
                exit(0)

            # For every group configured with an apply-macro { source-address "A.B.C.D/E etc" } stanza...
            # extract the group name and the list of allowed source ranges.
            for group in config.xpath('//configuration/protocols/bgp/group' +
                '[apply-macro/name="autopeer" and apply-macro/data/name="source-address"]'):
                    groupname = group.findtext("name")
                    allowed_src = config.xpath(('//configuration/protocols/bgp/group[name="%s"]' % groupname) +
                        '/apply-macro[name="autopeer"]/data/value')[0].text.split(" ")

                    # Check if the neighbor matches any of the allowed sources,
                    # adding him to the group if so, then stopping
                    for src in allowed_src:
                        if check_group_acl(src, neighbor)==True:
                            add_peer(dev, groupname, neighbor)
                            break

if __name__ == '__main__':
    main()
