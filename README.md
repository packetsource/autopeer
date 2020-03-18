# Automatic Configuration of Incoming BGP Peering Sessions

On JUNOS boxes, it's possible to ease the configuration burden
associated with setting up BGP peering using the `allow` directive.
Combined with the `passive` directive which instructs `rpd` not to
try to actively establish sessions, this allows you to create a
promisucous route reflector platform that will accept connections
from any of your internal routers, associated with a group and
set of input/output policies, without any explicit per-peer configuration.

An example configuration for this might look something like this:

```
protocols {
    bgp {
        group INTERNAL {
            type internal;
            family inet {
            	unicast;
            }
            import ANY;
            export ANY;
            passive;
            allow 192.0.2.0/24; /* allowed peers */
        }
    }
}
```

Unfortunately, these features do not operate as we would like if you
also make use of the TCP-layer security options such as RFC2385's
TCP MD5 and/or RFC5925's TCP-AO. In these cases, it is necessary
for `rpd` to seek the kernel's TCP module with the necessary secret
information, so that the kernel can broker the incoming TCP connection
correctly. If `rpd` doesn't know which peers will connect, it cannot
easily do that.

`autopeer.py` is a Python script intend to alleviate this problem and
restore some of the maintenance benefits associated with `allow` and `passive`.
Since JUNOS 16.1, Juniper has allowed the use of Python scripts, in addition to
the traditional SLAX/XML processing scripts to be used in response to network
events (`event-scripts` in JUNOS parlance).

`autopeer.py` works by taking a feed of the configured network events and looking
for the typical fingerprint associated with an incoming TCP connection that has
the TCP MD5 authentication option. It looks likes this:

```
Mar  9 18:48:53  vrr2 kernel: tcp_auth_ok: Packet from 212.23.38.1:60042 unexpectedly has MD5 digest
```

When this message is seen, `autopeer.py` extracts the IP address from the message, then
analyses the BGP configuration to look for any configured group that declares an interest
in the source address. Sadly it's not possible to re-use the `allow` directive for this,
since, quite rightly, JUNOS rejects any attempts to commit a configuration including
an `allow` directive and also a TCP MD5 `authentication-key` directive:

```
[edit protocols bgp group TEST]
  'allow'
    May not be configured with authentication-key
error: configuration check-out failed: (statements constraint check failed)
```

To rememdy this, `autopeer.py` looks for the declaration of interesting peers in
a custom configuration stanza faciliated by the `apply-macro` directive. 

> `apply-macro` is a hidden configuration knob that allows the further configuration of
> a set of user-specific key-value pairs. None of these configuration keys serve any purpose to
> vanilla JUNOS, but tools such as commit scripts or event scripts can make use of them
> to extract meta-data or intent-based super-configuration.

If `auotpeer.py` is able to match the report about incoming TCP connection with MD5 to a configured
peer group that has a specified interest list, it issues a configuration change to commit the
incoming neighbor, allowing the configuration.

With this in mind, our original BGP group definition now looks like this:

```
group INTERNAL {
	authentication-key "$9$jgBVhf74jskleirk-lg7"; ## SECRET-DATA
    apply-macro autopeer {
        source-address "192.0.2.0/24 198.51.100.0/24 203.0.113.0/24";
    }
    type internal;
    local-address 192.0.2.1;
    family inet-vpn {
        unicast;
    }
}
```

Any incoming connections within the specified address ranges in the custom key
`source-address` are eligible for automatic addition to the configuration. When
`autopeer.py` configures a peer, it records a log message to `/var/log/autopeer.log`:

```
2020-03-09 19:41:31: adding neighbor 192.0.2.2 to group INTERNAL
```

## Installation

- Copy `autopeer.py` into the conventional `/var/db/scripts/event` directory for storing event scripts. You need superuser rights to write to this location.

- Declare the event script within the JUNOS and the situation in which it is called

```
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
            python-script-user root; /* must be a super-user to exec(python) - wtf! */
        }
    }
}
system {
    scripts {
        language python;
    }
}
```