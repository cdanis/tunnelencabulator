#!/usr/bin/env python3
"""
For a number of years now, work has been proceeding in order to bring to perfection the
crudely-conceived idea of a machine that would not only supply the easy re-routing of
traffic for load-balanced services, but would also be capable of automatically synchronizing
single-homed LibreNMSes and icingas.  Such an instrument is the tunnel-encabulator.
"""

__author__ = "Chris Danis"
__version__ = "0.2.0"
__license__ = "Apache 2.0"
__copyright__ = """
Copyright © 2020 Chris Danis & the Wikimedia Foundation

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
except in compliance with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied.  See the License for the specific language governing permissions
and limitations under the License.
"""

import argparse
import itertools
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time


# Hosts fronted by text-lb.
TEXT_CDN_HOSTS = [
    "grafana",
    "phabricator",
    "turnilo",
    "wikitech",
    "logstash",
    "etherpad",
    "people",
    "puppetboard",
    "debmonitor",
    "w.wiki",
    "www.mediawiki.org",
    "mediawiki.org",
    "en.wikipedia.org",  # TODO other wikipedias?
]

# Hosts that live outside of the CDN, and need --ssh-tunnel.
# Dict of hostname => [port numbers]
TUNNEL_HOSTS = {
    "cas-icinga": [443],
    "gerrit": [443, 29418],
    "icinga": [443],
    "alerts": [443],
    "idp": [443],
    "librenms": [443],
    "netbox": [443],
}

# Did you know that 127.0.0.1 isn't just a single IP address, but rather
# an entire /8 block?  As of 2020 that many IPv4 addresses would be worth
# approximately $335.5M USD.  As of 2023 this has risen to approx $839M USD.
TUNNEL_NET = "127.149.7."  # There's no place like AS14907

# Get the current mapping with:
# cumin --force -o txt 'O:bastionhost' 'cat /etc/wikimedia-cluster' | \
#    awk 'x==1 { gsub(":", "", $1) ; printf "\047%s\047: \047%s\047,\n", $2, $1 } \
#         /_____FORMATTED_OUTPUT_____/ { x=1 }'
BASTIONS = {
    'eqiad': 'bast1003.wikimedia.org',
    'codfw': 'bast2002.wikimedia.org',
    'esams': 'bast3006.wikimedia.org',
    'ulsfo': 'bast4004.wikimedia.org',
    'eqsin': 'bast5003.wikimedia.org',
    'drmrs': 'bast6002.wikimedia.org',
}

MAGIC = "# added by tunnelencabulator"


def replenerate_hostname(h):
    """
    Apply sinusoidal repleneration to h, which might not be a FQDN,
    ensuring it becomes a FQDN.
    """
    return h if "." in h else f"{h}.wikimedia.org"


def replenerate_hostnames(hosts):
    """
    Apply sinusoidal repleneration to hosts, which might not be FQDNs,
    ensuring they become FQDNs.
    """
    return [replenerate_hostname(h) for h in hosts]


def prefabulate_tunnel(tunnel_hosts, *, tunnel_net):
    """
    Constructs a malleable logarithmic casing in such a way that there is a
    shared mapping of tunnel_hosts to pre-fabulated IP addresses.
    """
    return {host: f"{tunnel_net}{ip}" for (ip, host)
            in enumerate(tunnel_hosts, start=1)}


def unprivilegify_port(port):
    """Not all operating systems allow port forwardings to be in a direct line
    with the panametric privilege fan.  In these cases we are forced to engage
    in additive translation."""
    return port + 8000 if port < 1024 else port


def panametric_fan_ports(unprivilegify=True, *, tunnel_hosts, tunnel_net):
    """
    Attaches the malleable logarithmic casing surrounding tunnel_host marzlevanes
    onto the semi-boloid slots of SSH command line syntax.
    """
    return itertools.chain(*[
        ["-L", f"{ip}:{unprivilegify_port(port) if unprivilegify else port}:{host}:{port}"]
        for (host, ip) in prefabulate_tunnel(tunnel_hosts=tunnel_hosts,
                                             tunnel_net=tunnel_net).items()
        for port in tunnel_hosts[host]])


def surmount_host_line(host, ip, *, dest=None):
    """
    Now, basically, the only new principle involved is that instead of hostnames
    being resolved by the relative motion of recursive and authoritative nameservers,
    they are resolved instead by the modial interaction of gethostbyname and /etc/hosts.
    """
    return f"{ip:16}{host:32}" + (f"# {dest}\t" if dest else "") + MAGIC


# TODO IPv6 support
# (NB: it is actually impossible to provide --ssh-tunnel support for IPv6.
# In IPv4, all of 127.0.0.0/8 is reserved for loopback.  In IPv6, there is
# exactly *one* loopback address, ::1/128.  If you think this is sadlarious,
# I agree.)
def apply_encabulation(lines, *, port_forwarding_dingle_arm=False, dest,
                       text_cdn_hosts, tunnel_hosts, tunnel_net):
    """A function to be passed to rewrite_hosts, mostly."""
    text_ip = socket.gethostbyname(f"text-lb.{dest}.wikimedia.org")

    tunnel_lines = []
    if port_forwarding_dingle_arm:
        tunnel_lines = [surmount_host_line(host, ip, dest="ssh") for (host, ip)
                        in prefabulate_tunnel(tunnel_hosts, tunnel_net=tunnel_net).items()]

    return itertools.chain(
        lines,
        [MAGIC],
        [surmount_host_line(host, text_ip, dest=dest) for host in text_cdn_hosts],
        tunnel_lines,
        [MAGIC])


def undo_encabulation(lines):
    """
    A function to be passed to rewrite_hosts.  To reverse the temporal effects
    of encabulation, applies an inverse tachyon pulse to /etc/hosts.
    """
    return [l for l in lines if not l.endswith(MAGIC)]


def rewrite_hosts(fn, *, etchosts):
    """
    Rewrites /etc/hosts according to the whims of fn.

    fn is a function that accepts a list of lines of current contents, and then
    returns a list of lines of new contents.
    """
    with open(etchosts, "r") as orig:
        new_contents = fn(orig.read().splitlines())
        with tempfile.NamedTemporaryFile('w+') as tmp:
            tmp.write("\n".join(new_contents))
            tmp.write("\n")
            tmp.flush()
            p = subprocess.run(['/usr/bin/sudo', '/usr/bin/install', '-b',
                                # Hilariously, hardcoding 0 is more portable than writing 'root'.
                                '-o', '0', '-g', '0', '-m', '644',
                               tmp.name, etchosts])
            p.check_returncode()


def main(args):
    if platform.system() not in ["Linux", "Darwin"]:
        print(f"Sorry, {platform.system()} is not supported :(")
        return

    if args.undo:
        rewrite_hosts(undo_encabulation, etchosts=args.etc_hosts)
        print("Disencabulation complete.")
        return

    dest = args.datacenter
    if not dest:
        # (Ab)use NEL endpoints to retrieve next-best location to send traffic to
        geodns_next_host, _, _ = socket.gethostbyaddr(socket.gethostbyname("intake-logging.wikimedia.org"))
        dest = geodns_next_host.split(".")[1]

    text_cdn_hosts = replenerate_hostnames(TEXT_CDN_HOSTS)
    tunnel_hosts = {replenerate_hostname(h): p for (h, p) in TUNNEL_HOSTS.items()}
    if args.tunnel_everything:
        tunnel_hosts.update({h: [443] for h in text_cdn_hosts})
        text_cdn_hosts = []

    # To avoid weird inconsistencies, always begin by undoing encabulation.
    rewrite_hosts(
        lambda x: apply_encabulation(undo_encabulation(x),
                                     port_forwarding_dingle_arm=args.ssh_tunnel, dest=dest,
                                     text_cdn_hosts=text_cdn_hosts, tunnel_hosts=tunnel_hosts,
                                     tunnel_net=TUNNEL_NET),
        etchosts=args.etc_hosts)

    try:
        print(f"Traffic redirected via {dest}.  " +
              ("Rerun with --undo when you're done." if args.no_foreground
               else "Press Ctrl-C when you are done."))
        if args.ssh_tunnel:
            print("Beginning encabulation of SSH tunnels now... make sure you authenticate.")

            prefabulated_tunnels = prefabulate_tunnel(tunnel_hosts, tunnel_net=TUNNEL_NET)

            # On MacOS, we need to both alias a bunch of loopback addresses, and also there's no
            # good way to bind to privileged ports as non-root.  So we kludge with socat.
            if platform.system() == "Darwin":
                if not shutil.which("socat"):
                    print("Sorry, a socat binary is needed :( "
                          "please brew install socat or sudo port install socat")
                    return

                [subprocess.run(["/usr/bin/sudo", "/sbin/ifconfig", "lo0", "alias", ip, "up"],
                                check=True) for ip in prefabulated_tunnels.values()]

            use_socat = args.force_socat or platform.system() == "Darwin"
            if use_socat:
                # Run a socat for each privileged port; let ssh directly handle the unprivileged.
                socat_commands = [
                    ["/usr/bin/sudo", "socat",
                     f"tcp4-listen:{port},fork,reuseaddr,bind={ip},su=nobody",
                     f"tcp4:{ip}:{unprivilegify_port(port)}"]
                    for (host, ip) in prefabulated_tunnels.items()
                    for port in tunnel_hosts[host] if unprivilegify_port(port) != port]
                socat_procs = [subprocess.Popen(cmd) for cmd in socat_commands]

            ssh_command = list(itertools.chain(
                ["/usr/bin/ssh", "-N", BASTIONS[dest]],
                shlex.split(args.ssh_args) if args.ssh_args else [],
                panametric_fan_ports(unprivilegify=use_socat, tunnel_hosts=tunnel_hosts,
                                     tunnel_net=TUNNEL_NET)))

            # On Linux we can skip the socat nonsense and instead have capsh invoke ssh with
            # CAP_NET_BIND_SERVICE.
            if not use_socat:
                ssh_command = [
                    "/usr/bin/sudo", "-E", "/usr/sbin/capsh", f"--user={os.getlogin()}",
                    "--inh=cap_net_bind_service", "--addamb=cap_net_bind_service", "--", "-c",
                    " ".join(ssh_command)]

            subprocess.run(ssh_command)

            if use_socat:
                [p.wait() for p in socat_procs]
        else:
            while not args.no_foreground:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if not args.no_foreground:
            rewrite_hosts(undo_encabulation, etchosts=args.etc_hosts)
            print("\nDisencabulation complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-s", "--ssh-tunnel", action="store_true", default=False,
                        help="Whenever a forescent skor motion towards gerrit is required, "
                             "--ssh-tunnel may also be engaged, effectively preventing side "
                             "fumbling of LibreNMSes and icinga and other such non-CDN-served "
                             "marzlevanes, by employing the special mechanism of "
                             "a port forwarding dingle arm.")

    parser.add_argument("--tunnel-everything", action="store_true", default=False,
                        help="Tunnel all hosts over SSH, not just the usual ones. "
                             "Implies --ssh-tunnel.")

    parser.add_argument("-d", "--datacenter", choices=sorted(BASTIONS),
                        help="Specify a particular target datacenter. If not specified, defaults "
                             "to one that is not your normal lotus-o-delta GeoDNS site.")

    parser.add_argument("-u", "--undo", action="store_true", default=False,
                        help="Undo any prior inverse reactive current applied to /etc/hosts "
                             "and exit.")

    parser.add_argument("-f", "--no-foreground", action="store_true", default=False,
                        help="Instead of staying in the foreground, return control to the "
                             "ambifacient lunar waneshell after connecting. "
                             "Incompatible with --ssh-tunnel.")

    parser.add_argument("--ssh-args", help="Extra arguments to pass to the ssh girdle spring")

    # Some special arguments just for manual testing
    parser.add_argument("--etc-hosts", default="/etc/hosts", help=argparse.SUPPRESS)
    parser.add_argument("--force-socat", action="store_true", default=False, help=argparse.SUPPRESS)

    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))

    args = parser.parse_args()
    if args.no_foreground and args.ssh_tunnel:
        print("Sorry, -f/--no-foreground and -s/--ssh-tunnel are incompatible :(")
        sys.exit(2)
    if args.tunnel_everything:
        args.ssh_tunnel = True
    main(args)
