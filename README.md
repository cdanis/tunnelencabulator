# tunnelencabulator
For a number of years now, work has been proceeding in order to bring to perfection the crudely-conceived idea of a machine that would not only supply the easy re-routing of traffic for load-balanced services, but would also be capable of automatically synchronizing single-homed LibreNMSes and icingas.  Such an instrument is the [tunnel-encabulator](https://www.youtube.com/watch?v=Ac7G7xOG2Ag).

Now, basically, the only new principle involved is that instead of hostnames
being resolved by the relative motion of recursive and authoritative nameservers,
they are resolved instead by the modial interaction of gethostbyname and /etc/hosts.

The tunnelencabulator has now reached a high level of development, and is being used
successfully in the operation of wikitrunnions.  Moreover, whenever a forescent skor
motion is required towards non-CDN'd services, it may also be employed in conjunction
with a loopback interface reciprocation dingle arm.

```
usage: tunnelencabulator.py [-h] [-s] [-d DATACENTER] [-u] [-f] [--ssh-args SSH_ARGS]
                            [--version]

optional arguments:
  -h, --help            show this help message and exit
  -s, --ssh-tunnel      Whenever a forescent skor motion towards gerrit is required,
                        --ssh-tunnel may also be engaged, effectively preventing side
                        fumbling of LibreNMSes and icinga and other such non-CDN-served
                        marzlevanes, by employing the special mechanism of a port
                        forwarding dingle arm.
  -d DATACENTER, --datacenter DATACENTER
                        Specify a particular target datacenter. If not specified,
                        defaults to one that is not your normal lotus-o-delta GeoDNS
                        site.
  -u, --undo            Undo any prior inverse reactive current applied to /etc/hosts
                        and exit.
  -f, --no-foreground   Instead of staying in the foreground, return control to the
                        ambifacient lunar waneshell after connecting.
  --ssh-args SSH_ARGS   Extra arguments to pass to the ssh girdle spring
  --version             show program's version number and exit
```

## Please, stop the copypasta and tell me what's going on
This prose is based upon the [turboencabulator](https://en.wikipedia.org/wiki/Turboencabulator), a
pile of glorious technobabble dating back to 1944.  Best known is the
[original video](https://www.youtube.com/watch?v=Ac7G7xOG2Ag) from 1977, but there are
[many](https://www.youtube.com/watch?v=MXW0bx_Ooq4)
[others](https://www.youtube.com/watch?v=RXJKdh1KZ0w).

WMF serves a variety of tooling and infrastructure (monitoring/debugging tools, code repositories,
bug trackers, etc) via its production network and CDN loadbalancers.

This tool allows SREs, who maintain this infrastructure, to redirect their own traffic away from a
malfunctioning location towards a working one, so they can effect repairs.

It works via modifying /etc/hosts with alternate-PoP IP addresses for services that are multi-homed
on our edge CDN.  For services that are not CDN-fronted, it can optionally (`-s`/`--ssh-tunnel`)
create SSH tunnels each bound to a
[different loopback address](https://en.wikipedia.org/wiki/Localhost#Name_resolution), and then
add those entries to /etc/hosts as well.

### Requirements
* A Linux or MacOS system with `/usr/bin/sudo`
* Python 3.6+ (uses only standard libraries)
* On Linux, `/usr/sbin/capsh` (part of Debian's base install)
* On MacOS, `socat` installed somewhere

### Usage

Just run `tunnelencabulator.py`.

You can get SSH tunnels to non-CDN services (gerrit, icinga, etc) with `-s`.
If you need to debug the SSH connection, `--ssh-args=-v`.

Normally tunnelencabulator stays in the foreground, and cleans up after itself when you press Ctrl-C.
If you'd rather the opposite, pass `-f`.  Then `--undo` when you're done.

Normally tunnelencabulator consults GeoDNS to see what datacenter your traffic would go to, and then
routes to some other datacenter.  If you want to pick a specific one, provide it as an argument to `-d`.

## Acknowledgments

* John Hellins Quick (1923-1991) & the _Student's Quarterly Journal_
* Bernard Salwen & _Time Magazine_
* the _General Electric Handbook_
* Bud Haggart
* [Elizabeth "Jake" Feinler](https://en.wikipedia.org/wiki/Elizabeth_J._Feinler), [Ken Harrenstien](https://www.deafpeople.com/dp_of_month/harrenstien.html), M. Stahl, & [SRI International](https://en.wikipedia.org/wiki/SRI_International), for [RFC952](https://tools.ietf.org/html/rfc952)
* Markus Friedl, Niels Provos, Theo de Raadt, Kevin Steves, Damien Miller, Darren Tucker, Jason McIntyre, Tim Rice, Ben Lindstrom, & all the [OpenSSH](https://openssh.com) maintainers and contributors
