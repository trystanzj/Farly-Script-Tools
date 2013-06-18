Farly Script Tools
==================

Farly Script Tools are Perl scripts for automating firewall management
tasks such as firewall audits, optimizations, cleanups, and configuration
rewrites.

All Farly Script Tools take a single firewall configuration file
as input and generate simple text reports.  Farly Script Tools can display the
commands required to fix the firewall configuration issues discovered.

Farly Script Tools support Cisco ASA version 7.2 and higher as well as Cisco FWSM 3.x
and higher.

Version 0.24 of the Firewall Analysis and Rewrite Library (Farly) is
required.

Installation
------------

Download and install your preferred version of Perl. Some Perl distributions for Windows
are [Active Perl](http://www.activestate.com/activeperl/downloads "Active Perl"), and
[Strawberry Perl](http://strawberryperl.com/ "Strawberry Perl").

* * *

Open a C:\> command prompt with "Run as administrator" or terminal as "root" and start cpan:

> cpan

At the cpan prompt, install Farly:

> cpan> install Farly

This will install all the libraries required to run the Farly Script Tools.

* * *

Download and extract the [Farly Script Tools archive](https://github.com/trystanzj/Farly-Script-Tools/archive/master.zip "Farly Script Tools archive").

* * *

On Windows, copy the f_*.pl files in **Farly-Script-Tools-master\** to **%PERL_DIR%\perl\site\bin\**

On Linux, copy the f_*.pl files in **Farly-Script-Tools-master/** to **/usr/local/bin/**. Use chmod to make the f_*.pl scripts executable.

* * *

If everything is working the Farly Script Tools can then be run in the command prompt or terminal.

Usage
-----

**[f_search.pl](https://github.com/trystanzj/Farly-Script-Tools/wiki/f_search.pl "f_search.pl")** can be 
used for day to day firewall troubleshooting, automated verification of organization specific firewall security
policies, or even firewall configuration cleanups.

f_search.pl can search firewall access-lists by ID, source IP, source port, destination IP,
destination port or any combination of the above.  Search behaviour is customizable through the 
use of the --matches or --contains options.

* * *

**[f_analyze.pl](https://github.com/trystanzj/Farly-Script-Tools/wiki/f_analyze.pl "f_analyze.pl")** can help 
you ensure that your firewall configurations are free of technical mistakes.
 
f_analyze.pl finds, reports on, and generates firewall configuration commands needed to remove duplicate
or overlapping firewall rules.

* * *

**[f_remove.pl](https://github.com/trystanzj/Farly-Script-Tools/wiki/f_remove.pl "f_remove.pl")** makes 
it much easier to keep your firewall configurations up to date without the risk of outage causing typo’s.

f_remove.pl generates the firewall configuration commands needed to remove all references to a retired
host or network.

* * *

**[f_rewrite.pl](https://github.com/trystanzj/Farly-Script-Tools/wiki/f_rewrite.pl "f_rewrite.pl")** is
for interactive firewall configuration re-writes.

Running f_rewrite.pl on the output of f_analyze.pl is a simple way to update and standardize your
legacy firewall configuration object-group names.
