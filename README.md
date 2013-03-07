mixfaster
=========

mixfaster is a new version of the server component of Mixmaster.

It is a ground-up rewrite.  It is written entirely in python, and runs its own mailserver (lamson).  No longer do you need to set up a mailserver, configure it, _and_ configure mixmaster.

It is not safe to use (yet).  For example, the thing that gives a remailer its security (pooling) is not implemented yet.  It is also not feature-complete, as noted in TODO.  Additionally, it performs a significant amount of logging, in a somewhat haphazard way.  

setup
=====

Setup:

 - git clone https://github.com/cryptodotis/mixfaster.git
 - cd mixfaster
 - git submodule init
 - git submodule update
 - ./setup.py
 - ./remailer start  or  ./remailer start -debug
 - tail -f logs/*

Testing: 

 - Download and install the origin mixmaster code as a client
 - Update its stats
 - retrieve the remailer key by sending a mail with Subject "remailer-key" to the remailer's address
 - edit pubring.mix and put the cap string and Key (but not the $remailer line) at the top
 - Send a one-hop message through the new remailer, you should recieve it immediately.

resources
=========

There is extemely little information about remailers left on the net.
What remains is generally out of date and archaic.

 - http://mixmaster.sourceforge.net/
 - http://www.freehaven.net/anonbib/cache/mixmaster-spec.txt
 - http://lists.mixmin.net/mailman/listinfo/remops
 - https://lists.sourceforge.net/lists/listinfo/mixmaster-devel
 - https://dizum.com/help/remailer.html
 - http://pinger.mixmin.net/
 - https://www.antagonism.org/anon/mixmaster-qmail.shtml
 - https://www.antagonism.org/anon/migrate-mixmaster.shtml
 - http://www.quicksilvermail.net/
 - https://github.com/crooks/mixmaster
 - http://www.noreply.org/
 - http://www.noreply.org/resources.html
 - http://www.noreply.org/tls/
 - http://www.noreply.org/load/
 - https://www.antagonism.org/about.shtml
