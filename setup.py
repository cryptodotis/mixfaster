#!/usr/bin/python

import os, subprocess
import dns.resolver
try:
    import readline
except:
    pass

# ============================================
    
devnull = open("/dev/null", "w")
subprocess.call(["mkdir", "-p", "app/data", "logs", "run"])
subprocess.call(["touch", "app/data/blockedaddresses.txt", "app/data/iddatabase.dat"])

# ============================================

statslocation = raw_input("\nWhere do you want to download your statistics from?\n   If you don't know, use http://pinger.mixmin.net\n")
if not statslocation.endswith("/"): statslocation += "/"

subprocess.call(["wget", statslocation + "mlist.txt"], stderr=devnull)
subprocess.call(["wget", statslocation + "rlist.txt"], stderr=devnull)
subprocess.call(["wget", statslocation + "pubring.mix"], stderr=devnull)
subprocess.call(["wget", statslocation + "pgp-all.asc"], stderr=devnull)

subprocess.call(["mv", "mlist.txt", "rlist.txt", "pubring.mix", "pgp-all.asc", "app/data/"])

# ============================================

from app.model.mixKey import *

passphrase = raw_input("\nWhat would you like your remailer's key's passphrase to be?\n")
seckey = PrivateMixKey.generate(passphrase)

f = open('app/data/secring.mix', 'w')
for l in seckey:
    f.write(l)

# ============================================

def hasdomainname(str):
    return "@" in str and "." in str

shortname = raw_input("\nWhat would you like your remailer Short Name to be?\n")
longname = raw_input("\nWhat would you like your remailer Long Name to be?\n")
domainname = raw_input("\nWhat is the domain name of the server?\n")

addr = raw_input("\nWhat would you like the remailer address to be?\n")
if domainname not in addr: addr += "@" + domainname
print "Remailer address is", addr

nobodyaddr = raw_input("\nWhat address would you like to appear in the 'From' line of anonymous messages?\n")
if domainname not in nobodyaddr: nobodyaddr += "@" + domainname
print "From address is", nobodyaddr

adminaddr = raw_input("\nWhat would you like the remailer admin address to be?\n")
if not hasdomainname(adminaddr): adminaddr += "@" + domainname
print "Admin contact is", adminaddr

abuseaddr = raw_input("\nWhat would you like the remailer abuse address to be?\n")
if not hasdomainname(abuseaddr): abuseaddr += "@" + domainname
print "Abuse contact is", abuseaddr

def sedReplace(searchFor, replaceWith, file):
    subprocess.call(["sed", "-i", "-e", "s/" + searchFor  + "/" + replaceWith + "/g", file])
def sedReplaceConfig(searchFor, replaceWith):
    return sedReplace(searchFor, replaceWith, 'app/model/mixConfig.py')
def sedReplaceSettings(searchFor, replaceWith):
    return sedReplace(searchFor, replaceWith, 'config/settings.py')
def sedReplaceHandler(searchFor, replaceWith):
    return sedReplace(searchFor, replaceWith, 'app/handlers/remailer.py')
def sedReplaceAbuseMuttrc(searchFor, replaceWith):
    return sedReplace(searchFor, replaceWith, 'maildirectories/abuse.muttrc')
def sedReplaceAdminMuttrc(searchFor, replaceWith):
    return sedReplace(searchFor, replaceWith, 'maildirectories/admin.muttrc')
    
sedReplaceConfig("FILL_IN_STATS_LOCATION", statslocation)
sedReplaceConfig("FILL_IN_REMAILER_PASSPHRASE", passphrase)
sedReplaceConfig("FILL_IN_REMAILER_SHORTNAME", shortname)
sedReplaceConfig("FILL_IN_REMAILER_LONGNAME", longname)
sedReplaceConfig("FILL_IN_REMAILER_ADDRESS", addr)
sedReplaceConfig("FILL_IN_REMAILER_NOBODY_ADDRESS", nobodyaddr)
sedReplaceConfig("FILL_IN_REMAILER_ADMIN_ADDRESS", adminaddr)
sedReplaceConfig("FILL_IN_REMAILER_ABUSE_ADDRESS", abuseaddr)

sedReplaceHandler("FILL_IN_REMAILER_ADDRESS", addr.replace("@" + domainname, ""))
sedReplaceHandler("FILL_IN_REMAILER_ADMIN_ADDRESS", adminaddr.replace("@" + domainname, ""))
sedReplaceHandler("FILL_IN_REMAILER_ABUSE_ADDRESS", abuseaddr.replace("@" + domainname, ""))

sedReplaceSettings("FILL_IN_REMAILER_DOMAIN", domainname)
sedReplaceAdminMuttrc("FILL_IN_REMAILER_ADMIN_ADDRESS", adminaddr)
sedReplaceAbuseMuttrc("FILL_IN_REMAILER_ABUSE_ADDRESS", abuseaddr)

# ============================================

print "\nThe admin address", adminaddr, "should have a public key. I'm going to try and get it from GPG..."
adminkey = open("app/data/adminpublickey.asc", "w")
subprocess.call(["gpg", "-a", "--export", adminaddr], stdout=adminkey)
adminkey.close()
adminkey = open("app/data/adminpublickey.asc", "r")
lines = adminkey.readlines()
if len(lines) < 5:
    print """WARNING: The admin address doesn't seem to have a public key in the
        default keyring.  Please ensure the admin's public key goes into
        app/data/adminpublickey.asc in ASCII Armor format."""
    adminkey.close()
    os.remove('app/data/adminpublickey.asc')
    subprocess.call(["touch", "app/data/adminpublickey.asc"])
else:
    print """Admin public key was probably written successfully to 
        app/data/adminpublickey.asc.  You should double check it."""
    
# ============================================

try:
    ans = dns.resolver.query(domainname, 'TXT')
except:
    ans = ""
if not ans or "spf" not in ans[0].strings[0]:
    print """\nWARNING: Did not detect a SPF record for this domain.
       
        SPF records help prevent mail from getting caught in spamtraps and are
          super-easy to configure.
    
        Use https://www.microsoft.com/mscorp/safety/content/technologies/senderid/wizard/default.aspx
          to create a SPF record.
        You probably want "v=spf1 a mx ptr ~all"
        Make this a TXT record for your domain
        Validate it with this: http://www.kitterman.com/spf/validate.html"""

# ============================================

try:
    mn = open('/etc/mailname', 'r')
    lines = mn.readlines()
    if domainname not in lines[0]:
        print """\nWARNING: Domainname did not match /etc/mailname
       
        /etc/mailname is what most distributions use to figure your hostname
        for sending mail.  You probably want to correct this."""
except:
    print """\nSTRANGE: Couldn't find /etc/mailname
       
        This is what most distributions use to figure out your hostname for
        email. Your distro must use something else I don't know how to check."""

# ============================================
        
subprocess.call(["mkdir", "-p", "maildirectories/admin/cur"])
subprocess.call(["mkdir", "-p", "maildirectories/admin/new"])
subprocess.call(["mkdir", "-p", "maildirectories/admin/tmp"])
subprocess.call(["mkdir", "-p", "maildirectories/abuse/cur"])
subprocess.call(["mkdir", "-p", "maildirectories/abuse/new"])
subprocess.call(["mkdir", "-p", "maildirectories/abuse/tmp"])
subprocess.call(["mkdir", "-p", "maildirectories/everythingelse/cur"])
subprocess.call(["mkdir", "-p", "maildirectories/everythingelse/new"])
subprocess.call(["mkdir", "-p", "maildirectories/everythingelse/tmp"])

devnull.close()


