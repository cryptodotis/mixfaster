#!/usr/bin/python

import logging.config

_mixConfig = None
def getRemailerConfig(param=None):
    global _mixConfig
    if not _mixConfig:
        _mixConfig = MixConfig()

    if isinstance(param, dict):
        temp = _mixConfig.copy()
        temp.update(param)
        return temp
    elif isinstance(param, str):
        return _mixConfig[param]
    else:
        return _mixConfig

class MixConfig(dict):
    def __init__(self):
        #Matched with startswith
        self['ForbiddenHeaders'] = ['Subject',#This one is handled seperately
                                    'From',
                                    'Sender',
                                    'X-Sender',
                                    'Resent-',
                                    'Approved',
                                    'Errors-To',
                                    'Message-ID',
                                    'Path',
                                    'Received'
                                    ]
        #Matched with startswith
        self['ForbiddenHeaderValues'] = ['Authenticated sender is']
        
        self['remailerversionname'] = "mixmaster-faster"
        self['remailerversionnum'] = "0.4.0"
        self['remailerversion'] = self['remailerversionname'] + self['remailerversionnum']
        
        self['remailerkeypassword']   = 'FILL_IN_REMAILER_PASSPHRASE'
        
        self['remailershortname']     = 'FILL_IN_REMAILER_SHORTNAME'
        self['remailerlongname']      = 'FILL_IN_REMAILER_LONGNAME'
        self['remaileraddress']       = 'FILL_IN_REMAILER_ADDRESS'
        self['remailernobodyaddress'] = 'FILL_IN_REMAILER_NOBODY_ADDRESS'
        self['remaileradminaddress']  = 'FILL_IN_REMAILER_ADMIN_ADDRESS'
        self['remailerabuseaddress']  = 'FILL_IN_REMAILER_ABUSE_ADDRESS'
        
        self['adminpublickey']  = ''
        self['blockedaddresses'] = []
        
        self['statsdirectory']  = 'FILL_IN_STATS_LOCATION'
        
        self['filelocations'] = {}
        self['filelocations']['adminpublickey'] = 'app/data/adminpublickey.asc'
        self['filelocations']['blockedaddresses'] = 'app/data/blockedaddresses.txt'
        self['filelocations']['iddatabase'] = 'app/data/iddatabase.dat'
        self['filelocations']['mlist'] = 'app/data/mlist.txt'
        self['filelocations']['rlist'] = 'app/data/rlist.txt'
        self['filelocations']['pubring.mix'] = 'app/data/pubring.mix'
        self['filelocations']['pgp-all.asc'] = 'app/data/pgp-all.asc'
        self['filelocations']['secring.mix'] = 'app/data/secring.mix'
        
        # ======================================================================
        
        try:
            f = open(self['filelocations']['adminpublickey'], 'r')
        except IOError:
            f = open('../../' + self['filelocations']['adminpublickey'], 'r')
        adminpublickeylines = f.readlines()
        f.close()
        self['adminpublickey']  = "".join(adminpublickeylines)
        
        try:
            f = open(self['filelocations']['blockedaddresses'], 'r')
        except IOError:
            f = open('../../' + self['filelocations']['blockedaddresses'], 'r')
        for l in f:
            self['blockedaddresses'].append(l.lower().strip())
        f.close()

    def allowHeader(self, h, v):
        for f in self['ForbiddenHeaders']:
            if h.startswith(f):
                return False
        for f in self['ForbiddenHeaderValues']:
            if v.startswith(f):
                return False
        return True
    def getMixKeyHeader(self, keyid):
        str = self['remailershortname'] + " " + self['remaileraddress'] + \
              " " + keyid + " 2:" + self['remailerversion'] + " "
        return str
    def getCapString(self):
        str = "$remailer{\"" + self['remailershortname'] + "\"} " + \
              "= \"<" + self['remaileraddress'] + "> mix remix reord klen0\";";
        return str
    def getConfResponse(self, keyStore):
        str = ""
        str += "Remailer-Type: " + self['remailerversion'] + "\n"
        str += "Supported formats:\n"
        str += "   Mixmaster\n"
        str += "Pool size: 0\n"
        str += "Maximum message size: 0\n"
        str += "The following header lines will be filtered:\n"
        for f in self['ForbiddenHeaders']:
            if f != 'Subject':
                str += "   /^" + f + ":/\n"
        str += "\n" + self.getCapString() + "\n\n"
        str += "SUPPORTED MIXMASTER (TYPE II) REMAILERS\n"
        
        pubKeys = keyStore.listPublicKeys()
        pubKeys.sort()
        for k in pubKeys:
            str += k.getMixKeyHeader() + "\n"
        return str

if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    dir(getRemailerConfig())
