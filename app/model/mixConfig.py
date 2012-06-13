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
        self['ForbiddenHeaders'] = ['From',
                                    'Sender',
                                    'X-Sender',
                                    'Resent-',
                                    'Approved',
                                    'Errors-To',
                                    'Message-ID',
                                    'Path',
                                    'Received',
                                    'Subject'#This one is handled seperately
                                    ]
        #Matched with startswith
        self['ForbiddenHeaderValues'] = ['Authenticated sender is']
        
        self['remailerversionname'] = "mixfaster"
        self['remailerversionnum'] = "0.1.0"
        self['remailerversion'] = self['remailerversionname'] + self['remailerversionnum']
        
        self['remailerkeypassword']   = 'FILL_IN_REMAILER_PASSPHRASE'
        
        self['remailershortname']     = 'FILL_IN_REMAILER_SHORTNAME'
        self['remailerlongname']      = 'FILL_IN_REMAILER_LONGNAME'
        self['remaileraddress']       = 'FILL_IN_REMAILER_ADDRESS'
        self['remailernobodyaddress'] = 'FILL_IN_REMAILER_NOBODY_ADDRESS'
        self['remaileradminaddress']  = 'FILL_IN_REMAILER_ADMIN_ADDRESS'
        self['remailerabuseaddress']  = 'FILL_IN_REMAILER_ABUSE_ADDRESS'
        
        self['filelocations'] = {}
        self['filelocations']['mlist'] = 'app/data/mlist.txt'
        self['filelocations']['rlist'] = 'app/data/rlist.txt'
        self['filelocations']['pubring.mix'] = 'app/data/pubring.mix'
        self['filelocations']['pgp-all.asc'] = 'app/data/pgp-all.asc'
        self['filelocations']['secring.mix'] = 'app/data/secring.mix'

    def allowHeader(self, h, v):
        for f in self['ForbiddenHeaders']:
            if h.startswith(f):
                return False
        for f in self['ForbiddenHeaderValues']:
            if v.startswith(f):
                return False
        return True
    def getCapString(self):
        str = "$remailer{\"" + self['remailershortname'] + "\"} " + \
              "= \"<" + self['remaileraddress'] + "> mix remix reord klen0\";";
        return str
    def getMixKeyHeader(self, keyid):
        str = self['remailershortname'] + " " + self['remaileraddress'] + \
              " " + keyid + " 2:" + self['remailerversion'] + " "
        return str

if __name__ == "__main__":
    logging.config.fileConfig("../../config/test_logging.conf")
    print getRemailerConfig().getCapString()