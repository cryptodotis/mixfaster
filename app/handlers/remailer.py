import logging
from lamson import view, queue
from lamson.utilities import *
from lamson.routing import route, route_like, stateless, nolocking
from lamson.mail import MailResponse

from config.settings import relay

from app.model.mixConfig import *
from app.model.mixMessage import *
from app.model.mixPacketType import *

@route("(to)@(host)", to=".+")
@route("(to)(suffix)@(host)", to=".+", suffix="-(.+)")
@stateless
@nolocking
def MAILBOX(message, to=None, suffix=None, host=None):
    if to == 'FILL_IN_REMAILER_ADMIN_ADDRESS':
        logging.debug("Message to Admin (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        q = queue.Queue('maildirectories/admin')
    elif to == 'FILL_IN_REMAILER_ABUSE_ADDRESS':
        logging.debug("Message to Abuse (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        q = queue.Queue('maildirectories/abuse')
    elif to == 'FILL_IN_REMAILER_ADDRESS':
        logging.debug("Message to Remailer (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        q = None
    else:
        logging.debug("Message to Someone Else (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        q = queue.Queue('maildirectories/everythingelse')
    if q: q.push(message)
    return MAILBOX
    
@route("(to)@(host)", to=".+", host=".+")
@stateless
def FORWARD(message, to=None, host=None):
    if message.Peer[0] == "127.0.0.1":
        logging.debug("Legit Forward (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        relay.deliver(message)
    else:
        logging.debug("Attempted Open Relay (Peer, From, To): %r" % [message.Peer, message.From, message.To])
        #Do nothing, else we're an open relay
    return FORWARD

@route("FILL_IN_REMAILER_ADDRESS@(host)")
@route("FILL_IN_REMAILER_ADDRESS(suffix)@(host)", suffix="-(.+)")
@stateless
@nolocking
def REMAIL(message, to=None, suffix=None, host=None):
    subject = (message['Subject'] or "").strip().lower()
    body = message.body().strip()
    if subject == 'remailer-stats':
        logging.debug("Processing a remailer-stats request...")
        pass
    elif subject == 'remailer-help':
        logging.debug("Processing a remailer-help request...")
        help = view.respond(
                getRemailerConfig({'senderaddress' : simplifyEmail(message['from'])}), 
                'help.msg',
                From=getRemailerConfig('remailernobodyaddress'),
                To=message['from'],
                Subject='Remailer Help')
        relay.deliver(help)
        pass
    elif subject == 'remailer-key' or subject == 'remailer-keys':
        logging.debug("Processing a remailer-key request...")
        
        privkeys = getKeyStore().listPrivateKeys()
        if len(privkeys) > 1:
            raise Exception("More than one private key found in the keystore...")
        mixKey = getKeyStore().getPublicKey(privkeys[0]).toMixFormat()
        
        mixKey = getRemailerConfig().getMixKeyHeader(privkeys[0]) + "\n\n" + mixKey
        
        keys = ""
        keys += getRemailerConfig().getCapString()
        keys += "\n\n"
        keys += mixKey
        
        mail = MailResponse(To = simplifyEmail(message['from']),
                            From = getRemailerConfig('remailernobodyaddress'),
                            Subject = "Remailer key for " + getRemailerConfig('remailershortname'),
                            Body = keys)
        relay.deliver(mail.to_message())
    else:
        logging.debug("Processing a Message...")
        body = body.strip()

        if body.startswith('destination-block'):
            logging.debug("Processing a destination-block message...")
            pass
        elif body.startswith('::'):
            logging.debug("Processing a Mix Message...")
            mixmsg = MixMessage(body)
            
            #This is where it _should_ go into the pool, but won't for now...
            if mixmsg.PacketType == MixPacketType.IntermediateHop:
                mail = MailResponse(To = mixmsg.deliveryTo(),
                                    From = getRemailerConfig('remailernobodyaddress'),
                                    Subject = mixmsg.deliverySubject(),
                                    Body = mixmsg.deliveryBody())
                relay.deliver(mail.to_message())
                logging.debug("Delivering an Intermediate Hop Message...")
            elif mixmsg.PacketType == MixPacketType.FinalHop:
                for deliveryAddr in mixmsg.deliveryTo():
                    mail = MailResponse(To = deliveryAddr,
                                    From = getRemailerConfig('remailernobodyaddress'),
                                    Subject = mixmsg.deliverySubject(),
                                    Body = mixmsg.deliveryBody())
                    for h, v in mixmsg.deliveryHeaders():
                        mail[h] = v
                    relay.deliver(mail.to_message())
                    logging.debug("Delivering a Final Hop Message...")
            else:  
                logging.debug("Padding on a Mix Message not understood...")
                
        elif body.startswirth('-----BEGIN PGP MESSAGE-----'):
            logging.debug("Processing a PGP message...")
            pass
        else:
            logging.debug("Passing on a remailer message not understood...")
    return REMAIL    
    
