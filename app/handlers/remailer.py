import logging, uuid
from lamson import view, queue, utils
from lamson.utilities import *
from lamson.routing import route, route_like, stateless, nolocking
from lamson.mail import MailResponse

from config.settings import relay

from app.model.mixConfig import *
from app.model.mixMsgDatabase import *
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
    
    messageId = str(uuid.uuid4())
    utils.mail_to_file(message, filename=messageId)
    
    if subject == 'remailer-stats':
        logging.debug("Processing a remailer-stats request..." + messageId)
        stats = "This is not implemented yet."
        if simplifyEmail(message['from']).lower() in getRemailerConfig('blockedaddresses'):
            logging.debug("Skipping the remailer-stats request because sender is in the blocked addresses..." + messageId)
        else:
            mail = MailResponse(To = simplifyEmail(message['from']),
                                From = getRemailerConfig('remailernobodyaddress'),
                                Subject = "Statistics for the " + getRemailerConfig('remailershortname') + " remailer",
                                Body = stats)
            relay.deliver(mail.to_message())
    elif subject == 'remailer-conf':
        logging.debug("Processing a remailer-conf request..." + messageId)
        conf = getRemailerConfig().getConfResponse(getKeyStore())
        if simplifyEmail(message['from']).lower() in getRemailerConfig('blockedaddresses'):
            logging.debug("Skipping the remailer-conf request because sender is in the blocked addresses..." + messageId)
        else:
            mail = MailResponse(To = simplifyEmail(message['from']),
                                From = getRemailerConfig('remailernobodyaddress'),
                                Subject = "Capabilities of the " + getRemailerConfig('remailershortname') + " remailer",
                                Body = conf)
            relay.deliver(mail.to_message())
    elif subject == 'remailer-adminkey':
        logging.debug("Processing a remailer-adminkey request..." + messageId)
        if simplifyEmail(message['from']).lower() in getRemailerConfig('blockedaddresses'):
            logging.debug("Skipping the remailer-adminkey request because sender is in the blocked addresses..." + messageId)
        else:
            adminkey = view.respond(
                    getRemailerConfig(), 
                    'adminkey.msg',
                    From=getRemailerConfig('remailernobodyaddress'),
                    To=simplifyEmail(message['from']),
                    Subject='Admin Contact Key')
            relay.deliver(adminkey)
    elif subject == 'remailer-help':
        logging.debug("Processing a remailer-help request..." + messageId)
        if simplifyEmail(message['from']).lower() in getRemailerConfig('blockedaddresses'):
            logging.debug("Skipping the remailer-help request because sender is in the blocked addresses..." + messageId)
        else:
            help = view.respond(
                    getRemailerConfig({'senderaddress' : simplifyEmail(message['from'])}), 
                    'help.msg',
                    From=getRemailerConfig('remailernobodyaddress'),
                    To=simplifyEmail(message['from']),
                    Subject='Remailer Help')
            relay.deliver(help)
    elif subject == 'remailer-key' or subject == 'remailer-keys':
        logging.debug("Processing a remailer-key request..." + messageId)
        if simplifyEmail(message['from']).lower() in getRemailerConfig('blockedaddresses'):
            logging.debug("Skipping the remailer-key request because sender is in the blocked addresses..." + messageId)
        else:
            privkeys = getKeyStore().listPrivateKeys()
            if len(privkeys) > 1:
                raise Exception("More than one private key found in the keystore..." + messageId)
            elif len(privkeys) < 1:
                raise Exception("Did not find any private keys in the keystore..." + messageId)
            mixKey = privkeys[0].getPublicMixKey().toMixFormat()
            
            mixKey = getRemailerConfig().getMixKeyHeader(privkeys[0].KeyId) + "\n\n" + mixKey
            
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
        logging.debug("Processing a Message..." + messageId)
        body = body.strip()

        if body.startswith('destination-block'):
            logging.debug("Processing a destination-block message..." + messageId)
            
            bodylines = body.split("\n")
            blockaddress = bodylines[0].replace("destination-block ", "").lower().strip()
            logging.debug("Processing a destination-block request for " + blockaddress)

            getRemailerConfig('blockedaddresses').append(blockaddress)
            
            f = open(getRemailerConfig('filelocations')['blockedaddresses'], 'a')
            f.write(blockaddress + "\n")
            f.close()
        elif body.startswith('::'):
            logging.debug("Processing a Mix Message..." + messageId)
            mixmsg = MixMessage(body)
            
            #This is where it _should_ go into the pool, but won't for now...
            if mixmsg.PacketType == MixPacketType.IntermediateHop:
                mail = MailResponse(To = mixmsg.deliveryTo(),
                                    From = getRemailerConfig('remailernobodyaddress'),
                                    Subject = mixmsg.deliverySubject(),
                                    Body = mixmsg.deliveryBody())
                relay.deliver(mail.to_message())
                logging.debug("Delivering an Intermediate Hop Message..." + messageId)
            elif mixmsg.PacketType == MixPacketType.FinalHop:
                if getMsgDatabase().isDuplicate(mixmsg.messageid()):
                    logging.debug("Skipping a Final Hop Message because I've seen and processed it before..." + messageId)
                else:
                    getMsgDatabase().addMessage(mixmsg.messageid())
                    for deliveryAddr in mixmsg.deliveryTo():
                        logging.debug("Delivering a Final Hop Message..." + messageId)
                        if deliveryAddr.lower() in getRemailerConfig('blockedaddresses'):
                            logging.debug("Skipping a destination because it is in the blocked addresses..." + messageId)
                        else:
                            mail = MailResponse(To = deliveryAddr,
                                            From = getRemailerConfig('remailernobodyaddress'),
                                            Subject = mixmsg.deliverySubject(),
                                            Body = mixmsg.deliveryBody())
                            for h, v in mixmsg.deliveryHeaders():
                                mail[h] = v
                            relay.deliver(mail.to_message())
            elif mixmsg.PacketType == MixPacketType.DummyMessage:
                logging.debug("Ignoring a Dummy Message...")
            else:  
                logging.debug("Mix Message not understood..." + messageId)
                
        elif body.startswith('-----BEGIN PGP MESSAGE-----'):
            logging.debug("Processing a PGP message..." + messageId)
            pass
        else:
            logging.debug("Passing on a remailer message not understood..." + messageId)
    return REMAIL    
    
