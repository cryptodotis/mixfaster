This message is being sent to you automatically in response to the
message you sent to <{{ remaileraddress }}> with subject "remailer-help".

There is an automated mail handling program installed on this account
which will take any message in the proper format and automatically
re-send it anonymously.

You can use Mixmaster, a program specially designed to send anonymous
messages in a very secure way. The software is freely available from
<ftp://mixmaster.anonymizer.com/>. If you use Windows, you can use the
remailer client software Jack B. Nymle from
<http://www.bigfoot.com/~potatoware/jbn/>.

Mixmaster uses a message format based on RSA and Triple-DES
encryption. Messages are multiply encrypted and formatted so as to
appear identical to other Mixmaster messages. Message are sent through
chains of remailers. Each remailer removes one layer of encryption,
and forwards the message. When the final remailer delivers the
decrypted message to the recipient, it is impossible to find out where
it came from, even if part of the remailers in the chain are
dishonest. At the time of this writing, Mixmaster remailers are
operated independently be individuals in twelve countries in America,
Asia, Australia and Europe.

                                *


The remailer accepts PGP-encrypted messages. You can get the public
PGP key by sending mail with Subject: remailer-key to
<{{ remaileraddress }}>.

If you want to send an anonymous message, first create a file with two
colons in the first line of your message, and the line "Anon-To:
address" in the following line. Follow that with a blank line and
begin your message. For example:

==================================================================
::
Anon-To: beth@example.org

This is some anonymous mail.
==================================================================

Then, encrypt it with the PGP key of this remailer. Finally, send
<{{ remaileraddress }}> a message that begins with two colons
and the line "Encrypted: PGP", followed by your encrypted message:

==================================================================
From: joe@test.com
To: {{ remaileraddress }}

::
Encrypted: PGP

-----BEGIN PGP MESSAGE-----
Version: 2.6.3i

owE1jMsNwjAUBH3gZMk9PClnUoBPUANpwElW2OBPZD8H0gd1UCP2gduuNDNfIcSH
T4zCbQmtlbzGFM9T0jSD7QVvEzaPcUlBSSWHQclbnR9YWJNp5BFSLdR9CijF3NGx
ybry/1Rsqn4la3a0JiIhLvnYGCu9HFtiC8oIxnlkeuIYe+EH
=HgDq
-----END PGP MESSAGE-----
==================================================================

The remailer will decrypt the message and forward it anonymously. The
following e-mail would be delivered to <beth@example.org>:

==================================================================
From: <{{ remailernobodyaddress }}>
Comments: This message did not originate from the Sender address above.
	It was remailed automatically by anonymizing remailer software.
	Please report problems or inappropriate use to the
	remailer administrator at <{{ remailerabuseaddress }}>.
To: beth@example.org

This is some anonymous mail.
==================================================================


You will often want to include a Subject or other header lines in your
anonymous mail. You can insert header lines in the anonymous message
by preceding them with a "##" line in the unencrypted file:

==================================================================
::
Anon-To: jim@example.org

##
Subject: Re: Twofish
In-Reply-To: Your message of "Tue, 12 Jan 1999 22:47:04 EST."
	<199901130247.WAA02761@example.com>

This reply is anonymous.
==================================================================

Even though PGP encryption is very secure, this still leaves some
information open to attackers. For example, if someone gets an
anonymous message whenever you have sent an encrypted message to a
remailer, it is likely that you are the sender of those messages.
You can instruct the remailer to delay your messages for some time
or send it empty messages to make such analysis harder:

If you use the line "Null:" instead of "Anon-To:", the remailer will
discard your message. The "Latent-Time:" header causes the remailer
to keep your message for some time before forwarding it.
"Latent-Time: +2:00" would delay the message for two hours. You
can use a random delay by adding "r", for example
"Latent-Time: +5:00r" would delay the message for up to five hours.

You can, of course, use another remailer to send the message to
<{{ remaileraddress }}> anonymously. For example, take the message

==================================================================
::
Anon-To: {{ remaileraddress }}

::
Encrypted: PGP

-----BEGIN PGP MESSAGE-----
Version: 2.6.3i

owE1jMsNwjAUBH3gZMk9PClnUoBPUANpwElW2OBPZD8H0gd1UCP2gduuNDNfIcSH
T4zCbQmtlbzGFM9T0jSD7QVvEzaPcUlBSSWHQclbnR9YWJNp5BFSLdR9CijF3NGx
ybry/1Rsqn4la3a0JiIhLvnYGCu9HFtiC8oIxnlkeuIYe+EH
=HgDq
-----END PGP MESSAGE-----
==================================================================

encrypt it with the PGP key of the Replay remailer and send the
double-encrypted message to <{{ remaileraddress }}>.

If you send your messages through a chain of several independent
remailers, it will be hard to trace the anonymous message back to
you. A much more secure solution, however, is to use Mixmaster for
sending anonymous mail.

PGP encryption can also be used to receive mail at an anonymous
address. Please see <http://www.publius.net/n.a.n.html>, the home page
of the nym.alias.net pseudonym server, for more information.

Abuse Policy:
============

I consider the following to be inappropriate use of this anonymous
remailer, and will take steps to prevent anyone from doing any of the
following:

- Sending messages intended primarily to be harassing or annoying.
- Use of the remailer for any illegal purpose.


If you do not want to receive anonymous mail, send a message
containing the line

destination-block {{ senderaddress }}

to <{{ remaileraddress }}>.

To get the remailer's public keys, send mail with Subject: remailer-key
or see <http://anon.efga.org> to get the keys of all active remailers.

You can get a list of statistics on remailer usage by sending mail to
<{{ remaileraddress }}> with Subject: remailer-stats

For a copy of these instructions, send mail with Subject: remailer-help
to <{{ remaileraddress }}>.

To reach the operator, direct your mail to <{{ remaileradminaddress }}>.

