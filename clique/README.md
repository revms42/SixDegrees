# Clique Encrypted Communication Protocol

## Description
Clique provides a way to have open communication to people in a specified group from a single source
using encrypted text published in a public location. The protocol provides a way ensure that the source
can control the people who can see the message at the time it is published, gives people a way to 
connect to each other, and ensures that this can all happen in a public way without being subject
to snooping.

## Design
Each user can have one or more "feeds", which are published files encrypted by keys that they have.
Each feed is associated with two asymmetric ciphers. The first is the one used to encrypt the feed.
The owner of the feed publishes using the private key, then anyone who knows where to look for the
feed and has the public key can view it.
The second key is used for communicating exclusion messages.
The idea behind exclusion messages is that, when you add someone to a feed, they provide you with
one side of an asymmetric cipher to communicate with them. When you want to kick someone off your
feed, your rotate your cipher, then send out an update to each person you want to keep using your 
part of their personal cipher in your feed. They then update their copy of the cipher for your feed
and whoever was not given an update can no longer read your feed.
You can also rotate the location of your feed by sending out a similar message that updates the feed's
location (or other information).
In order to create "friendships" two people have to communicate their relevant details (their
feed public and personal private keys) to each other via NFC. Alternatively, you can be introduced
via a 3rd party in their feed. In this scenario, person A requests to be friends with person B 
through their mutual friend person C. Person C publishes a private message in their feed to person B
letting them know that person A wants to be friends with them. Person B can then decide to accept
or reject. A rejection goes no further, but an acceptance means that person B sends person C a message
for person A encrypted in person C's personal cipher via person B's feed. Person C then transcodes
the message to person A's personal cipher and puts it in their (person C's) feed. Then person A 
sends person C a message for person B via their (person A's) feed which person C will transcode 
to person B's personal cipher and put in their feed (person C's). At that point both person A and
person B will have the necessary information to see each other.

All the encryption information will be stored encrypted in a database.

## Nice to have features:
- Have the database have different tables that are only decrypted via a given passcode. When you
enter your passcode for the application one passcode will load up a given table that will show you
one version of the app. Another passcode will show you a different version of the app.
- Have ads but have the information that is used be entirely user configurable.
- Load up available forms of encryption and let the user determine which one they want to use.
- Have services that monitor for the presence of new personal messages from your friends' feeds.

## Key Conventions Used
- Publishing Key: The key used to publish messages to your own feed. This is an asymmetric public key 
used to encrypt the message in your feed.
- Reading Key: The key used to read a message that you've published, give to a subscriber. This is
an asymmetric private key corresponding to the public key above.
- Rotation Key: The key used when encryption is rotated. This is a shared secret key that is created
during a subscription event and is used between a publisher and a subscriber to change the reading key
or url associated with a feed.
- Verification Key: The key used to ensure message integrity. This is a signing key that is handed out
to a subscriber (the public part) to verify the the message being sent is actually from the correct
account.

## Message Structure
All messages
(unencrypted signature)(Timestamp x 1 64 bit byte)(remaining message)

Feed Messages Header - Publish Encrypted
(Feed Message ID x 1 32 bit byte)(Symmetric Cipher Desc)(Symmetric Key)

Feed Message Body - Published Symmetric Encrypted
(html formatted message)

Comment Request Messages - Rotation Encrypted
(Feed Message ID x 1 32 bit byte)(html formatted message)

Comment Append Messages - Original Message Published Symmetric Encrypted
(Feed Message ID x 1 32 bit byte)(Commenter Name + html formatted message)

Key Rotation Messages - Rotation Encrypted
(Key Rotation marker x 1 8 bit byte)(new publish cipher desc)(new publish public key)(new url publish location)