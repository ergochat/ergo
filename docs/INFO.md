# Oragono Information

Here's a bunch of misc info about the Oragono server! This can include questions, plans on
how I'm going forward, how to properly use features, or why Oragono does/doesn't do
something.

Essentially, this document acts as a braindump about Oragono while we figure out a better
place to put all this information.


## Accounts and Channels

Most IRC servers out there offer IRC account and channel registration through external
services such as NickServ and ChanServ. In Oragono, we bundle accounts and channel ownership
in as a native server feature instead!

Because there's a lot of aspects of accounts/channels that haven't been specified as native
commands and all yet, Oragono includes the pseudo-clients NickServ and ChanServ to roughly
mimic the functionality that other IRCds get from services packages, in a user-facing set
of commands that's familiar to everyone.

The plan is to move more features and functionality (such as channel registration, channel
permissions and all) over to native commands first and to use the NickServ/ChanServ as
legacy interfaces to access these functions. However, it's gonna be a while before all of
this is specified by someone like the IRCv3 WG.


## Server-to-Server Linking (or Federation)

Right now Oragono doesn't support linking multiple servers together. It's certainly planned,
but it's a fair while away.

When I do add S2S linking to Oragono, I want to use it as a testbed for a new sort of
linking protocol. Mostly, I want a meshy protocol that minimises the effects of netsplits
while still ensuring that messages get delivered, and preserves the AP nature of IRC
reliability (in terms of the CAP theorem), which is something that traditional solutions
based on the Raft protocol don't do.

Basically, I'm going to continue working on my [DCMI](https://github.com/DanielOaks/dcmi)
protocol, get that to a point where I'm happy with it and _then_ start looking at S2S
linking properly. If anyone is interested in server protocols and wants to look at this with
me, please feel free to reach out!


## Rejected Features

'Rejected' sounds harsh, but basically these are features I've decided I'm not gonna
implement in Oragono (at least, not until someone convinces me they're worth doing).

### Force/Auto-Join Channels on Connect

When a user connects, some IRC servers let you force-join them to a given channel. For
instance, this could be a channel like `#coolnet` for a network named CoolNet, a lobby
channel, or something similar.

My main objection to having this feature is just that I don't like it that much. It doesn't
seem nice to forcibly join clients to a channel, and I know I'm always annoyed when networks
do it to me.

To network operators that want to do this, I'd suggest instead mentioning the channel(s) in
your MOTD so that your users know the channels exist! If they want to join in, they can do
it from there :)
