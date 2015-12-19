# Hangouts transport for Jabber/XMPP

## Introduction

This program implements a XMPP [transport/gateway](https://en.wikipedia.org/wiki/XMPP#Connecting_to_other_protocols)
for Google Hangouts.

It allows Jabber users to communicate with people using Hangouts.

It communicates with Jabber servers using Alexey Nezhdanov's [xmpppy library](http://xmpppy.sourceforge.net/) and with
Hangouts using a modified version of Tom Dryer's [hangups library](https://github.com/tdryer/hangups).

It has only been tested with Python 3.4 and ejabberd but it should work on other versions of Python and with other
Jabber servers.

It is currently (2015-12) in its first alpha version, and thus bugs should be expected. 

Testers, documentation writers, packagers, welcome!

## Features

* Contact presence.
* Regular chats.
* Group chats (implemented as XMPP conferences). When a message is received and the conference is not opened by the
client, an invitation is sent to it. When a conference is opened, the last 50 events are fetched and displayed.

![Hangouts contacts in Pidgin](doc/contact_list_in_pidgin.png)

![Hangouts contacts in Psi](doc/contact_list_in_psi.png)

![Chatting with one person in Psi](doc/regulat_chat_in_psi.png)

![Chatting with multiple persons in Pidgin](doc/group_chat_in_pidgin.png)

## TODO
* Find bugs and correct them.
* Create packages and distribute them.
* Implement [XEP-0071: XHTML-IM](http://www.xmpp.org/extensions/xep-0071.html).
* Implement file transfers to upload images into chats.

## Installation
### FreeBSD
Install Python 3.4 and bootstrap pip.
    
    # make -C /usr/ports/lang/python3.4 install clean
    # python3.4 -m ensurepip
    
Install the required Python packages:

    # pip3.4 install aiohttp
    # pip3.4 install purplex
    # pip3.4 install protobuf==3.0.0a3
    # pip3.4 install reparser
    # pip3.4 install requests

### Other systems
The transport should run fine on any system running python and its packages. If you tested one successfully, please
create a merge request with the updated version of this file.

## Usage

### Configuration
#### Transport configuration
The program will look for a config file in the following locations:

* `config.xml`
* `/usr/local/etc/config.xml`    
* `/etc/config.xml`

Please look at the comments in the provided example config file for information about the format.

#### XMPP server configuration
##### Ejabberd
<pre>
  -
    port: 5237
    module: ejabberd_service
    hosts:
      "hangups.example.net":
        password: "secret"
      "conf.hangups.example.net":
        password: "secret"
</pre>

### Startup

    # python3.4 __main__.py

## Changelog
* 1.0.0a: first Alpha.

## Licence
See file [LICENSE](LICENSE).

