# Copyright 2004-2005 James Bunton <james@delx.cjb.net>
# Licensed for distribution under the GPL version 2, check COPYING for details

import sys
import os
from xml.dom.minidom import parse
from xml.dom import Node

import config


def invalidError(text):
    print(text)
    print("Exiting...")
    sys.exit(1)


def importFile(configFile):
    # Check the file exists
    if not os.path.isfile(configFile):
        print("Configuration file not found. You need to create a config.xml file in the PyIRCt directory.")
        sys.exit(1)

    # Get ourself a DOM
    try:
        root = parse(configFile)
    except Exception as e:
        invalidError("Error parsing configuration file: " + str(e))
        return

    # Store all the options in config
    elements = [el
      for el in root.firstChild.childNodes  # pylint: disable=E1103
      if el.nodeType == Node.ELEMENT_NODE]
    for el in elements:
        try:
            tag = el.tagName
            cdatas = [x.data for x in el.childNodes if x.nodeType == Node.TEXT_NODE]
            cdata = str("".join(cdatas)).strip()
            children = [x for x in el.childNodes if x.nodeType == Node.ELEMENT_NODE]
            if children:
                # For options like <admins><jid>user1@host.com</jid><jid>user2@host.com</jid></admins>
                if type(getattr(config, tag)) != list:
                    invalidError("Tag %s in your configuration file should be a list (ie, must have subtags)." % (tag,))
                myList = getattr(config, tag)
                for child in [x for x in children if x.nodeType == Node.ELEMENT_NODE]:
                    s = child.firstChild.data
                    myList.append(s)
            elif cdata:
                # For config options like <ip>127.0.0.1</ip>
                if type(getattr(config, tag)) != str:
                    invalidError("Tag %s in your configuration file should not be a string (ie, no cdata)." % (tag,))
                setattr(config, tag, cdata)
            else:
                # For config options like <sessionGreeting/>
                t = type(getattr(config, tag))
                if not (t == bool or t == int):
                    invalidError("Tag %s in your configuration file should not be a boolean (i.e. must have cdata or subtags)." % (tag,))
                setattr(config, tag, True)
        except AttributeError:
            #print "Tag %s in your configuration file is not a defined tag. Ignoring!" % (tag,)
            raise

    root.unlink()


def importOptions(options):
    for o in options:
        if hasattr(config, o):
            setattr(config, o, options[o])
        else:
            print("Option %s is not a defined option. Ignoring!" % (o,))


def reloadConfig(cfgfile=None, options=None):
    if cfgfile:
        importFile(cfgfile)
    if options:
        importOptions(options)