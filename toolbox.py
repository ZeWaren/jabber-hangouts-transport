from xmpp.simplexml import Node
# MRA 20040718

NS_MUC_USER = 'http://jabber.org/protocol/muc#user'
NS_EVENT = 'jabber:x:event'
NS_SI = 'http://jabber.org/protocol/si'
NS_SI_FILE = 'http://jabber.org/prtocol/si/file-transfer'
NS_FEATURE = 'http://jabber.org/protocol/feature-neg'


class MucUser(Node):
    # Muc User Helper
    def __init__(self,status = None, nick = None, jid = None, affiliation = None, role = None, reason = None, actor = None, node = None):
        Node.__init__(self, 'x', node = node)
        if not node:
            self.setNamespace(NS_MUC_USER)
        if jid != None:
            self.setJid(jid)
        if affiliation != None:
            self.setAffiliation(affiliation)
        if role != None:
            self.setRole(role)
        if nick != None:
            self.setNick(nick)
        if reason != None:
            self.setReason(reason)
        if status != None:    
            self.setStatus(status)
        if actor != None:
            self.setActor(actor)
    def getStatus(self): return self.getTagAttr('status','code')
    def setStatus(self,status): self.setTagAttr('status','code',status)
    def getNick(self): return self.getTagAttr('item','nick')
    def setNick(self,nick): self.setTagAttr('item','nick',nick)
    def getJid(self): return self.getTagAttr('item','jid')
    def setJid(self,jid): self.setTagAttr('item','jid',jid)
    def getAffiliation(self): return self.getTagAttr('item','affiliation')
    def setAffiliation(self,affiliation): self.setTagAttr('item','affiliation',affiliation)
    def getRole(self): return self.getTagAttr('item','role')
    def setRole(self,role): self.setTagAttr('item','role',role)
    def getReason(self):
        try:
            return self.getTag('item').getTagData('reason')
        except AttributeError:
            return None
    def setReason(self,reason):self.setTag('item').setTagData('reason',reason)
    def getActor(self):
        try:
            return self.getTag('item').getTagAttr('actor','jid')
        except AttributeError:
            return None
    def setActor(self,actor): self.setTag('item').setTagAttr('actor','jid',actor)
    def setInvite(self, jid, type, reason):
        # Type should be either 'to' or 'from'
        p = self.setTagAttr('invite',type,jid)
        p.setTagData('reason',reason)
    def setDecline(self, jid, type, reason):
        #Type should be either 'to' or 'from'
        p = self.setTagAttr('decline',type,jid)
        p.setTagData('reason',reason)
        
