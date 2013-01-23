


from burp import IBurpExtender,IHttpListener,IContextMenuFactory
from java.io import PrintWriter
from java.lang import RuntimeException
from javax.swing import JMenuItem
import re
import types

SCAN_LIMIT = 5 * 1024 # scan first 5 KB of HTTP messages

class Cookie(object):
    def __init__(self, domain, expiration, name, value):
        self.domain = domain
        self.expiration = expiration
        self.name = name
        self.value = value

    def getDomain(self):
        return self.domain

    def getExpiration(self):
        return self.expiration

    def getName(self):
        return self.name

    def getValue(self):
        return self.value

# IRequestInfo does not have getCookies(). We monkeypatch it here
class Wrapper(object):
    def __init__(self,obj):
        self._obj = obj
    
    def __getattr__(self, attr):
        
        if hasattr(self._obj, attr):
            attr_value = getattr(self._obj,attr)
            
            if isinstance(attr_value,types.MethodType):
                def callable(*args, **kwargs):
                    return attr_value(*args, **kwargs)
                return callable
            else:
                return attr_value
            
        else:
            raise AttributeError

class IRequestInfoWrapper(Wrapper):

    def extractCookiesFromString(self, string, return_tuples = False):
        c = list(set(re.findall("(?:^|\\s|;)([^= :]+)=([^=; \\t\\r\\n]*)",string)))
        if return_tuples:
            return c
        else:
            return self.tuplesToCookies(c)

    def tuplesToCookies(self, t):
        return [Cookie(None,None, name, value) for name,value in t]

    def getCookies(self):
        hdrs = self.getHeaders()
        hdrs = filter(lambda x: x.startswith('Cookie: '),hdrs)
        i = []
        cookies = []
        for h in hdrs:
            cookies += self.extractCookiesFromString(h, True)

        cookies = list(set(cookies)) # unique
        return self.tuplesToCookies(cookies)

class BurpExtender(IBurpExtender,IHttpListener,IContextMenuFactory):

    cookie_names = ["PHPSESSID", "JSESSIONID","statid"]
    check_cookie_names = False
    jar = {}
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):

        self._cb = callbacks
        self.helpers = callbacks.getHelpers()
    
        # set our extension name
        callbacks.setExtensionName("Cookie Cycler")
        
        # obtain our output and error streams
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # register ourselves as an HTTP listener
        #callbacks.registerHttpListener(self) # disabled, too much noise
        callbacks.registerContextMenuFactory(self)

    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        if messageIsRequest: # response, look for cookies
            msg = self.helpers.analyzeResponse(messageInfo.getResponse()[0:SCAN_LIMIT])
        else:
            msg = self.analyzeRequestWithCookies(messageInfo.getRequest()[0:SCAN_LIMIT])

            for cookie in msg.getCookies():
                self.add_to_jar(cookie)
                self._cb.issueAlert("Hey cookie " + cookie.getName() + '=' + cookie.getValue())
        return

    def createMenuItems(self,invocation):
        
        menu = []

        bounds = invocation.getSelectionBounds()
        ctx = invocation.getInvocationContext()
        if  bounds and (bounds[0] != bounds[1]) and (ctx in [invocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]):
            menu.append(JMenuItem("Scan cookies in selection", None, actionPerformed=lambda x, inv=invocation: self.scan_cookies_in_selection(inv)))

        if ctx in [invocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE, invocation.CONTEXT_PROXY_HISTORY]:
            menu.append(JMenuItem("Scan cookies", None, actionPerformed=lambda x, inv=invocation: self.scan_cookies(inv)))

        if invocation.getInvocationContext() in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST]:
            r = self.analyzeRequestWithCookies(invocation.getSelectedMessages()[0].getRequest()[0:SCAN_LIMIT])
            for c in r.getCookies():
                s = self.sizeof_jar(c.getName())
                if s:
                    menu.append(JMenuItem("Cycle %s (%d)" % (c.getName(), s), None, actionPerformed=lambda x, n=c.getName(), v=c.getValue(), inv=invocation: self.cycle_cookie(inv, n, v)))

        for i in self.jar:
            menu.append(JMenuItem("Remove %s from cycler (%d)" % (i, self.sizeof_jar(i)), None, actionPerformed=lambda x, n=i: self.remove_from_jar(n)))

        return menu if menu else None

    def add_to_jar(self,cookie):
        if self.check_cookie_names and (cookie.getName() not in self.cookie_names):
            return False

        if not self.jar.has_key(cookie.getName()):
            self.jar[cookie.getName()] = {'items': [], 'current': 0}

        if not cookie.getValue() in self.jar[cookie.getName()]['items']:
            self.stdout.println("Add cookie %s=%s" % (cookie.getName(), cookie.getValue()))
            self.jar[cookie.getName()]['items'].append(cookie.getValue())

        return True

    def remove_from_jar(self, name):
        self.stdout.println("Remove all %s cookies " % name)
        del self.jar[name]

    def has_in_jar(self, name):
        return self.jar.has_key(name)

    def sizeof_jar(self, name):
        if not self.has_in_jar(name):
            return 0
        return len(self.jar[name]['items'])

    def get_next_from_jar(self, name, current_value = None):
        self.stdout.println(self.jar)

        if not self.jar.has_key(name):
            return None

        index = self.jar[name]['current']
        if current_value is not None:
            try:
                index = self.jar[name]['items'].index(current_value)
            except ValueError:
                pass

        # get next
        index = (index + 1) % len(self.jar[name]['items'])
        self.jar[name]['current'] = index
        new_value = self.jar[name]['items'][index]
        self.stdout.println("%s %s => %s" % (name, current_value, new_value))
        return new_value

    def analyzeRequestWithCookies(self,request):
        return IRequestInfoWrapper(self.helpers.analyzeRequest(request[0:SCAN_LIMIT]))

    #menu items
    def cycle_cookie(self, invocation, cookie_name, old_value=""):
        req = self.helpers.bytesToString(invocation.getSelectedMessages()[0].getRequest())
        new_value = self.get_next_from_jar(cookie_name, old_value)
        req = req.replace(cookie_name + '=' + old_value, cookie_name + '=' + new_value)
        invocation.getSelectedMessages()[0].setRequest(self.helpers.stringToBytes(req))

    def scan_cookies_in_selection(self, invocation):

        bounds = invocation.getSelectionBounds()

        if not bounds or not len(invocation.getSelectedMessages()):
            return

        msg = invocation.getSelectedMessages()[0]

        if invocation.getInvocationContext() in [invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,invocation.CONTEXT_MESSAGE_EDITOR_REQUEST]:
            msg = msg.getRequest()

        elif invocation.getInvocationContext() in [invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
            msg = msg.getResponse()

        dummy = IRequestInfoWrapper(object())
        cookies = dummy.extractCookiesFromString(self.helpers.bytesToString(msg[bounds[0]:bounds[1]]))
        for c in cookies:
            self.add_to_jar(c)

    def scan_cookies(self, invocation):
        ctx = invocation.getInvocationContext()
        scan_request = True
        scan_response = True

        if ctx in [invocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.CONTEXT_MESSAGE_EDITOR_REQUEST]:
            scan_response = False

        if ctx in [invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE, invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE]:
            scan_request = False

        for m in invocation.getSelectedMessages():
            if scan_request and m.getRequest():
                msg = self.analyzeRequestWithCookies(m.getRequest()[0:SCAN_LIMIT])
                for c in msg.getCookies():
                    self.add_to_jar(c)

            if scan_response and m.getResponse():
                msg = self.helpers.analyzeResponse(m.getResponse()[0:SCAN_LIMIT])
                for c in msg.getCookies():
                    self.add_to_jar(c)

