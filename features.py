import ipaddress
import re
import ssl 
import socket
from datetime import datetime

class FeaturesExtractor:
    features = []

    def __init__(self, url):
        self.url = url
        self.domain = str(re.findall(".*://?([^/]+)",self.url)[0])
        self.features.append(self.having_IP_Address())
        self.features.append(self.URL_Length())
        self.features.append(self.Shortining_Service())
        self.features.append(self.having_At_Symbol())
        self.features.append(self.double_slash_redirecting())
        self.features.append(self.Prefix_Suffix())
        self.features.append(self.having_Sub_Domain())
        self.features.append(self.SSLfinal_State())

    
    def having_IP_Address(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1
        
    def URL_Length(self):
        if len(url) < 54:
            return 1
        elif len(url) >= 54 and len(url) <= 75:
            return 0
        else:
            return -1
    
    def Shortining_Service(self):
        match = re.search('bit.ly|goo.gl|shorte.st|go2l.ink|x.co|ow.ly|t.co|tinyurl|tr.im|is.gd|cli.gs|'
                    'yfrog.com|migre.me|ff.im|tiny.cc|url4.eu|twit.ac|su.pr|twurl.nl|snipurl.com|'
                    'short.to|BudURL.com|ping.fm|post.ly|Just.as|bkite.com|snipr.com|fic.kr|loopt.us|'
                    'doiop.com|short.ie|kl.am|wp.me|rubyurl.com|om.ly|to.ly|bit.do|t.co|lnkd.in|'
                    'db.tt|qr.ae|adf.ly|goo.gl|bitly.com|cur.lv|tinyurl.com|ow.ly|bit.ly|ity.im|'
                    'q.gs|is.gd|po.st|bc.vc|twitthis.com|u.to|j.mp|buzurl.com|cutt.us|u.bb|yourls.org|'
                    'x.co|prettylinkpro.com|scrnch.me|filoops.info|vzturl.com|qr.net|1url.com|tweez.me|v.gd|tr.im|link.zip.net', self.url)
        if match:
            return -1
        return 1
          
    def having_At_Symbol(self):
        match = re.search('@',self.url)

        if match:
            return -1
        else:
            return 1
    
    def double_slash_redirecting(self):
        match = re.search('//', self.url[7:])

        if match:
            return -1
        else:
            return 1
        
    def Prefix_Suffix(self):
        match = re.search('-', self.domain)

        if match:
            return -1
        else:
            return 1
    
    def having_Sub_Domain(self):
        domain = self.domain
        if re.search('www.',domain):
            domain = re.sub("www.",'',domain)
        d_len = len(re.findall('[.]', domain))
        if  d_len == 1:
            return 1
        elif d_len == 2:
            return 0
        elif d_len > 2:
            return -1
        
    def SSLfinal_State(self):
        protocol = re.split("://",url)[0]
        if protocol == "https":
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.domain)
            conn.settimeout(3)
            conn.connect((self.domain, 443))
            cert = conn.getpeercert()
            conn.close()

            not_before_str = cert['notBefore']
            not_after_str = cert['notAfter']
    
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")

            lifetime = not_after.year - not_before.year

            issuer = cert['issuer']
            reputable_cas = ["GeoTrust",
                             "GoDaddy",
                             "Network Solutions",
                             "Thawte",
                             "Comodo",
                             "Doster",
                             "VeriSign",
                             "GlobalSign",
                             "Entrust",
                             "DigiCert",
                             "Symantec",
                             "RapidSSL",
                             "Trustwave",
                             "IdenTrust",
                             "Google"
                             ]
            issuer = issuer[1][0][1].split(" ")[0]
            print(issuer)
            for ca in reputable_cas:
                if issuer.lower() in ca.lower() and lifetime >= 1:
                    return 1
                else:
                    continue
            return 0
        else:
            return -1
        
    def Domain_registeration_length(self):
        pass

    def Favicon(self):
        pass





url = "https://www.instagram.com/"
sample = FeaturesExtractor(url)
print(sample.features)