import ipaddress
import re
import ssl 
import socket
from datetime import datetime
import whois
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import dns.resolver
from googlesearch import search
from pysafebrowsing import SafeBrowsing




class FeaturesExtractor:
    features = []

    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.url_parse = ""
        self.whois_res = ""
        self.soup = ""
        self.google_api = "GOOGLE_API_KEY"
        self.similarweb_api_key = "SIMILARWEB_API_KEY"

        try:
            self.url_parse = urlparse(url)
            self.domain = self.url_parse.netloc
        except:
            pass


        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",

            }
            self.header = headers



            self.response = requests.get(url, headers=headers)
            self.soup = BeautifulSoup(self.response.content, "html.parser")
        except:
            pass


        try:
            self.whois_res = whois.whois(self.domain)
        except:
            pass


        self.features.append(self.having_IP_Address())
        self.features.append(self.URL_Length())
        self.features.append(self.Shortining_Service())
        self.features.append(self.having_At_Symbol())
        self.features.append(self.double_slash_redirecting())
        self.features.append(self.Prefix_Suffix())
        self.features.append(self.having_Sub_Domain())
        self.features.append(self.SSLfinal_State())
        self.features.append(self.Domain_registeration_length())
        self.features.append(self.Favicon())
        self.features.append(self.port())
        self.features.append(self.HTTPS_token())
        self.features.append(self.Request_URL())
        self.features.append(self.URL_of_Anchor())
        self.features.append(self.Links_in_tags())
        self.features.append(self.SFH())
        self.features.append(self.Submitting_to_email())
        self.features.append(self.Abnormal_URL())
        self.features.append(self.Redirect())
        self.features.append(self.on_mouseover())
        self.features.append(self.RightClick())
        self.features.append(self.popUpWidnow())
        self.features.append(self.Iframe())
        self.features.append(self.age_of_domain())
        self.features.append(self.DNSRecord())
        self.features.append(self.web_traffic())
        self.features.append(self.Page_Rank())
        self.features.append(self.Google_Index())
        self.features.append(self.Links_pointing_to_page())
        self.features.append(self.Statistical_report())









    
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
        match = re.search('bit.ly|goo.gl|shorte.st|go2l.ink|ow.ly|t.co|tinyurl|tr.im|is.gd|cli.gs|'
                    'yfrog.com|migre.me|ff.im|tiny.cc|url4.eu|twit.ac|su.pr|twurl.nl|snipurl.com|'
                    'short.to|BudURL.com|ping.fm|post.ly|Just.as|bkite.com|snipr.com|fic.kr|loopt.us|'
                    'doiop.com|short.ie|kl.am|wp.me|rubyurl.com|om.ly|to.ly|bit.do|t.co|lnkd.in|'
                    'db.tt|qr.ae|adf.ly|goo.gl|bitly.com|cur.lv|tinyurl.com|ow.ly|bit.ly|ity.im|'
                    'q.gs|is.gd|po.st|bc.vc|twitthis.com|u.to|j.mp|buzurl.com|cutt.us|u.bb|yourls.org|'
                    'prettylinkpro.com|scrnch.me|filoops.info|vzturl.com|qr.net|1url.com|tweez.me|v.gd|tr.im|link.zip.net', self.url)
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
        try:
            protocol = self.url_parse.scheme
            if 'https' in protocol:
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
                for ca in reputable_cas:
                    if issuer.lower() in ca.lower() and lifetime >= 1: 
                        return 1
                    else:
                        continue
                return 0
            else:
                return -1
        except:
            pass
        
    def Domain_registeration_length(self):

        try:
            try:
                expiration_date = self.whois_res.expiration_date.year
            except:
                expiration_date = self.whois_res.expiration_date[0].year
            
            try:
                creation_date = self.whois_res.creation_date.year
            except:
                creation_date = self.whois_res.creation_date[0].year

            life = expiration_date - creation_date

            if life <= 1:
                return -1
            else:
                return 1 
        except:
            return None

    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1
        
    def port(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
               return -1
            return 1
        except:
            return -1
        
    def HTTPS_token(self):
        if "https" in self.domain:
            return -1
        else:
            return 1
        
    def Request_URL(self):

        try:

            total_objects = 0
            external_objects = 0

            domain_name = self.domain.split(".")
            if domain_name[0] == 'www':
                domain_name = domain_name[1]
            else:
                domain_name = domain_name[0]

            tags_names= ['img', 'video', 'audio', 'embed', 'iframe']

            for tag in tags_names:
                tags = self.soup.find_all(tag)

                for tag in tags:
                    src = tag.get('src')
                    if src:
                        total_objects += 1
                        if domain_name not in src:
                            external_objects += 1
            percent =(external_objects/total_objects)*100

            if percent < 22:
                return 1
            elif (percent >= 22) and percent < 66:
                return 0
            else:
                return -1
    
        except:
            pass
        

    def URL_of_Anchor(self):
        try:
            total = 0
            sus_points = 0
            tags = self.soup.find_all("a")
            for tag in tags:
                link = tag.get('href')
                if link:
                    total += 1
                    if ('#' in link and link[0]=="#" ) or 'javascript' in str(link).lower() or 'mailto' in link or (url == link):
                        sus_points += 1

            percent = (sus_points/total)* 100

            if percent < 31:
                return 1
            elif percent >= 31 and percent <= 67:
                return 0
            else:
                return -1
                    
        except:
            pass

    def Links_in_tags(self):
        try:

            total = 0
            good = 0

            domain_name = self.domain.split(".")
            if domain_name[0] == 'www':
                domain_name = domain_name[1]
            else:
                domain_name = domain_name[0]

            tag_names = ['script', 'meta', 'link']

            for tag in tag_names:

                tags = self.soup.find_all(tag)

                for tag in tags:
                    src = tag.get('src')
                    href = tag.get('href')

                    if src:
                        total += 1
                        if self.domain in src or self.url in src:
                            good += 1


                    if href:
                        total += 1
                        if self.domain in href or self.url in href:
                            good += 1

            percent = (good/total)*100


            if percent < 17:
                return 1
            elif percent >=17 and percent <=81 :
                return 0
            else:
                return -1
        except:
            pass

    def SFH(self):
        try:
            if len(self.soup.find_all('form')) == 0:
                return 1
            else:
                tags = self.soup.find_all('form')
                for form in tags:
                    tag = form.get("action")
                    if tag == '' or tag == 'about:blank':
                        return -1
                    elif self.url not in tag or self.domain not in tag:
                        return 0
                    else:
                        return 1
        except:
            return -1

    def Submitting_to_email(self):
        
        try:
            if re.findall( r"(mail()|mailto:)", str(self.soup)):
                return -1
            else:
                return 1
        except:
            pass

    def Abnormal_URL(self):
        try:
            if self.whois_res["domain_name"][0].lower() not in self.domain.lower():
                return -1
            else:
                return 1
        except:
            pass

    def Redirect(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) >= 2 and len(self.response.history) < 4:
                return 0
            else:
                return -1
        except:
            pass

    def on_mouseover(self):
        try:
            script_tags = self.soup.find_all('script')
            for tag in script_tags:
                js_code = tag.text
                if 'windows.status' in js_code or 'windows.statusbar' in js_code:
                    return -1
            return 1            
        except:
            pass

    def RightClick(self):
        try:
            if re.findall(r"event.button *?== *?2", self.response.text):
                return -1
            else:
                return 1
        except:
            pass

    def popUpWidnow(self):
        try:
            popup = self.soup.select('.popup input[type="text"]')
            
            if popup or re.findall(r"alert\(", self.response.text):
                return -1
            else:
                return 1
        except:
            pass

    def Iframe(self):
        try:
            if self.soup.find_all('iframe'):
                return -1
            else:
                return 1

        except:
            pass

    def age_of_domain(self):
        try:
            try:
                creation_date = self.whois_res.creation_date.year
                creation_date = self.whois_res.creation_date
            except:
                creation_date = self.whois_res.creation_date[0]

            if not creation_date or creation_date > datetime.now():
                return -1
            
            age_in_months = (datetime.now() - creation_date).days / 30

            if age_in_months >= 6:
                return 1
            else:
                return -1

        except:
            pass

    def DNSRecord(self):
        try:
            answers = dns.resolver.resolve(self.domain)
            if answers.response:
                return 1
            else:
                return -1
        except dns.resolver.NXDOMAIN:
            return -1
        except:
            pass

    def web_traffic(self):
        try:
            endpoint = f"https://api.similarweb.com/v1/similar-rank/{self.domain}/rank?api_key={self.similarweb_api_key}"
            response = requests.get(endpoint).json()
            try:
                rank = response["similar_rank"]['rank']
            except:
                return -1

            if rank<= 100000:
                return 1
            elif rank >  100000:
                return 0
        except:
            pass


    def Page_Rank(self):
        try:
            pgrank = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain} , headers=self.header)


            match = re.findall(r'<b>cPR Score:</b></font> <font color="#4d82f7"><b>([\d.]+)/10</b>', pgrank.text)

            if match:
                match = float(match[0])
                if match < 0.2:
                    return -1
                else:
                    return 1
        except:
            pass


    def Google_Index(self):
        try:
            query = f"site:{self.domain}"
            search_results = search(query, num=1, stop=1)
            for result in search_results:
                if self.domain in result:
                    return 1
                else:
                    return -1

        except:
            return -1

    def Links_pointing_to_page(self):
        try:
            count = 0
            a_tags = self.soup.find_all('a')
            for tag in a_tags:
                href = tag.get('href')
                if href:
                    count +=1
            if count == 0:
                return -1
            elif count > 0 and count<= 2:
                return 0
            else:
                return 1

        except:
            pass

    def Statistical_report(self):
        try:
            safe_browse = SafeBrowsing(self.google_api)
            lookup = safe_browse.lookup_urls([self.url])
            if lookup[self.url]['malicious']:
                return -1
            else:
                return 1
        except:
            pass

    def getfeatureslist(self):
        return self.features
    
