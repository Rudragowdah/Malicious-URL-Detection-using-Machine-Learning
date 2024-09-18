# logic.py
import re
import requests
from urllib.parse import urlparse
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import dns.resolver
from googlesearch import search
import pandas as pd
import numpy as np


def check_url_status(url):
    
    if url =="":
        return -2,[]
    
    # Create an empty 2D NumPy array with 1 row and 30 columns
    array = np.zeros((1, 30), dtype=int)

    
    #url = "http://www.whatsapp.com"

    # Function to check if a URL contains an IP address
    def contains_ip_address(url):
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        return bool(re.search(ip_pattern, url))

    # Function to check if a URL contains a hexadecimal IP address
    def contains_hex_ip_address(url):
        hex_ip_pattern = r"(?:0[xX][0-9a-fA-F]{1,2}\.){3}0[xX][0-9a-fA-F]{1,2}"
        return bool(re.search(hex_ip_pattern, url))

    # Check if the example URLs contain IP addresses or hexadecimal IP addresses
    is_url_phishing = contains_ip_address(url) or contains_hex_ip_address(url)

    # Print the results
    print(f"1.  URL  ({url}): {'Phishing' if is_url_phishing else 'Not Phishing'}")
    if is_url_phishing:
      array[0,0] = -1
    else:
      array[0,0] = 1



    # Function to classify URLs based on length
    def classify_url_by_length(url):
        url_length = len(url)
        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        else:
            return -1

    # Classify the example URLs
    classification_url = classify_url_by_length(url)

    # Print the classification results
    print(f"2.  URL  ({url}): {classification_url}")
    array[0,1] = classification_url


    # Function to check if a URL is a TinyURL
    def is_tiny_url(url):
        try:
          response = requests.head(url, allow_redirects=True)
          final_url = response.url
          print(response.url)
          print(final_url)
          if url == final_url:
            return 1
          else:
            return -1
        except Exception as e:
          print(e)
          return -1

    try:
      # Check if the URL is a TinyURL
      is_tiny = is_tiny_url(url)

      # Print the result
      print(f"3.  URL ({url}) is a TinyURL: {is_tiny}")

      array[0,2] = is_tiny
    except Exception:
      array[0,2] = -1



    # Function to check if a URL contains an "@" symbol
    def contains_at_symbol(url):
        return "@" in url

    # Check if the example URLs contain an "@" symbol
    is_url_phishing = contains_at_symbol(url)

    # Print the results
    print(f"4.  URL ({url}) is phishing: {is_url_phishing}")

    if is_url_phishing:
      array[0,3] = -1
    else:
      array[0,3] = 1



    # Function to check if a URL is phishing based on the position of "//"
    def is_phishing_url(url):
        if url.startswith("http://") and url.rfind("//") > 6:
            return True
        elif url.startswith("https://") and url.rfind("//") > 7:
            return True
        else:
            return False

    # Check if the example URLs are phishing URLs
    is_url_phishing = is_phishing_url(url)

    # Print the results
    print(f"5.  URL ({url}) is phishing: {is_url_phishing}")
    if is_url_phishing:
      array[0,4] = -1
    else:
      array[0,4] = 1




    # Function to check if a URL's domain name includes a "-" symbol
    def domain_has_hyphen(url):
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return "-" in domain

    # Check if the example URLs' domain names include a "-" symbol
    is_url_phishing = domain_has_hyphen(url)

    # Print the results
    print(f"6.  URL ({url}) is phishing: {is_url_phishing}")

    if is_url_phishing:
      array[0,5] = -1
    else:
      array[0,5] = 1



    # Function to classify URLs based on the number of dots in the domain part
    def classify_url_by_subdomains(url):
        parsed_url = urlparse(url)
        #print(parsed_url)
        domain = parsed_url.netloc.split('.')  # Extract the domain part excluding www and ccTLD
        #print(domain)
        num_dots = len(domain) - 2
        #print(num_dots)

        if num_dots == 1:
            return 1
        elif num_dots == 2:
            return 0
        else:
            return -1


    # Classify the example URLs
    classification_url = classify_url_by_subdomains(url)

    # Print the classification results
    print(f"7.  URL ({url}) is classified as: {classification_url}")

    array[0,6] = classification_url


    # Function to check if a URL uses HTTPS
    def is_https(url):
      return url.startswith("https://")

    # Function to get the URL scheme (HTTP or HTTPS)
    def get_scheme(url):
      if is_https(url):
          return '1'
      else:
          return '-1'


    # Get the scheme for each example URL
    scheme_url = get_scheme(url)

    # Print the results
    print(f"8.  Scheme for URL  ({url}): {scheme_url}")

    array[0,7] = scheme_url


    # Function to check if a domain expires in less than or equal to 1 year
    def is_phishing_domain(domain):
        try:
            domain_info = whois.whois(domain)
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):  # Handle multiple expiration dates
                expiration_date = expiration_date[0]
            if expiration_date is not None:
                days_until_expiration = (expiration_date - datetime.now()).days
                if days_until_expiration <= 365:  # Less than or equal to 1 year
                    return True
            return False
        except Exception as e:
            #print(f"Error checking domain {domain}: {e}")
            return False
    try:

      parsed_url = urlparse(url)
      domain = parsed_url.netloc

      # Check if the example domains are phishing
      is_phishing_domain = is_phishing_domain(domain)

    except Exception:
      is_phishing_domain = True

    # Print the results
    print(f"9.  Domain {domain} is phishing: {is_phishing_domain}")

    if is_phishing_domain:
      array[0,8] = -1
    else:
      array[0,8] = 1



    # Function to check if the favicon is loaded from an external domain
    def is_phishing_favicon(url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
            if favicon_link:
                favicon_url = favicon_link.get('href')
                if favicon_url:
                    absolute_favicon_url = urljoin(url, favicon_url)
                    if absolute_favicon_url.startswith(url):
                        return False  # Favicon is loaded from the same domain
                    else:
                        return True  # Favicon is loaded from an external domain
            return False  # Favicon not found or not loaded externally
        except Exception as e:
            print(f"Error checking favicon for {url}: {e}")
            return False


    # Check if the example URLs have phishing favicon
    is_phishing_favicon_url = is_phishing_favicon(url)

    # Print the results
    print(f"10. Favicon for URL ({url}) is loaded externally: {is_phishing_favicon_url}")

    if is_phishing_favicon_url:
      array[0,9] = -1
    else:
      array[0,9] = 1



    # Function to check if a URL uses a non-standard port
    def is_phishing_port(url):
        try:
            parsed_url = urlparse(url)
            port = parsed_url.port
            if port is not None:
                # List of common standard ports
                standard_ports = [21, 80, 22, 23, 443, 445, 1433, 1521, 3306, 3389]
                if port not in standard_ports:
                    return True  # Non-standard port, considered phishing
            return False  # Standard port used, considered legitimate
        except Exception as e:
            print(f"Error checking port for {url}: {e}")
            return False

    try:

      # Check if the example URLs have phishing port
      is_phishing_port_url = is_phishing_port(url)

      # Print the results
      print(f"11. URL ({url}) uses non-standard port: {is_phishing_port_url}")

      if is_phishing_port_url:
        array[0,10] = -1
      else:
        array[0,10] = 1
    except Exception:
      array[0,10] = -1



    # Function to check if a URL uses the "HTTP" token in the domain part
    def has_http_token_in_domain(url):
        try:
          parsed_url = urlparse(url)
          domain_parts = parsed_url.netloc.split('.')
          if 'http' in domain_parts:
            return True  # HTTP token found in domain part, considered phishing
          elif 'https' in domain_parts:
            return True
          for item in domain_parts:
            if 'http' in item or 'https' in item:
              return True
          return False  # HTTP token not found in domain part, considered legitimate
        except Exception as e:
            print(f"Error checking HTTP token in domain for {url}: {e}")
            return False

    # Check if the example URLs have HTTP token in domain
    has_http_token_url = has_http_token_in_domain(url)

    # Print the results
    print(f"12. URL ({url}) has HTTP token in domain: {has_http_token_url}")

    if has_http_token_url:
      array[0,11] = -1
    else:
      array[0,11] = 1




    # Function to calculate the percentage of request URLs in HTML content
    def calculate_request_url_percentage(html_content):
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            total_objects = 0
            request_objects = 0

            # Count total objects and request objects
            for tag in soup.find_all(['img', 'video', 'audio']):
                total_objects += 1
                if tag.has_attr('src') and 'http' in tag['src']:
                    request_objects += 1

            if total_objects == 0:
                return 0  # Return 0 if no objects found

            # Calculate percentage of request URLs
            percentage = (request_objects / total_objects) * 100
            return percentage
        except Exception as e:
            print(f"Error calculating request URL percentage: {e}")
            return 0

    try:
      # Example URL to fetch HTML content (replace with your URL)
      response = requests.get(url)
      html_content = response.content

      # Calculate the percentage of request URLs
      request_url_percentage = calculate_request_url_percentage(html_content)

      request_url_percentage = 100 - request_url_percentage

      # Print the result
      print(f"13. Percentage of request URLs: {request_url_percentage}%")


      # Determine the URL legitimacy based on the percentage
      if request_url_percentage < 22:
        array[0,12] = 1
        print("Legitimate URL")
      elif 22 <= request_url_percentage < 61:
        array[0,12] = 0
        print("Suspicious URL")
      else:
        array[0,12] = -1
        print("Phishing URL")

    except Exception:
      array[0,12] = -1


    try:
      # Send a GET request to the URL and get the HTML content
      response = requests.get(url)
      html_content = response.content

      # Parse the HTML content using Beautiful Soup
      soup = BeautifulSoup(html_content, "html.parser")

      # Find all <a> tags
      a_tags = soup.find_all("a")

      # Initialize counters
      num_anchor_tags = 0
      num_valid_anchor_tags = 0

      # Loop through each <a> tag
      for a_tag in a_tags:
          # Check if the <a> tag has an href attribute
          if a_tag.has_attr("href"):
              href = a_tag["href"]
              #print(href)
              # Check if the href attribute is not empty and doesn't link to default or empty content
              if href and not href.startswith("#") and not href.startswith("javascript") and not href.endswith("#"):
                  num_valid_anchor_tags += 1
              num_anchor_tags += 1

      # Calculate percentages
      percentage_valid_anchor_tags = (num_valid_anchor_tags / num_anchor_tags) * 100 if num_anchor_tags > 0 else 0

      # Print the results
      print(f"Total <a> tags: {num_anchor_tags}")
      print(f"14. Valid Anchor URLs from <a> tags: {num_valid_anchor_tags} ({percentage_valid_anchor_tags:.2f}%)")
      invalidAnchorTags = num_anchor_tags - num_valid_anchor_tags
      if num_anchor_tags !=0:
        percentage = invalidAnchorTags/num_anchor_tags * 100
        if percentage <31:
          array[0,13] = 1
          print('legitimate')
        elif percentage >=31 and percentage <=67:
          array[0,13] = 0
          print("Suspicious")
        else:
          array[0,13] = -1
          print("Phishing")
      else:
        array[0,13] = -1
        print("phishing")
    except Exception:
      array[0,13] = -1




    try:

      # Send a GET request to the URL and get the HTML content
      response = requests.get(url)
      html_content = response.content

      # Parse the HTML content using Beautiful Soup
      soup = BeautifulSoup(html_content, "html.parser")

      # Find all <meta>, <script>, and <link> tags
      meta_tags = soup.find_all("meta")
      script_tags = soup.find_all("script")
      link_tags = soup.find_all("link")

      # Initialize counters
      num_same_domain_links = 0
      total_links = 0

      # Function to check if a link is from the same domain
      def is_same_domain(url, base_url):
          return urlparse(url).netloc == urlparse(base_url).netloc

      # Function to count same domain links
      def count_same_domain_links(tags):
          count = 0
          for tag in tags:
              if tag.has_attr("content"):
                  if is_same_domain(tag["content"], url):
                      count += 1
              elif tag.has_attr("src") or tag.has_attr("href"):
                  if is_same_domain(tag.get("src") or tag.get("href"), url):
                      count += 1
          return count

      # Count same domain links in <meta> tags
      num_same_domain_links += count_same_domain_links(meta_tags)
      total_links += len(meta_tags)

      # Count same domain links in <script> tags
      num_same_domain_links += count_same_domain_links(script_tags)
      total_links += len(script_tags)

      # Count same domain links in <link> tags
      num_same_domain_links += count_same_domain_links(link_tags)
      total_links += len(link_tags)

      # Calculate percentage of same domain links
      percentage_same_domain_links = (num_same_domain_links / total_links) * 100 if total_links > 0 else 0

      # Print the results
      print(f"15. Total links in <meta>, <script>, and <link> tags: {total_links}")
      print(f"Same domain links: {num_same_domain_links} ({percentage_same_domain_links:.2f}%)")
      if percentage_same_domain_links==0:
        array[0,14] = -1
        print("Phishing")
      elif percentage_same_domain_links < 25:
        array[0,14] = 1
        print('Legitimate')
      elif 25 <= percentage_same_domain_links <=81:
        array[0,14] = 0
        print("Suspicious")
      else:
        array[0,14] = -1
        print("Phishing")
    except Exception:
      array[0,14] = -1
      print("URL does not exist")





    # Function to check if SFH is phishing, suspicious, or legitimate
    def check_sfh(url):
        try:
            response = requests.get(url)
            if response.status_code != 200:
                print(f"Failed to fetch URL: {url}")
                return -1

            soup = BeautifulSoup(response.content, 'html.parser')
            form_tags = soup.find_all('form')

            if not form_tags:
                return 0  # No form tags found

            num_phishing_sfh = 0
            num_suspicious_sfh = 0
            num_legitimate_sfh = 0

            for form_tag in form_tags:
                action_url = form_tag.get('action', '')

                # Check if the SFH is empty or "about:blank"
                if is_doubtful_url(action_url):
                    num_phishing_sfh += 1
                else:
                    # Get domain of action URL and current URL
                    action_domain = get_domain(action_url)
                    current_domain = get_domain(url)

                    # Check if SFH refers to a different domain
                    if action_domain != current_domain:
                        num_suspicious_sfh += 1
                    else:
                        num_legitimate_sfh += 1
            print(num_phishing_sfh)
            print(num_suspicious_sfh)
            print(num_legitimate_sfh)
            # Determine SFH classification based on counts
            if num_phishing_sfh > 0:
                return -1
            elif num_suspicious_sfh > 0:
                return 0
            else:
                return 1
        except Exception as e:
            print(f"Error checking SFH: {e}")
            return -1

    # Function to check if a URL is empty or "about:blank"
    def is_doubtful_url(url):
        return url.strip() == "" or url.lower() == "about:blank"

    # Function to extract domain from URL
    def get_domain(url):
        parsed_url = urlparse(url)
        return parsed_url.netloc

    sfh_result = check_sfh(url)
    print(f"16. SFH classification for {url}: {sfh_result}")
    array[0,15] = sfh_result





    # Function to check if URL uses "mail()" or "mailto:" for submitting information
    def check_submit_to_email(url):
        try:
            response = requests.get(url)
            if response.status_code != 200:
                print(f"Failed to fetch URL: {url}")
                return -1

            soup = BeautifulSoup(response.content, 'html.parser')

            # Check for "mail()" function in JavaScript code
            script_tags = soup.find_all('script')
            for script_tag in script_tags:
                if script_tag.string:
                    if "mail(" in script_tag.string:
                        return -1   #"Phishing (Uses 'mail()' function)"

            # Check for "mailto:" in anchor tags
            anchor_tags = soup.find_all('a', href=True)
            for anchor_tag in anchor_tags:
                href = anchor_tag['href']
                if href.startswith("mailto:"):
                    return -1   #"Phishing (Uses 'mailto:')"

            return 1   #"Legitimate"
        except Exception as e:
            print(f"Error checking URL: {e}")
            return -1   #"Error"


    submit_to_email_result = check_submit_to_email(url)
    print(f"17. Submission to email classification for {url}: {submit_to_email_result}")

    array[0,16] = submit_to_email_result




    # Function to check if URL includes the host name
    def check_abnormal_url(url):
        try:
            parsed_url = urlparse(url)
            if parsed_url.netloc:
                # URL includes host name
                return 1   #"Legitimate"
            else:
                # Host name is not included in the URL
                return -1   #"Phishing (Abnormal URL)"
        except Exception as e:
            print(f"Error checking URL: {e}")
            return -1   #"Error"

    abnormal_url_result = check_abnormal_url(url)
    print(f"18. Abnormal URL classification for {url}: {abnormal_url_result}")

    array[0,17] = abnormal_url_result




    # Function to check website forwarding
    def check_website_forwarding(url):
        try:
            # Send a HEAD request to get the number of redirects
            response = requests.head(url, allow_redirects=True)
            num_redirects = len(response.history)

            if num_redirects <= 1:
                return 1   #"Legitimate"
            elif num_redirects >= 2 and num_redirects < 4:
                return 0   #"Suspicious"
            else:
                return -1   #"Phishing"
        except requests.RequestException as e:
            print(f"Error checking URL: {e}")
            return -1   #"Error"

    forwarding_result = check_website_forwarding(url)
    print(f"19. Website Forwarding classification for {url}: {forwarding_result}")
    array[0,18] = forwarding_result






    # Function to check if right-click is disabled
    def check_right_click_disabled(url):
        try:
            response = requests.get(url)
            source_code = response.text

            if "event.button==2" in source_code:
                return -1   #"Phishing"
            else:
                return 1   #"Legitimate"
        except requests.exceptions.RequestException as e:
            #print(f"Error checking URL: {e}")
            return -1   #"Error"

    # Check if right-click is disabled
    right_click_result = check_right_click_disabled(url)
    print(f"21. Right Click Disabled classification for {url}: {right_click_result}")
    array[0,20] = right_click_result




    try:

      # Send an HTTP GET request to the URL
      response = requests.get(url)

      if response.status_code == 200:
        # Parse the HTML content of the webpage
        soup = BeautifulSoup(response.content, "html.parser")

        # Find all input elements of type text
        text_input_fields = soup.find_all("input", {"type": "text"})

        if text_input_fields:
          array[0,21] = -1
          print("22. Popup window contains text fields. This could be phishing.")
        else:
          array[0,21] = 1
          print("22. Popup window does not contain text fields. Likely legitimate.")
      else:
        array[0,21] = -1
        print("22. Error fetching the webpage. Status code:", response.status_code)
    except Exception:
      array[0,21] = -1



    # Function to check if the website uses an iframe
    def check_iframe_usage(url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, "html.parser")

            if soup.find("iframe"):
                return -1   #"Phishing"
            else:
                return 1   #"Legitimate"
        except requests.exceptions.RequestException as e:
            print(f"Error checking URL: {e}")
            return -1   #"Error"

    # Check if the website uses an iframe
    iframe_result = check_iframe_usage(url)
    print(f"23. Using Iframe classification for {url}: {iframe_result}")
    array[0,22] = iframe_result





    def extract_domain_name(url):
        parsed_url = urlparse(url)
        domain_name = parsed_url.netloc
        if domain_name.startswith("www."):
            domain_name = domain_name[4:]  # Remove "www." if present
        return domain_name

    def check_domain_age(url):
      try:
        domain_name = extract_domain_name(url)
        domain_info = whois.whois(domain_name)

        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Use the first creation date if there are multiple

        today = datetime.now()
        age_in_months = (today.year - creation_date.year) * 12 + today.month - creation_date.month

        if age_in_months >= 6:
            return 1   #"Legitimate"
        else:
            return -1   #"Phishing"
      except Exception as e:
        print(f"Error checking domain age for {url}: {e}")
        return -1   #"Error"


    domain_age_result = check_domain_age(url)
    print(f"24. Age of Domain classification for {url}: {domain_age_result}")
    array[0,23] = domain_age_result





    def check_dns_record(domain_name):
        try:
            answers = dns.resolver.resolve(domain_name, 'A')
            if answers:
                return 1   #"Legitimate"
            else:
                return -1   #"Phishing"
        except dns.resolver.NoAnswer:
            return -1   #"Phishing"
        except Exception as e:
            print(f"Error checking DNS record for {domain_name}: {e}")
            return -1   #"Error"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    dns_record_result = check_dns_record(domain)
    print(f"25. DNS Record classification for {domain}: {dns_record_result}")

    array[0,24] = dns_record_result

    if array[0,7]==-1:
      array[0,25] = -1
    else:
      array[0,25] = 1
    print(f"26. website traffic classification: {array[0,25]}")



    if array[0,2] == 1:
      array[0,26] = 1
    else:
      array[0,26] = -1

    print(f"27. classification {array[0,26]}")


    # Function to check if a website is indexed by Google
    def is_indexed_by_google(website_url):
        query = f"site:{website_url}"
        search_results = list(search(query, num_results=1))
        return len(search_results) > 0

    # Check if the website is indexed by Google
    if is_indexed_by_google(url):
      array[0,27] = 1
      print("28. Legitimate (Indexed by Google)")
    else:
      array[0,27] = -1
      print("28. Phishing (Not Indexed by Google)")





    def get_external_links(url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                external_links = set()
                parsed_url = urlparse(url)
                domain = parsed_url.netloc

                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith(('http://', 'https://')) and domain not in href:
                        external_links.add(href)

                return len(external_links)
            else:
                print(f"Error: Unable to fetch URL {url}")
        except Exception as e:
            print(f"Error: {e}")

    def classify_legitimacy(num_links):
        if num_links == 0:
            return -1   #"Phishing"
        elif 0 < num_links <= 2:
            return 0   #"Suspicious"
        else:
            return 1   #"Legitimate"

    num_external_links = get_external_links(url)
    if num_external_links is not None:
        print(f"Number of external links: {num_external_links}")
        result = classify_legitimacy(num_external_links)
        print(f"29. Classification: {result}")
        array[0,28] = result
    else:
        array[0,28] = -1





    # Top 10 domains and IPs from PhishTank statistical data
    phish_tank_top_domains = [
        "creeksideshowstable.com", "altervista.org", "sendmaui.net",
        "seriport.com", "bjcurio.com", "118bm.com", "esphc.pt",
        "paypal-system.de", "google.com", "remorquesfranc.net"
    ]

    phish_tank_top_ips = [
        "178.219.117.72", "199.204.248.109", "79.124.104.31",
        "94.154.60.19", "46.174.25.83", "95.128.74.50", "67.208.112.27",
        "91.239.245.32", "118.244.132.16", "159.253.36.2"
    ]


    # Function to check if a URL's domain or IP is in the top lists
    def is_in_top_lists(url, top_domains, top_ips):
        domain = urlparse(url).netloc
        ip_address = urlparse(url).hostname
        return domain in top_domains or ip_address in top_ips

    # Check if the URL's domain or IP is in the top lists
    if is_in_top_lists(url, phish_tank_top_domains, phish_tank_top_ips):
        array[0,29] = -1
        print("30. Phishing")
    else:
      array[0,29] = 1
      print("30. Legitimate")


    print(array)

    dataset = pd.read_csv('dataset.csv')
    X = dataset.iloc[:, 1:-1].values
    y = dataset.iloc[:, -1].values
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = .2, random_state = 0)
    from sklearn.ensemble import RandomForestClassifier
    classifier = RandomForestClassifier(n_estimators = 100, criterion = 'entropy', random_state = 0)
    classifier.fit(X_train, y_train)
    pred = classifier.predict(array)

    mylist = array[0].tolist()

    print(mylist)


    return pred[0],mylist


