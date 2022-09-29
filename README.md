# forensics_creations
This is a repository for tracking our creations for our Digital Forensics class.
## September Creation: Boleto Malware Snort Rule

We created a Snort Rule that alerts when evidence of the Boleto malware is detected. The rule looks for the traffic to a specifically-named PHP file (“/1dkfJu.php?”). This URL is used in a phishing attack sent to the user. When the user clicks on the link, it downloads malware to their computer. The snort rule sends an alert when the user clicks on the malicious link by looking for a GET request connected to that specific PHP file name.

### Background on Boleto Malware

In Brazil, payments are made online using forms called “Boletos.” These forms are used nationally and contain payment information similar to bank account details used in America. A relatively new attack on these forms is when a threat actor uses malicious payloads (or malware) in order to steal or change the payment credentials on forms as the user submits them. Normally these attacks go unnoticed until long after the user has submitted payment, and they can be difficult to track and reverse. As of today, Boleto malware has caused millions of dollars of monetary loss. 


### Breaking Down the Snort Rule

#### Full Snort Rule: 
alert tcp any any -> any any (msg:“Probable successful phishing attack. (Boleto Malware)"; flow:established,to_server; content:"GET"; content:"/1dkfJu.php?"; sid: 10000001; rev:1;) 

####Breakdown
alert - this tells Snort that we want to be alerted
tcp - we are looking for tcp/HTTP traffic
any any (first) - analyzing traffic from any source (in this case the user)
any any (second) - analyzing traffic to any destination (the malicious web server)
msg: - a description of the issue, the message we want to receive with the alert
flow: - defines the traffic flow - in this case it is established and to_server
content: - defining the specific content we are looking for - in this case “GET” and the PHP file name
sid: - the Snort ID number

### Test Case Evidence

![Snort Rule Result](./imgs/septembercreationscreenshot.png)

Applications Used:
Kali Linux VM
Wireshark
SNORT

To begin the test case we analyzed Wireshark traffic. The source and destination found on Wireshark matched the content we were searching for with our SNORT rule. Since the content matched what we were searching for SNORT was able to notify us of the potential phishing attack. 

