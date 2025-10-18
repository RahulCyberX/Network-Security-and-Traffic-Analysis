# #10: NetworkMiner: Analyze traffic files and practice network forensics

---

I used **NetworkMiner** to perform network forensics on provided PCAPs. I focused on understanding tool capabilities, loading PCAPs, and extracting basic artifacts (hosts, sessions, files, credentials). This entry documents exactly what I did, why I did it, and how — with the TryHackMe answers included.

**Role:** Incident responder / forensic analyst

**Tools:** NetworkMiner 2.7.2 (GUI)

**Deliverable:** PCAP analysis, extracted artifacts, THM answers

---

# Tool Overview (Part 1)

## Objective

Explore the **Hosts, Sessions, DNS, Credentials panels** and answer PCAP-based questions.

## Steps I performed

1. I loaded `mx-3.pcap`.

![image.png](image.png)

- **Hosts tab** showed IPs, MACs, OS fingerprints, sessions.
    
    ![image.png](image%201.png)
    
- **Sessions tab** listed connections + protocols.
    
    ![image.png](image%202.png)
    
- **DNS tab** gave queries and responses.
    
    ![image.png](image%203.png)
    
- **Credentials tab** shows captured credentials.

1. To check total number of frames → 
    
    ![image.png](image%204.png)
    
    ![image.png](image%205.png)
    

1. To check web server of a particular IP? →
    
    ![image.png](image%206.png)
    
2. To see username and passwords we can go to credentials tab? → 
    
    ![image.png](image%207.png)
    

---

# Tool Overview (Part 2)

## Objective

Explore **Files, Images, Parameters, Keywords, Messages, Anomalies panels** and answer PCAP-based questions.

## Steps I performed

1. I loaded `mx-7.pcap`
    
    ![image.png](image%208.png)
    

1. To explore the **Files**, I go to the Files tab, and right click on any file. From there I can click any of these options for more info.
    
    ![image.png](image%209.png)
    

3. To inspect **images**, I go to the images tab.

![image.png](image%2010.png)

And by hovering over the image, it shows the file's detailed information (source & destination address and file path).

1. To see extracted **parameters** from investigated pcaps, I simply go to the parameters tab, and easily copy parameters and values easily. 
    
    ![image.png](image%2011.png)
    

1. To see **extracted keywords** from the investigated pcaps, this section is very useful in the keywords tab.
    
    ![image.png](image%2012.png)
    

1. The **messages** menu shows extracted emails, chats and messages from investigated pcaps.
    
    ![image.png](image%2013.png)
    

1. The **anomalies** menu shows detected anomalies in the processed pcap.
    
    ![image.png](image%2014.png)
    

## Questions & Answers

1. To check **Linux distro** (frame 63075)? 
    
    ![image.png](image%2015.png)
    
2. To find the **source IP** of `ads.bmp.2E5F0FD9.bmp`image ? 
    
    ![image.png](image%2016.png)
    

---

1. To find **OS** of any IP address / host? 
    
    ![image.png](image%2017.png)
    
2. To know how many **bytes were received** from one address to other through any particular port like port 1065? 
    
    ![image.png](image%2018.png)
    
3. To get the **sequence** number of a frame?
    
    ![image.png](image%2019.png)
    
4. To find Number of detected content types? 
    
    I need to use the parameters menu here, and look for the parameter name *Content-Type*. I can use the Filter keyword input for time efficiency.
    
    ![image.png](image%2020.png)
    
    Unique content types are: text/plain and multipart/mixed. So the number is 2.
    

---

## My final understanding

- **NetworkMiner** is best used for **post-event forensic triage**.
- It quickly shows **hosts, OS, sessions, credentials, files**.
- For deep packet analysis, I’d switch to **Wireshark**.
- For real-time detection, I’d use **Snort**.

---