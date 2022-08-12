![Layer-8-Logo-Wide](https://user-images.githubusercontent.com/8293038/96061566-93d8af00-0e61-11eb-8b84-3fd207290be2.png)
# The Storfield Methodology

A methodology to formulate attack paths in a quiet manner by understanding the basic aspects and protocols of a network.

Originally presented at [Red Team Village](https://redteamvillage.io) during [DEFCON30](https://defcon.org)  by [Cory Wolff](https://twitter.com/cwolff411).

The Storfield Methodology focuses on three main questions:
1. Where am I?
2. Where is the DC?
3. Where are the high-value targets?

![](https://user-images.githubusercontent.com/8293038/184412445-5010f316-a0ce-46b4-a8d4-5f78c653bd0f.png)

## Where am I?
Often times when we land on a network we don't fully understand where we are located. Are we sitting on a management subnet? A client subnet? What would we find if we were to look at the `arp` table for example? Would we see client machines and printers? Or would we see file servers, mail servers, and domain controllers?

Where we start is a major factor in our decision making when formulating attacks. Depending on the hosts around us, we may want to use `NTLM Relay` for example and try to mitm an SMB connection.

So, how do we discover our network neighbors while staying quiet and limiting the traffic we generate? If we're operating in a mature environment, we can't simply kick off `nmap` and start whippin' packets around.

BUT WHAT ABOUT THE FLAGS?!

There are those of us who might argue that if you use the right settings during a command line `nmap` scan you can evade detection. 

Sure. But that takes a lot of effort and changes depending on the network and the IPS/IDS settings. Certain `nmap` flags might work for us in one network, but it's not guaranteed to work in the next.

The Storfield Methodology is meant to be repeatable during every engagement. When following this method the steps should be the same regardless of the security controls implemented in a particular network.

Ok, so back to the matter at hand. How do we discover the hosts around us and find out where we are?

We stick with the basics. That's how.

The suggested steps for discovering our current location as well as other subnets can be outlined as such:

- ARP Scan
- Ping Broadcast Address
- Ping sweep via BASH or PowerShell
- TCP sweep via netcat/bash or PowerShell
- Packet Capture

## Where is the Domain Controller?
In a Microsoft Active Directory environment the Domain Controller is the heart. All AD services must flow through the(a) Domain Controller. In larger networks we'll see more than one, but they all serve the same purpose of running the AD environment.

This is an important aspect in our quest to formulate attack paths. The DC hosts authentication with Kerberos, serves as the DNS server, provides the SYSVOL and NETLOGON shares, and manages the LDAP catalog.

There could be many ways to discover a Domain Controller, but the Storfield Methodology suggests the following:
1. Most AD environments use a Domain Controller as the DNS server for the whole network. In this likely scenario, we can look for the DHCP assigned DNS server which should lead us to a Domain Controller.
2. If working on a Windows machine, we can also print out the environment variable `%LOGONSERVER` by executing `echo %LOGONSERVER`  through a cmd or PowerShell window.
3. Packet Capture. By capturing packets and looking at hosts that are sending/receiving DNS and Kerberos, we can get a pretty good idea of where a Domain Controller is located.


## Where are the member servers located?
Understanding the location of servers that host SQL, HTTP, and act as file servers can lead to various attack paths during the exploitation phase of our engagement. While we can gather much of the intelligence necessary to determine the location of these high value targets during our subnet recon phase (see below), there are additional steps we can take to discover these hosts while flying beneath the radar.
1. Parsing an LDAP dump - we should look for Organizational Units (OU) that represent possible member servers i.e. "Contoso SQL Machines"
2. Domain logon scripts - often times sysadmin's will use the domain logon scripts to automatically mount file shares during a user logon event. Mounting SYSVOL(more on this below) and browsing the `scripts` folder can lead to the discovery of file servers previously undiscovered
3. GPO Bookmarks - in many enterprise environments, sysadmins create Group Policies to set the bookmarks of intranet sites. This could be a valuable way to discover internal web hosts. Additionally, we should check the shortcuts created on the user desktop as well to see if we can discover any juicy bits.

### Mounting SYSVOL/NETLOGON
As practitioners of The Storfield Methodology we love SYSVOL. By its very nature, Active Directory makes this share accessible to all domain users. Microsoft refers to it as 'a folder which resides on each and every domain controller on the domain' and that 'it contains the domains public files that need to be accessed by clients...'. [A good break down on SYSVOL here](https://social.technet.microsoft.com/wiki/contents/articles/24160.active-directory-back-to-basics-sysvol.aspx)

This can provide us with information that can aid in our reconnaissance. We can view logon scripts and group policies to discover some of the items mentioned above.

We can access this folder in many ways.
1. We can use `smbclient` and connect to the DC `smbclient -U USERNAME \\\\DOMAIN_NAME\SYSVOL`
2. We can mount it like any other fileshare and look in the scripts folder and for juicy xml files with `find . -name *.xml`


## Reconing a Subnet
There are many ways that we can observe the services used and the hosts active in a particular environment, but we must consider the amount of traffic generated by these methods and instead opt for a quieter approach.

As you might have guessed, this means keeping it simple.

### Host Discovery
ARP is an often forgotten about protocol. Address Resolution Protocol maps software identifiers (IP addresses) to hardware identifiers (MAC addresses). Every machine on the network stores an ARP table locally so that it can easily determine the correct MAC address for a particular IP.

As attackers, this can provide valuable information in discovering hosts in the environment by simply looking at the arp table. Most commonly we will use `arp -a -i INTERFACE` on the bash terminal to view this table. 
![](https://user-images.githubusercontent.com/8293038/184408570-d603581d-2568-4f42-9079-572dc120add9.png) 

This will provide us with a list of IP addresses stored in the ARP table and we can now add these hosts to our discovered host list.

A second way is to do a ping sweep. Yes, we can use tooling (see above), but we want to keep it as simple as possible. We can do this by performing a ping sweep through a bash or powershell one-liner.

```
for i in `seq 1 255`; do ping -c 1 192.168.1.$i | tr \\n ' ' | awk '/1 received/ {print $2}'; done
```

```
1..254 | % {"192.168.1.$($_): $(Test-Connection -count 1 -comp 192.168.1.$($_) -quiet)"}
```

### Service Discovery
First, we need to decide on the services that are most interesting to us. In Active Directory it most likely comes down to a handful of services. We should know our ports:

1. SMB - 139, 445
2. HTTP/HTTPS - 80, 443
3. RDP - 3389
4. DNS - 53
5. LDAP - 389, 636
6. LDAP Global Catalog Services - 3268, 3269

With our target services and their associated ports in mind, we can use `netcat` and some fancy bash scripting to create a one-liner that will loop through a subnet, check if that port is open with `netcat` and if it is, add the ip to a text file.

```
for i in `seq 1 254`; do nc -zvw1 x.x.x.$i SERVICE_PORT 2>&1 | grep "Connected" | cut -d " " -f4 | cut -d ":" -f1 >> SERVICE_NAME-hosts.txt;done
```



## Reconing Active Directory

### LDAP

Lightweight **Directory** Access Protocol (LDAP) is the underlying technology behind Active **Directory**. LDAP is a protocol and service that contains a catalog off **all** the objects in a domain. Everything is an object in AD and LDAP - users, machines, groups, you name it.

In order for Active Directory to work, users need to be able to see the catalog of objects. They may not have access rights to all objects, but if you needed to add a user to a privileged group for example - the low level user needs to know it exists and Active Directory then needs to know that the user was added to the group. It does this through LDAP.

So, all users need access to this catalog which means that even as a low level user we can dump the full LDAP catalog and take a look around.

Using `ldapsearch` we can connect to the LDAP server and dump the catalog:

`ldapsearch –x –h 10.0.0.1 –b “DC=contoso,DC=com`

![](https://user-images.githubusercontent.com/8293038/184410690-f76dcbfb-f46a-4f34-b2e6-38da4beb4111.png)

![](https://user-images.githubusercontent.com/8293038/184410839-8da4bde5-262c-4434-8970-c65ba97836d5.png)

Dumping LDAP will provide us with a list of users, computer names, groups, service accounts, and possibly juicy info such as passwords. We can then parse this dump to create lists of users, perform `nslookup` on the computer names to get hostname/ip combos, and even maybe find a password.

Luckily, there's a tool that can automate this and help us organize our LDAP dump into groups of files called [SilentHound](https://github.com/layer8secure/SlientHound)

`silenthound.py -u 'USERNAME' -p 'PASSWORD' x.x.x.x DOMAIN_NAME -n -k -g -o OUTPUT_FOLDER/ `

![](https://user-images.githubusercontent.com/8293038/184411632-deb70bbf-3a85-4895-9366-112ceb689bcd.png)

![](https://user-images.githubusercontent.com/8293038/184411748-f49dc21e-12eb-40c7-af40-1283b978b0b9.png)

## Formulate Attacks
By this point we should have gathered the following information while limiting our network traffic and staying quiet
1. A list of active targets
2. A list of SMB hosts
3. A list of RDP Hosts
4. A list of Domain Controllers
5. Computer names and IPs
6. AD groups
7. AD users
8. Location of member services and other high value hosts