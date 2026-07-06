# 01 Installing the Domain Controller 


1. Use `Sconfig ` to:
    - Change the hostname 
    - Change the Ip address to static 
    - Change the DNS server to our own Ip address

2. Install the Aactive Directory Windwos Feature 

```shell
Install-windowsFeature AD-Donmain-Services -IncludeManagementTools