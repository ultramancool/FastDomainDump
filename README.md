# FastDomainDump

## Intro
FastDomainDump is a tool to quickly dump user information from a windows domain controller.

## Motivation
FastDomainDump was written because I wanted to gather both the last time a user changed their password and the last time they logged on from a domain controller and do it in a reasonable amount of time. 
I had previously been using NetPwAge from OptimumX and some ancient tool from the Windows 2000 Resource kit to fetch the last logon age. Both tools were very slow on a large domain (with 10s of thousands of users) so I wrote something which can gather more information and do it much much faster. What took 3-6 hours using the other tools is now possible within a matter of 5 minutes using this tool. 

## Disclaimer
What you do with this is your problem, not mine. And yes, you can do this all _without_ domain admin priviledges. 

## Usage
You may invoke FastDomainDump against a specific domain controller or a domain (will dump _all_ primary and backup servers for the domain):

    FastDomainDump.exe domain MYDOMAIN
    FastDomainDump.exe server MYPDC

## Output
It outputs tab delimited values (easily readable in Calc or Excel) including the following:
- Name
- Full Name
- Comment
- User Comment
- Flags
- Auth Flags
- Password Age
- Expired Password?
- Last Logon
- Last Logoff
- Expiry Date
- Priv
- Bad Password Count
- Profile
- Homedir
- Max Storage
- Workstations

Note that not all values are present on all servers, some may require certain features to be enabled or be in use.
These will be written to a file called serverName.txt.

## License
See COPYING file.