# FastDomainDump

## Intro
FastDomainDump is a tool to quickly dump user information from a windows domain controller.

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
- Pw Age
- Expired Pw?
- Last Logon
- Last Logoff
- Expiry Date
- Priv
- Bad Pw Count
- Profile
- Homedir
- Max Storage
- Workstations

These will be written to a file called serverName.txt.