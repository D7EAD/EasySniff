<p align="center">
  <img src="https://github.com/0xDEFEC/EasySniff/blob/master/images/icon.ico" width="190px" height="190px" align="center">
  <i>EasySniff</i>
</p>

# Abstract
EasySniff is a smooth, clean, and effective network sniffing tool. It abstracts unnecessary technical information and makes monitoring traffic a lot easier for users. It provides a clean GUI with customizable tools and settings that the user can put to use. This tool was made to be used as an alternative to some other sniffers that may seem haphazardly made. Furthermore, it is to be used for educational purposes in the sector of network-oriented programming.

Sections of EasySniff are as follows:
  - <a href="#abstract">Abstract</a>
  - <a href="#dependencies">Dependencies</a>
  - <a href="#tutorial">Tutorial</a>
  - <a href="#features">Features</a>
  - <a href="#control-schemes">Control Schemes</a>
  - <a href="#intended-audiences">Intended Audiences</a>
  - <a href="#agreement">Agreement</a>
  - <a href="#credits">Credits</a>
  - <a href="#notes">Notes</a>
  - <a href="#known-issues">Known Issues</a>

<br/>

# Dependencies
EasySniff REQUIRES the following in order to operate:
  - WinPCap 4.1.3 (found <a href="https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe">here</a>).
  - MSVC++ 2019 redist (found <a href="https://aka.ms/vs/16/release/VC_redist.x64.exe">here</a>).

<br/>

# Tutorial
As some may have issues using EasySniff, a tutorial is here to help! The general process of installation and usage is as follows below:
  - Download and install the dependencies listed above.
  - Download the <a href="https://github.com/0xDEFEC/EasySniff/archive/master.zip">.zip</a> file from this repository.
  - Run setup\Release\setup.msi, this will install it to your Program Files.
    - After installation, EasySniff will now be added to your Desktop.
  - Open EasySniff and it should run fine.
    - From this point, select the adapter/interface that your desired traffic will go through and sniff!

<br/>

# Features
Some functions and features within EasySniff are as follows:
  - Compact executable--roughly 260KB!
  - Highly organized interface--I have OCD.
  - Multi-threaded design--100% smooth operation.
  - Full sniffing GUI oriented around the IPv4, TCP, and UDP protocols.
  - Immediate geolocation of any captured IP address--non-local.
  - Immediate ISP-related information returned for captured IPs.
  - Service integrity information regarding an ISP--known security technology.
  - Easy data export methods--IP and packet data.
  - Ability to ping any captured address on the fly!
  - Ability to quickly scan a chosen IP for any open ports.
  - Ability to look up more narrowed, specific information regarding an address.
  - Options to show more advanced data regarding captured packets.
  - ...and more!

<br/>

# Control Schemes
EasySniff has a few control schemes--shortcuts--for some functions that it performs. These control schemes can be found below:
  - Key click [C]:
    - ...to clear the captured addresses (or packet data).
  - Key click [S]:
    - ...to begin or end the sniffing process.
  - Single click [any mouse key]:
    - ...to copy any selected data in any shown cell.
  - Single click [any mouse key] + D:
    - ...to remove a specific row from the captured IPs until [Clear].
  - Single click [any mouse key] + P:
    - ...to perform a port scan on an IP from an appropriate cell.
  - Double click [any mouse key]:
    - ...to ping a selected IP from an appropriate cell.
    
<br/>

# Intended Audiences
The intended audiences to use this program or its source code can be any of the following:
  - Script kiddies on XBOX, PlayStation, or, hell... even PC!
  - Genuine people who want to learn something.
  - People who want to get ideas inspired by this tool.
  - Literally anyone else.

<br/>

# Agreement
By using EasySniff or its source code, you agree upon the following conditions: (1). You affirm that you understand EasySniff is strictly an open-source alternative and is to be used for education regarding network-oriented programming. (2). You will not use EasySniff or its source code with any malicious intent or to commit unapproved network recon, aiding in DoS/DDoS attacking other networks, etc. (3). You are entirely responsible for your use of this application and not the developer(s), dependency developer(s), or anyone else except for you.

All responsibility of this program's usage is assumed by, and only by, the user.

<br/>

# Credits
Programming, GUI Design: d7ead

Quality Assurance Testers (Bug Testers): Johnny

<br/>

# Notes
EasySniff version is 1.1.

This was made to prove how easy it is to make a sniffer.

Bandwidth listed under "Protected" is advertised network capacity, not protection capacity.

<br/>

# Known Issues
  - Incremental use of RAM throughout life of the process (EasySniff.exe).
  - Doesn't work for some VPN providers and tunnels.
  - IP Lookup API isn't valid anymore. Don't feel like adding a new one.
