# Mobile SNMP++

Mobile SNMP++ is an iOS project, which you can include in your own project so you can perform some SNMP commands.

## History
Mobile SNMP++ is based on [SNMP++ v3.x from Frank Fock](http://www.agentpp.com/snmp_pp3_x/snmp_pp3_x.html), which in turn is based on [SNMP++ v2.8 from HP](http://www.sa-ha.de/snmp/).
Currently Mobile SNMP++ supports only SNMP v1 and v2c

## Usage (Really, really short...)
In order to use this project, you have two options. You can either just download the project and add it as a subproject to your current Xcode project, or you can add this as a submodule to your git repository
In either case, you should also add the headerfile XISMobileSNMP_PP.h to your project (but do _NOT_ copy it), and you also have to import this header file.

## Sample Project
I have included a sample project (snmpGetSample) you can inspect. I suggest you open the `<snmpGetSample.xcworkspace`> if you wish to build and/or inspect this file.