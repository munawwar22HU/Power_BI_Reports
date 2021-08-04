import glob
import csv
from typing import List

Filenames = glob.glob("Syslog\\RawData\\Syslog*.txt")
# Nested Lists which will store data to be written to the CSV Files
Data = []
SpywareData = []
DeviceData = []
VirusData = []
CallbackData = []
NetworkData = []
BehaviourData = []
WebsecurityData = []
SypwareHeaderData = [
    "Event Name", "Device External ID", "Log Generation Date",
    "Number of Detections", "Endpoint host name", "Virus Name",
    "Action Result", "File Name", "File Path", "Endpoint IPv4 Address",
    "User Name", "Scan_Type", "Security_Threat_Type"
]
DeviceHeader = [
    "Event Name", "Log Generation Date", "Source Host Name", "Target Process",
    "File Name", "Device Type", "Permission"
]
VirusHeader = [
    "Event Name", "Device External ID", "Log Generation Date",
    "Number of Detections", "Endpoint", "Action", "Second Action", "Scan Type",
    "Reason Code", "First Action Result", "Second Action Result",
    "Severity Code", "File Name", "File Path", "Endpoint IPv4 address"
]

CallbackHeader = [
    "Event Name", "Device External ID", "Log Generation Date",
    "Endpoint Host Name", "Endpoint IPv4 Address", "Domain Name", "Action",
    "Risk Level", "Detection Source", "Destination Format",
    "Callback IPV4 address", "Process Name"
]
NetworkHeader = [
    "Event Name", "Device External ID", "Log Generation Date",
    "Target Process", "Action", "Source IPv4 Address",
    "Destination IPv4 Address", "Source Port", "Destination Port",
    "Traffic / Connection", "Threat Name"
]
BehaviourMonitoringHeader = [
    "Event Name", "Log Generation Date", "Risk Level", "Policy ID",
    "Aegis Subject", "Event Type", "Target", "Action", "Operation",
    "Source host (endpoint)", "Source host IP address"
]
WebSecurityHeader = [
    "Event Name", "Device External ID", "Log Generation Date", "Protocol",
    "Detections", "Server Port", "Action", "Endpoint IPv4 address",
    "Policy Name", "Device Direction", "Filter/Blocking Type", "URL",
    "User Name", "Client Host Name", "Process Name", "Web Reputation Rating",
    "Severity Level"
]
Header = ["Log Generation Date","Service Facility","IPv4 Address","Appliance Vendor", "Appliance Product", "Appliance Version","Event Name", "Event ID", "Severity"]


def WriteCsv(filename, header, DataList):
    """"
    Write Data to the csv file 
    """
    with open(filename, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for data in DataList:
            writer.writerow(data)


def WebSecurity(split_line):
    """
    --------------------------------
    CEF Web Security Logs
    --------------------------------
    deviceExternalId : ID
    rt : Log generation time
    app : Protocol
    cnt : Detections
    dpt : Server Port
    act : Action
    src : Endpoint IPv4 address
    cs1Label : SLF_PolicyName
    cs1 : External User Policy
    deviceDirection : Traffic/Connection
    cat : Filter/Blocking Type
    dvchost : Endpoint Host Name
    request : URL
    duser   : User name
    shost   : Client host name
    deviceProcessName : Process Name
    cn3Label :  ReputationScore
    cn3 : 49
    deviceFacility : Product
    cn2Label : SLF_SeverityLevel
    cn2 : Severity Level
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["deviceExternalId="] = parseData.find("deviceExternalId=")
    IndexKeys["rt="] = parseData.find("rt=")
    IndexKeys["app="] = parseData.find("app=")
    IndexKeys["cnt="] = parseData.find("cnt=")
    IndexKeys["dpt"] = parseData.find("dpt")
    IndexKeys["act"] = parseData.find("act")
    IndexKeys["src"] = parseData.find("src")
    IndexKeys["cs1Label"] = parseData.find("cs1Label")
    IndexKeys["cs1"] = parseData.rfind("cs1")
    IndexKeys["deviceDirection"] = parseData.find("deviceDirection")
    IndexKeys["cat"] = parseData.find("cat")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    IndexKeys["request"] = parseData.find("request")
    IndexKeys["duser"] = parseData.find("duser")
    IndexKeys["shost"] = parseData.find("shost")
    IndexKeys["deviceProcessName"] = parseData.find("deviceProcessName")
    IndexKeys["cn3Label"] = parseData.find("cn3Label")
    IndexKeys["cn3"] = parseData.rfind("cn3")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    IndexKeys["cn2Label"] = parseData.find("cn2Label")
    IndexKeys["cn2"] = parseData.rfind("cn2")
    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Web Security")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    split_line = split_line[:-1]
    split_line.extend(LineData)
    StorageIndex = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13, 14, 15, 16, 18, 21]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    WebsecurityData.append(Result)


def DeviceAccess(split_line):
    """
    ------------------------------------
    CEF Device Access Control Logs
    -----------------------------------
    rt : The log generation time in UTC
    cs1Label : Product Entity/Endpoint
    cs1 : Server host name
    shost : Source host name
    dvchost : Target host name
    cn1Label : Product
    cn1 : Product ID
    ************************
    sproc : Target Process
    fname : fname
    ************************
    cn2Label : Device Type
    cn2 : Example : "0"
    cn3Label : Permission
    cn3 : Example : "3"
    deviceFacility : Product
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["rt"] = parseData.find("rt")
    IndexKeys["cs1Label"] = parseData.find("cs1Label")
    IndexKeys["cs1"] = parseData.rfind("cs1")
    IndexKeys["shost"] = parseData.find("shost")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    IndexKeys["cn1Label"] = parseData.find("cn1Label")
    IndexKeys["cn1"] = parseData.rfind("cn1")
    IndexKeys["sproc"] = parseData.find("sproc")
    IndexKeys["fname"] = parseData.find("fname")
    IndexKeys["cn2Label"] = parseData.find("cn2Label")
    IndexKeys["cn2"] = parseData.rfind("cn2")
    IndexKeys["cn3Label"] = parseData.find("cn3Label")
    IndexKeys["cn3"] = parseData.rfind("cn3")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    # for k, v in list(IndexKeys.items()):
    #     if v == -1:
    #         del IndexKeys[k]
    if IndexKeys["sproc"] == -1:
        IndexKeys["sproc"] = IndexKeys["cn2Label"]
        IndexKeys["fname"] = IndexKeys["cn2Label"]

    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Device Access")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    StorageIndex = [0, 1, 4, 8, 9, 11, 13]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    DeviceData.append(Result)


def Spyware(split_line):
    """
    --------------------------
    CEF Spyware/Grayware Logs
    --------------------------
    deviceExternalId : ID
    rt : log generation time in UTC
    cnt : Number of detections
    dhost : Endpoint host name
    cn1 : Pattern type
    cs1Label : VirusName
    cs1 : Spyware/Grayware
    cs2Label : EngineVersion
    cs2 : 6.2.3027
    cs5Label : ActionResult
    cs5 : Action
    cs6Label : Pattern Version
    cs6 : 1297
    cat : Log Type
    dvchost : Endpoint host name
    fname
    filePath
    dst : Endpoint IPv4 address
    deviceFacility : Product
    fileHash : File SHA-1
    duser: User name
    cn2Label : Scan_Type
    cn2 : Scan_Type
    cn3Label : Security_Threat_Type
    cn3 : Adware
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["deviceExternalId"] = parseData.find("deviceExternalId")
    IndexKeys["rt"] = parseData.find("rt")
    IndexKeys["cnt"] = parseData.find("cnt")
    IndexKeys["dhost"] = parseData.find("dhost")
    IndexKeys["cn1Label"] = parseData.find("cn1Label")
    IndexKeys["cn1"] = parseData.rfind("cn1")
    IndexKeys["cs1Label"] = parseData.find("cs1Label")
    IndexKeys["cs1"] = parseData.rfind("cs1")
    IndexKeys["cs2Label"] = parseData.find("cs2Label")
    IndexKeys["cs2"] = parseData.rfind("cs2")
    IndexKeys["cs5Label"] = parseData.find("cs5Label")
    IndexKeys["cs5"] = parseData.rfind("cs5")
    IndexKeys["cs6Label"] = parseData.find("cs6Label")
    IndexKeys["cs6"] = parseData.rfind("cs6")
    IndexKeys["cat"] = parseData.find("cat")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    IndexKeys["fname"] = parseData.find("fname")
    IndexKeys["filePath"] = parseData.find("filePath")
    IndexKeys["dst"] = parseData.find("dst")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    IndexKeys["fileHash"] = parseData.find("fileHash")
    IndexKeys["duser"] = parseData.find("duser")
    if IndexKeys["fileHash"] == -1:
        IndexKeys["fileHash"] = IndexKeys["duser"]
    IndexKeys["cn2Label"] = parseData.find("cn2Label")
    IndexKeys["cn2"] = parseData.rfind("cn2")
    IndexKeys["cn3Label"] = parseData.find("cn3Label")
    IndexKeys["cn3"] = parseData.rfind("cn3")
    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Spyware")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    StorageIndex = [0, 1, 2, 3, 4, 8, 12, 17, 18, 19, 22, 24, 26]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    SpywareData.append(Result)


def Virus(split_line):
    """
    -----------------------------
    CEF Virus/Malware Logs
    -----------------------------
    deviceExternalId
    rt
    cnt
    dhost
    act
    cn1Label
    cn1
    cn2Label
    cn2
    cs1Label
    cs1
    cs2Label
    cs2
    cs3Label
    cs3
    cs4Label
    cs4
    cs5Label
    cs5
    cs6Label
    cs6
    dvchost
    cn3Label
    cn3
    fname
    filepath
    dst
    fileHash
    deviceFacility
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["deviceExternalId"] = parseData.find("deviceExternalId")
    IndexKeys["rt"] = parseData.find("rt")
    IndexKeys["cnt"] = parseData.find("cnt")
    IndexKeys["dhost"] = parseData.find("dhost")
    IndexKeys["act"] = parseData.find("act")
    IndexKeys["cn1Label"] = parseData.find("cn1Label")
    IndexKeys["cn1"] = parseData.rfind("cn1")
    IndexKeys["cn2Label"] = parseData.find("cn2Label")
    IndexKeys["cn2"] = parseData.rfind("cn2")
    IndexKeys["cs1Label"] = parseData.find("cs1Label")
    IndexKeys["cs1"] = parseData.rfind("cs1")
    IndexKeys["cs2Label"] = parseData.find("cs2Label")
    IndexKeys["cs2"] = parseData.rfind("cs2")
    IndexKeys["cs3Label"] = parseData.find("cs3Label")
    IndexKeys["cs3"] = parseData.rfind("cs3")
    IndexKeys["cs4Label"] = parseData.find("cs4Label")
    IndexKeys["cs4"] = parseData.rfind("cs4")
    IndexKeys["cs5Label"] = parseData.find("cs5Label")
    IndexKeys["cs5"] = parseData.rfind("cs5")
    IndexKeys["cs6Label"] = parseData.find("cs6Label")
    IndexKeys["cs6"] = parseData.rfind("cs6")
    IndexKeys["cat"] = parseData.find("cat")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    IndexKeys["cn3Label"] = parseData.find("cn3Label")
    IndexKeys["cn3"] = parseData.rfind("cn3")
    IndexKeys["fname"] = parseData.find("fname")
    IndexKeys["filePath"] = parseData.find("filePath")
    IndexKeys["dst"] = parseData.find("dst")
    IndexKeys["fileHash"] = parseData.find("fileHash")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Virus")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    Result = list()
    # StorageIndex = [0,1,2,3,4,5,9,11,17,19,21,25,26,27]
    StorageIndex = [0, 1, 2, 3, 4, 5, 9, 11, 17, 19, 21, 25, 26, 27, 28]
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    VirusData.append(Result)


def CallBack(split_line):
    """
    ---------------------
    C&C Callback Logs
    ---------------------
    deviceExternalId : ID
    rt : Log generation time in UTC
    deviceFacility : Product
    cs2Label : EI_ProductVersion
    cs2 : Product version
    shost : Endpoint host name
    src :  Enpoint IPv4 address
    cs3Label : SLF_DomainName
    cs3 : DOMAIN1
    act : Action
    cn1Label : SLF_CCCA_Risklevel
    cn1 : C&C risk level
    cn2Label : SLF_CCCA_DetectionSource
    cn2 : C&C list source
    cn3Label : SLF_CCCA_DetectionFormat
    cn3 : Callback address format
    dst : Callback IPv4 address
    deviceProcessName : Process Name
    dvchost
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["deviceExternalId"] = parseData.find("deviceExternalId")
    IndexKeys["rt"] = parseData.find("rt")
    IndexKeys["cat"] = parseData.find("cat")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    IndexKeys["cs2Label"] = parseData.find("cs2Label")
    IndexKeys["cs2"] = parseData.rfind("cs2")
    IndexKeys["shost"] = parseData.find("shost")
    IndexKeys["src"] = parseData.find("src")
    IndexKeys["cs3Label"] = parseData.find("cs3Label")
    IndexKeys["cs3"] = parseData.rfind("cs3")
    IndexKeys["act"] = parseData.find("act")
    IndexKeys["cn1Label"] = parseData.find("cn1Label")
    IndexKeys["cn1"] = parseData.rfind("cn1")
    IndexKeys["cn2Label"] = parseData.find("cn2Label")
    IndexKeys["cn2"] = parseData.rfind("cn2")
    IndexKeys["cn3Label"] = parseData.find("cn3Label")
    IndexKeys["cn3"] = parseData.rfind("cn3")
    IndexKeys["dst"] = parseData.find("dst")
    IndexKeys["deviceProcessName"] = parseData.find("deviceProcessName")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Callback")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    StorageIndex = [0, 1, 2, 7, 8, 10, 11, 13, 15, 17, 18, 19]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    CallbackData.append(Result)


def BehaviourMonitoring(split_line):
    """
    ----------------------------
    CEF Behavior Monitoring Logs
    ----------------------------
    rt
    dvchost
    cs5Label
    cs5
    cs2Label
    cs2
    sproc
    cs3Label
    cs3
    cs1Label
    cs1
    act
    cs4Label
    cs4
    shost
    src
    deviceFacility
    """
    parseData = split_line[-1]
    IndexKeys = dict()
    IndexKeys["rt"] = parseData.find("rt")
    IndexKeys["dvchost"] = parseData.find("dvchost")
    IndexKeys["cs5Label"] = parseData.find("cs5Label")
    IndexKeys["cs5"] = parseData.rfind("cs5")
    IndexKeys["cs2Label"] = parseData.find("cs2Label")
    IndexKeys["cs2"] = parseData.rfind("cs2")
    IndexKeys["sproc"] = parseData.find("sproc")
    IndexKeys["cs3Label"] = parseData.find("cs3Label")
    IndexKeys["cs3"] = parseData.rfind("cs3")
    IndexKeys["cs1Label"] = parseData.find("cs1Label")
    IndexKeys["cs1"] = parseData.rfind("cs1")
    IndexKeys["act"] = parseData.find("act")
    IndexKeys["cs4Label"] = parseData.find("cs4Label")
    IndexKeys["cs4"] = parseData.rfind("cs4")
    IndexKeys["shost"] = parseData.find("shost")
    IndexKeys["src"] = parseData.find("src")
    IndexKeys["deviceFacility"] = parseData.find("deviceFacility")
    Indexes = list(IndexKeys.values())
    LineData = list()
    LineData.append("Behaviour Monitoring")
    for i in range(1, len(Indexes)):
        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    StorageIndex = [0, 1, 4, 6, 7, 9, 11, 12, 14, 15, 16]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    BehaviourData.append(Result)


def NetworkContent(split_line):
    """
    --------------------------------------
    CEF Network Content Inspection Logs
    --------------------------------------
    deviceExternalId : ID
    rt : log generation time in UTC
    cat : Log Type
    deviceFacility : Product name
    deviceProcessName : Target Procss
    act : Action
    src : Source IPv4 address
    dst : Destination IPv4 address
    spt : Source Port
    dpt : Destination Port
    deviceDirection : Traffic/Connection
    cn1Label : SLF_PatternType
    cn1 : Pattern Type
    cs2Label : NICE_ThreatName
    cs2 : ThreatName
    dvchost 
    reason
    """
    parseData = split_line[-1]
    IndexKey = dict()
    IndexKey["deviceExternalId"] = parseData.find("deviceExternalId")
    IndexKey["rt"] = parseData.find("rt")
    IndexKey["cat"] = parseData.find("cat")
    IndexKey["deviceFacility"] = parseData.find("deviceFacility")
    IndexKey["deviceProcessName"] = parseData.find("deviceProcessName")
    IndexKey["act"] = parseData.find("act")
    IndexKey["src"] = parseData.find("src")
    IndexKey["dst"] = parseData.find("dst")
    IndexKey["spt"] = parseData.find("spt")
    IndexKey["dpt"] = parseData.find("dpt")
    IndexKey["deviceDirection"] = parseData.find("deviceDirection")
    IndexKey["cn1Label"] = parseData.find("cn1Label")
    IndexKey["cn1"] = parseData.rfind("cn1")
    IndexKey["cs2Label"] = parseData.find("cs2Label")
    IndexKey["cs2"] = parseData.rfind("cs2")
    IndexKey["dvchost"] = parseData.find("dvchost")
    IndexKey["reason"] = parseData.find("reason")
    Indexes = list(IndexKey.values())
    LineData = list()
    LineData.append("Network Content")
    for i in range(1, len(Indexes)):

        LineData.append(parseData[Indexes[i - 1]:Indexes[i]].strip())
    LineData.append(parseData[Indexes[-1]:])
    StorageIndex = [0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 15]
    Result = list()
    for index in StorageIndex:
        temp = LineData[index]
        temp = temp[temp.find("=") + 1:]
        Result.append(temp)
    NetworkData.append(Result)

def ParseContent(content):
    """
    Parse the content of a single file line by line
    """
    
    for line in content:
        split_pipe = line.strip().split("|")
        split_tab = split_pipe[0].strip().split("\t")
        LogHead = split_pipe[1:-1]
        split_tab.pop(3)
        split_tab.extend(LogHead)    
        Data.append(split_tab)
    
        if split_pipe[4][0:3] == "AV:":
            Virus(split_pipe)
        elif split_pipe[4] == "700107":
            DeviceAccess(split_pipe)
        elif split_pipe[4] == "Spyware Detected":
            Spyware(split_pipe)
        elif split_pipe[4][0:4] == "CnC:":
            CallBack(split_pipe)
        elif split_pipe[4][0:2] == "WB":
            WebSecurity(split_pipe)
        elif split_pipe[4][0:3] == "BM:":
            BehaviourMonitoring(split_pipe)
        elif split_pipe[4][0:5] == "NCIE:":
            NetworkContent(split_pipe)


def ReadSyslog(filename):
    """
    Read a syslog files in pwd
    """
    with open(filename) as File:
        content = File.readlines()
        ParseContent(content)


# Extract File Name
for filename in Filenames:
    """
    Iterate through all the log files in the present working directory.
    """
    
    ReadSyslog(filename)

WriteCsv("Syslog\\ProcessedData\\WebSecurity.csv", WebSecurityHeader, WebsecurityData)
WriteCsv("Syslog\\ProcessedData\\Virus.csv", VirusHeader, VirusData)
WriteCsv("Syslog\\ProcessedData\\Callback.csv", CallbackHeader, CallbackData)
WriteCsv("Syslog\\ProcessedData\\Behaviour.csv", BehaviourMonitoringHeader, BehaviourData)
WriteCsv("Syslog\\ProcessedData\\Spyware.csv", SypwareHeaderData, SpywareData)
WriteCsv('Syslog\\ProcessedData\\Network.csv', NetworkHeader, NetworkData)
WriteCsv("Syslog\\ProcessedData\\Device.csv", DeviceHeader, DeviceData)
WriteCsv("Syslog\\ProcessedData\\Syslog.csv",Header,Data)