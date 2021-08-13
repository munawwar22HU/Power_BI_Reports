# Import Required Modules
import sys
import os
import pandas as pd
import pyodbc

# MSSQL Connection String
conn = pyodbc.connect(
    'Driver={SQL Server};''Server=DESKTOP-D8MO5LN\SQLEXPRESS;''Database=DB;''Trusted_Connection=yes;')
cursor = conn.cursor()


# Filenames
FileNames = ["CustomLog", "IntegrityMonitoring","LogInspection", "SystemEvents", "Global"]
DATE = sys.argv[1]
for i in range(5):
    FileNames[i]=FileNames[i]+"-"+DATE+".csv"
#DATE = "2021-08-04"

# Global Dataframe
GlobalDF = pd.read_csv(FileNames[4])
GlobalDF = GlobalDF.fillna(value="N/A")

# SystemEvents Dataframe
SystemEvents = pd.read_csv(FileNames[3])
SystemEvents = SystemEvents.fillna(value="N/A")

# LogInspection Dataframe
LogInspection = pd.read_csv(FileNames[2])
LogInspection = LogInspection.fillna(value=0)

# IntegrityMonitoring Dataframe
IntegrityMonitoring = pd.read_csv(FileNames[1])
IntegrityMonitoring = IntegrityMonitoring.fillna(value="N/A")

# CustomLog Dataframe
CustomLog = pd.read_csv(FileNames[0])
CustomLog = CustomLog.fillna(value="N/A")


# Traverse through Global DF row by row
for row in GlobalDF.itertuples():

    # Common Information for all Logs
    cursor.execute('''
        INSERT INTO DB.dbo.Syslog(RecievedOn,GeneratedOn,DeviceVendor,DeviceProduct,DeviceVersion,SignatureID,EventName,Severity,TrendMicroDsTenant)
        VALUES (?,?,?,?,?,?,?,?,?)
        ''',
                   row[2],              # RecieveOn
                   row[3],              # GeneratedOn
                   row.DeviceVendor,    # DeviceVendor
                   row.DeviceProduct,   # DeviceProduct
                   row.DeviceVersion,   # DeviceVersion
                   row.SignatureID,     # SignatureID
                   row.Name,            # EventName
                   row.Severity,        # Severity
                   "Primary")           # TrendMicroDsTenant
    # Get the id of the last syslog row that was inserted
    rs = cursor.execute("SELECT Max(idSyslog) from Syslog")
    id = rs.fetchone()[0]
    #  System Events
    if row.DeviceProduct == "Deep Security Manager":
        Value = SystemEvents.iloc[[row.EventId]].to_dict('index')

        cursor.execute('''
        INSERT INTO [dbo].[System](idSyslog,Source,SystemUser,Target,Message)
        VALUES (?,?,?,?,?)
        ''',
                       id,
                       Value[row.EventId]['src'],
                       Value[row.EventId]['suser'],
                       Value[row.EventId]['target'],
                       Value[row.EventId]['msg'])
    # Security_Events
    elif row.DeviceProduct == "Deep Security Agent":
        # Custom Log Inspection
        if (row.SignatureID == 40):
            Value = CustomLog.iloc[[row.EventId]].to_dict('index')
            cursor.execute('''
            INSERT INTO [dbo].[CustomLog](idSyslog,HostID,HostName,Description,TargetEntity,TargetUser,SourceHostName,Message)
            VALUES (?,?,?,?,?,?,?,?)
            ''',
                           id,
                           Value[row.EventId]['Host ID'],
                           Value[row.EventId]['dvc'],
                           Value[row.EventId]['LI Description'],
                           Value[row.EventId]['fname'],
                           Value[row.EventId]['duser'],
                           Value[row.EventId]['shost'],
                           Value[row.EventId]['msg'][0:1000])
        # Integrity Monitoring Events
        elif 2000000 <= row.SignatureID <= 2999999:
            Value = IntegrityMonitoring.iloc[[row.EventId]].to_dict('index')
            cursor.execute('''
            INSERT INTO [dbo].[IntegrityMonitoring](idSyslog,HostID,HostName,Action,FilePath,SourceUser,SourceProcess,Message)
            VALUES (?,?,?,?,?,?,?,?)
            ''',
                           id,
                           Value[row.EventId]['Host ID'],
                           Value[row.EventId]['Dvc'],
                           Value[row.EventId]['Act'],
                           Value[row.EventId]['filePath'],
                           Value[row.EventId]['suser'],
                           Value[row.EventId]['sproc'],
                           Value[row.EventId]['msg'][0:1000])
        # Log Inspection Events
        elif 3000000 <= row.SignatureID <= 3999999:
            Value = LogInspection.iloc[[row.EventId]].to_dict('index')
            cursor.execute('''
            INSERT INTO [dbo].[LogInspection](idSyslog,HostID,HostName,Description,TargetUser,SourceHostName,Message)
            VALUES (?,?,?,?,?,?,?)
            ''',
                           id,
                           Value[row.EventId]['Host ID'],
                           Value[row.EventId]['dvc'],
                           Value[row.EventId]['LI Description'],
                           Value[row.EventId]['duser'],
                           Value[row.EventId]['shost'],
                           Value[row.EventId]['msg'][0:1000])
    # Commit
cursor.commit()
for i in range(5):
    os.remove(FileNames[i])

