@echo off
set arg1=%1
set message=Conversion complete
C:/Users/munaw/AppData/Local/Programs/Python/Python37-32/python.exe C:/PowerBI/Power_BI_Reports/DeepSecurity/SyslogToCsv.py %arg1%
echo %message%
C:/Users/munaw/AppData/Local/Programs/Python/Python37-32/python.exe C:/PowerBI/Power_BI_Reports/DeepSecurity/CsvToSql.py %arg1%
pause