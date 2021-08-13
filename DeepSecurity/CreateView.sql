----System Events by Level
/*
CREATE VIEW  [System Events by Level] AS
select DATEPART(YEAR, sysl.GeneratedOn) 'Year', MIN(DATENAME(MONTH, sysl.GeneratedOn)) 'Month',MIN(DATEPART(DAY, sysl.GeneratedOn)) 'Day',sysl.Severity 'Event Severity', COUNT(*) 'Frequency'
from System syst  , Syslog sysl
where syst.idSyslog = sysl.idSyslog
group by sysl.Severity,DATEPART(YEAR, sysl.GeneratedOn),DATEPART(MONTH, sysl.GeneratedOn),DATEPART(DAY, sysl.GeneratedOn);
GO
*/

Select * from[System Events by Level]


-- TOP 25 Common EventNames
/*
CREATE VIEW [TOP 25 COMMON SYSTEM EVENTNAMES] AS
select top 25 count(*) '# of Events' , min(sysl.EventName) 'Event Name'
from System sys , Syslog sysl
where sys.idSyslog = sysl.idSyslog
group by sysl.EventName
order by count(*) desc;

GO
*/


SELECT * FROM [TOP 25 COMMON SYSTEM EVENTNAMES]

--25 Most Active Computers Ranked by Number of System Events
/*
ALTER VIEW [25 Most Active Computers Ranked by Number of System Events] AS
select top 25 count(*) '# of Events' , Target 'Computer'
from System sys , Syslog sysl
where sys.idSyslog = sysl.idSyslog and Target LIKE '%[0-9].%[0-9].%[0-9].%[0-9]%' 
group by Target
order by count(*) desc;
*/

 SELECT * FROM  [25 Most Active Computers Ranked by Number of System Events]



