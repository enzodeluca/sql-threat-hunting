-- THREAT HUNTING SUITE: LOG ANALYSIS & ANOMALY DETECTION
-- TARGET DATASET: Enterprise Authentication Logs
-- Objective: Identify high-frequency authentication failures per account.
-- Security Context: Distinguishes a standard user typo from an active, automated attack.

select Employee_ID, IP_Address, COUNT(*) as Failed_Attempts
from Authentication_Logs
where Success_Failure = 'Failure'
group by Employee_ID, IP_Address
having count(*) >= 5
order by Failed_Attempts DESC;

-- Objective 2: Detect concurrent successful logins for a single identity across 
-- distinct geographic locations within an impossible physical transit window.
-- Security Context: Flag compromised account credentials being bypassed globally.

select 
    t1.Employee_ID, 
    t1.Login_Time as First_Login, 
    t1.Location as First_Location,
    t2.Login_Time as Second_Login,
    t2.Location as Second_Location
from Authentication_Logs t1
join Authentication_Logs t2
    on t1.Employee_ID = t2.Employee_ID
where
    t1.Location <> t2.Location
and t1.Success_Failure = 'Success'
and t2.Success_Failure = 'Success'
and t2.Login_Time > t1.Login_Time
AND t2.Login_Time <= t1.Login_Time + INTERVAL '1' HOUR;