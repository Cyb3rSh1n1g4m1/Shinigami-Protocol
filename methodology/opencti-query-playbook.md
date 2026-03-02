
# OpenCTI Query Playbook (Examples)

## ClickFix / User-assisted execution pivots
- technique:T1204 AND (label:ClickFix OR note:ClickFix OR description:clipboard)
- technique:T1059.001 AND (PowerShell OR "Win+R")

## TA571 pivots
- threat-actor:TA571 AND (indicator:* OR infrastructure:* OR malware:*)
- threat-actor:TA571 AND technique:T1189

## Storm-1811 pivots
- threat-actor:"Storm-1811" AND (tool:* OR malware:* OR technique:*)
- threat-actor:"Storm-1811" AND technique:T1219

## UNC3944 / Scattered Spider pivots
- threat-actor:UNC3944 AND (technique:T1078 OR technique:T1621 OR technique:T1589)
- threat-actor:"Scattered Spider" AND (identity OR helpdesk OR "MFA")

## Campaign pivots
- campaign:"ClickFix-to-Identity-Compromise" AND (indicator:* OR infrastructure:*)
- campaign:"ClickFix-to-Identity-Compromise" AND technique:*
