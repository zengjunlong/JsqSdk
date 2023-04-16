set snparams=/a /v /n "your certificate name"
set snparams=%snparams% /tr "timestamp server"
set snparams=%snparams% /du "company"
set snparams=%snparams% /d "your certificate name"
set snparams=%snparams% /fd sha256
set snparams=%snparams% /td sha256 

%~dp0\signtool\SignTool.exe sign %snparams% %1
