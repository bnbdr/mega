@echo off

set aclbkup=patch.acl
set target=C:\Windows\system32\ExplorerFrame.dll
if [%1]==[] goto usage

REM backup perms and original file
echo saving backup of original dll
copy %target% %target%.orig   >NUL 2>&1 || goto :ERROR
echo saving original permissions 
icacls %target% /save %aclbkup% >NUL 2>&1 || goto :ERROR

echo.
REM give ownership of file to administratos, allow write
echo taking ownership
takeown /F %target% /A >NUL 2>&1 || goto :ERROR
echo changing permissions
icacls %target% /grant Administrators:(W)  >NUL 2>&1 || goto :ERROR


REM kill processes that use the dll
echo.
echo killing processes with handles 
taskkill /im explorer.exe /f  >NUL 2>&1
taskkill /im rundll32.exe /f  >NUL 2>&1
taskkill /im firefox.exe /f  >NUL 2>&1
call :slp

echo overwriting target
copy /Y %1 %target%  >NUL 2>&1 || goto :ERROR
call :slp

echo.
echo restarting explorer
start explorer

echo.
echo trying to restore permissions and ownership
icacls %target% /grant Administrators:(F)  >NUL 2>&1 || goto :ERROR
echo restoring ownership
icacls %target% /setowner "NT SERVICE\TrustedInstaller" >NUL 2>&1 || goto :ERROR
echo restoring permissions
icacls C:\Windows\system32\ /restore %aclbkup%  >NUL 2>&1 || goto :ERROR

echo Done!
echo.
echo.
echo Enjoy :)
exit /B


:slp
echo sleeping
ping 127.0.0.0 -n 2 >NUL
exit /B

:usage
echo Usage: install.bat [patched-dll]
exit /B 1

:ERROR
echo FAILED
exit /B 