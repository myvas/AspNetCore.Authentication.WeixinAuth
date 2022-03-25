@REM https://stackoverflow.com/questions/755382/i-want-to-delete-all-bin-and-obj-folders-to-force-all-projects-to-rebuild-everyt
@ECHO *************
@ECHO ** WARNING!
@ECHO ** This will delete all bin and obj folders!
@ECHO ** Press Ctrl-C to Cancel
@ECHO *************
@ECHO.
@PAUSE
@ECHO *************
@ECHO.

FOR /F "tokens=*" %%G IN ('DIR /B /AD /S bin') DO RMDIR /S /Q "%%G"
FOR /F "tokens=*" %%G IN ('DIR /B /AD /S obj') DO RMDIR /S /Q "%%G"

@ECHO.
@ECHO *************
@ECHO ** Completed! All bin and obj folders are deleted.
@ECHO *************
@ECHO.
@PAUSE