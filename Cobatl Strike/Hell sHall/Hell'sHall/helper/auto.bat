@echo off
setlocal

:: Tools
set "AES_TOOL=CypherAES.exe"
set "STEGO_TOOL=OEFInjection.exe"
set "CONVERT_BIN=CtoBin.py"

:: Output folder
set "OUTPUT=output"
if not exist "%OUTPUT%" mkdir "%OUTPUT%"

echo ===========================================
echo AES Encrypt + EOF Stego Inject Script
echo ===========================================
echo [!] Press any key to start 
pause >nul


for %%F in (*.c) do (
  if exist "%%F" (
    echo [*] Converting .c file : %%F
    python3 "%CONVERT_BIN%" "%%F" "%%~nF.bin"
  )
  echo [!] Save as "%%~nF.bin"
  echo ----------------------------------------------
)

	  
:: For each data file (*.txt, *.bin)
for %%D in (txt bin) do (
  for %%F in (*%%D) do (
    if exist "%%F" (
      echo [*] Encrypting payload file: %%F
      "%AES_TOOL%" --encrypt "%%F" "%OUTPUT%\%%~nF_blob.enc"
      if errorlevel 1 (
        echo [!] Encryption failed: %%F
      ) else (
        :: For each image (*.png, *.jpg, *.jpeg, *.bmp, *.ico)
        for %%E in (png jpg jpeg bmp ico) do (
          for %%I in (*%%E) do (
            if exist "%%I" (
              echo    	[+] Injecting into: %%I
              "%STEGO_TOOL%" --inject "%%I" "%OUTPUT%\%%~nF_blob.enc" "%OUTPUT%\%%~nI_%%~nF_stego%%~xI"
              if errorlevel 1 (
                echo [!] Injection failed: %%I
              ) else (
                echo    	[+] %OUTPUT%\%%~nI_%%~nF_stego%%~xI
              )
            )
          )
        )
      )
    )
  )
)

echo ===========================================
echo Done. Output saved in: "%OUTPUT%"
echo Press any key to exit...
pause >nul
