@echo off
pyinstaller --onefile ^
    --add-data "images\BLAHPR.jpg;images" ^
    --add-data "data;data" ^
    --add-data "images\BLAHPR.ico;images" ^
    --icon "images\BLAHPR.ico" ^
    --upx-dir "D:\upx-5.0.2-win64" ^
    --name "Blahpr Net" ^
    --distpath "Blahpr Net" ^
    BlahprNet.pyw

echo.
pause
