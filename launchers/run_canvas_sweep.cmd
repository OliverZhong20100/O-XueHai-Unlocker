@echo off
set PYTHONIOENCODING=utf-8
set PYTHONPATH=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest\pylibs
set BASE=C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\oAN1i2VRVDeZQaMsrRqanPxYuhcU\workspace\conv_19f78e04910_fcda16370b95\output\sm-p200-takeover\pentest
set PYS=D:\Program Files\Tencent\Marvis\MarvisAgent\1.60.3000.716\runtime\python311\python.exe
"%PYS%" "%BASE%\canvas_sweep.py" > "%BASE%\canvas_sweep_out.txt" 2>&1
echo canvas_sweep_done
