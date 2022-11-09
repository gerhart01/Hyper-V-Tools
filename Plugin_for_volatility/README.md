#
# Hyper-V memory plugin for volatility. v1.0.20221109 
#

Installation instructions:

1. Download volatility3 from [Github](https://github.com/volatilityfoundation/volatility3) 
   
   2 files must be modified:

"volatility3\framework\layers\hyperv.py"
"volatility3\framework\automagic\stacker.py"

2. Install modules for volatility 3

```
	pip install -r requirements.txt
```

3. Copy hyperv.py to volatility3\framework\layers
4. Modify stacker.py (physical_layer) - you can see example file stacker.py in archive
   
   4.1. Insert in import section

```python
 #
 # hvlib integration
 #

 import os
 from volatility3.framework.layers import hyperv
 ```
      
    4.2. Find string "physical_layer = physical.FileLayer(new_context, current_config_path, current_layer_name)"
replace it with next code:

```python
 #
 # hvlib integration
 #

 dir_win = os.getenv('WINDIR')
 dir_win = dir_win.replace('\\','/').lower()

 hvlib_fn = "file:///"+dir_win+"/hvmm.dmp"
 if location.lower() == hvlib_fn:
    print("Hyper-V layer is active")
    physical_layer = hyperv.FileLayer(new_context, current_config_path, current_layer_name)
 else:
    physical_layer = physical.FileLayer(new_context, current_config_path, current_layer_name)
 ```


5. Copy hvlib.py, hvlib.dll and hvmm.sys to <python_dir>\Lib\site-packages (f.e. C:\Python39x64\Lib\site-packages or C:\Python310x64\Lib\site-packages).
	If you use some python virtual environment plugins, you need to copy files inside it:
	for example to venv\Lib\site-packages for virtualenv.
6. Copy file hvmm.dmp to C:\Windows\hvmm.dmp (it needed, because volatility needs to read real file)
7. Execute

python.exe vol.py -vv -f "C:\windows\hvmm.dmp" windows.pslist

![](./images/image001.png)

if you have problem with kernel signature scanning you need change PDB-finding alghorithm