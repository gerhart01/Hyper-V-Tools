Extract.Hvcall (Hvcall GUI - GUI interface for extract_hvcalls.py IDA PRO script) utility for automatically extraction of Hyper-V hypercalls names and code numbers from Hyper-V core binaries:

	securekernel.exe
	winhvr.sys
	winhv.sys
	ntoskrnl.exe
	
additionally can be added
 
	securekernella57.exe
	ntkrla57.exe

Use IDA PRO for binary analysis

1. Download fresh version of idahunt plugin (https://github.com/nccgroup/idahunt) and place it in the directory with Extract.Hvcalls - idahunt can be used in some cases for disassembling binaries.
2. Install python plugins

```python
pip install:
 sark
 pefile
 
 or
 
 pip install -r requirements.txt
 
```

3. Run Extract.Hvcalls.exe

![](./images/image001.png)

4. Select path to Hyper-V core binaries and IDA PRO or modify config.json in program folder (preferably for multiple runs)
5. Click 'Start' button 
6. Waiting, until IDA PRO finished script processing
7. You can see resulting json files inside "result" directory:
	hvcalls_results.json - list of Hyper-V hypercalls
	hvcalls_unknown.json - list of hypercalls name with unknown Hypercall code (you need do manual analysis for it)
	
I recommend extract hypercalls from winhvr.sys and winhv.sys first, then from other files
If you have problems with extraction results try to prepare IDA PRO database manually and save it in i64 files as usual

GPL3 License