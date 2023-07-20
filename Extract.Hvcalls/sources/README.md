Extract.Hvcall utility automatically extract Hyper-V hypercalls names and codes extraction from next Windows binaries:

	securekernel.exe
	winhvr.sys
	winhv.sys
	ntoskrnl.exe
	
additionally can be added
 
	securekernella57.exe
	ntkrla57.exe

Uses IDA PRO for binary analysis

1. Download fresh version of idahunt plugin (https://github.com/nccgroup/idahunt) and place it in the directory with Extract.Hvcalls - idahunt can be used in some cases for disassembling binaries.
2. Install python plugins

pip install:
 sark
 pefile

3. Run Extract.Hvcalls.exe

![](./images/image001.png)

4. Select path to Windows binaries and IDA PRO
5. Click 'Start' button. Waiting, until IDA PRO finished script processing
6. Run python.exe hvcalls_merge.py.
7. You can see resulting json files inside "result" directory:
	hvcalls_results.json - list of Hyper-V hypercalls
	hvcalls_unknown.json - list of hypercalls name with unknown Hypercall code (you need do manual analysis for it)
	
I recommend extract hypercalls from winhvr.sys and winhv.sys first, then from other files.