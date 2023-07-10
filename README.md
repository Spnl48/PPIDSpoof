# PPIDSpoof

> Security solutions and defenders will often look for abnormal parent-child relationships. For example, if Microsoft Word spawns cmd.exe this is generally an indicator of malicious macros being executed. If cmd.exe is spawned with a different PPID then it will conceal the true parent process and instead appear as if it was spawned by a different process.

**This helps evade detections that are based on anomalous parent-child process relationships.**



## usage:
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/bbe36430-70f4-4091-8293-8cc453330f80)


DEMO

> When choosing the Parent Process To spoof, you should choose a process with Medium Integrity Level. However, the code didn't work as expected and we got an “Access is denied” error.

**in this case, we choose svchost with Medium Integrity Level and RuntimeBroker.exe and spawn child process.**

![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/c93184fa-e7f3-40ad-b748-d6aaa9c6e5ee)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/1677760e-4548-4419-a5cf-fc8c7aaef925)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/f8cc3d44-a991-4cd6-b10e-9a01f7ee3745)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/d68b3d80-ac37-4c71-a95c-4e5be3ced0d4)



