# PPIDSpoof

Security solutions and defenders will often look for abnormal parent-child relationships. For example, if Microsoft Word spawns cmd.exe this is generally an indicator of malicious macros being executed. If cmd.exe is spawned with a different PPID then it will conceal the true parent process and instead appear as if it was spawned by a different process.

This helps evade detections that are based on anomalous parent-child process relationships. When I started learning and implementing this technique, the first question that popped into my mind is what parent-child process relationship should I spoof.

Using Process Hacker, I noticed several instances of the RuntimeBroker.exe process running under the parent process svchost.exe. If this parent-child process relationship is common, then this is a good candidate for spoofing.
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/af77ae2d-7d71-4b9f-a76b-5988fe0cf530)

usage:
![grafik](https://github.com/Spnl48/PPIDSpoof/assets/68971838/4ef1bd0a-ae26-4946-a49d-0e063ea9914d)


DEMO
When choosing the Parent Process To spoof, you should choose a process with Medium Integrity Level. However, the code didn’t work as expected and we got an “Access is denied” error.

![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/ffa715f2-3173-4cb6-810f-b0cd01284123)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/787af28d-9c59-4a4c-b276-513197021136)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/a2a8f7d3-7f5b-439d-89fc-f1021f5aa290)
![image](https://github.com/Spnl48/PPIDSpoof/assets/68971838/389d9c99-2e0e-4120-af16-424a4a929ab9)


