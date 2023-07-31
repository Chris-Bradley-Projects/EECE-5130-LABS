# EECE-5550-LAB#2 Buffer Overflow Attack Lab

### Title and Author

* **Title:** *EECE Buffer Overflow Attack Lab*
* **Author:** *Christopher Bradley*

### Purpose of Buffer Overflow Attack Lab #2

* The Purpose of this lab is to use four different servers, each running a program with a buffer-overflow vulnerability. In the lab I develop a scheme to exploit the vulnerability and gain the root privilege on these servers. Also the lab explores dealing with several countermeasures against buffer-overflow attacks. The four main topics of the lab are Buffer overflow vulnerability and attack, Stack layout in a function invocation, Address randomization Non-executable stack/StackGuard, and Shellcode.

**File Overview:**

* Labsetup - This folder contains all the servers for each attack level and contains the boiler plate code for creating the attacks on the server.
* task1_shellcode_delete_file.py - Contins the code for delting a file for task 1
* task2_custom_exploit.py - contains the code for creating a custom command asked for in task 2
* task2_reverse_shell_exploit.py - contains the code for the reverse shell in task2 
* task3_reverse_shell_exploit.py - contains the code for the reverse shell in task 3
* task4_reverse_shell_exploit.py - contains the code for the reverse shell in task 4
* task5_reverse_shell_exploit.py - contains the code for the reverse shell in task 5
* task 6 and 7 do not invlove changing the exploit file. The prevoius exploit files are used.

**Code SnapShots and Explanation**
* Tasks #1
  * Below shows the code used to delete a file using shellcode. The second picture shows the file that was created to be deleted.
    * ![Deleting a file](/Images/LAB2/task1_delete_file.png)
    * ![The File to delete](/Images/LAB2/task1_file_to_delete.png)
* Tasks #2
  * Part #1: Below shows the code used to exploit the server and plant a temp file. The second photo shows the command being excuted on the server.
    * ![temp file created](/Images/LAB2/task2_tmp_file_created.png)
    * ![virus file created on server](/Images/LAB2/task2_virus_created.png)
  * Part #2: Below shows the code used to exploit the sever and get a root shell. 
    * ![Reverse shell code](/Images/LAB2/task2_reverse_shell_code.png)
    * ![Reverse shell photo](/Images/LAB2/task2_reverse_shell.png)
* Tasks #3
  * Below shows the code used to exploit the server and get a root shell. For this one we had to update becasue we were not given edp. This made the attack more complicated.
    * ![Reverse Shell code](/Images/LAB2/task3_reverse_shell_code.png)
    * ![Reverse Shell photo](/Images/LAB2/task3_reverse_shell.png)
* Tasks #4
  * Below shows the code used to exploit the server and get a root shell. For this one we had to update the shellcode to 64-bit version and update the edp and buffer address to corespond with server 3.
    * ![ProjectClient Loop](/Images/LAB2/task4_reverse_shell.png)
* Tasks #5
  * Below shows the code used to exploit the sever and get a root shell. This one is very similar to task#4 except the offset had to be updated becasue of the smaller distance between the frame pointer and buffer.
    * ![ProjectMain Queue](/Images/LAB2/task5_reverse_shell.png)
* Tasks # 6
  * The first picture below shows that now when you send a badfile to the server each time the edp address and buffer change. This was becasue randomization was turned back on. The second picture shows it took 44022 times before the brute force method worked. The third picture shows that I got access to the root shell.
    * ![Address changes each time](/Images/LAB2/task6_address_change.png)
    * ![Took 44022 tries to get root](/Images/LAB2/task6_44022_for_root.png)
    * ![Root shell from server](/Images/LAB2/task6_got_root.png)
* Tasks # 7
  * Part A: The picture below shows that now the badfile is being rejected. The stack prevention made it so the shell code in the badfile does not get run and the process aborted. This is becasue of the stack protection.
    * ![Stack detected](/Images/LAB2/task7a_stack_detected.png)
  * Part B: Below shows that since I changed the options to now be non executable we get a segmentation fault when trying to execute the shellcode.
    * ![Segmentation Fault](/Images/LAB2/task7b_segmentation_fault.png)