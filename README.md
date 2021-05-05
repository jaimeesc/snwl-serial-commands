# snwl-serial-commands


## SonicWall Serial Console Automation Tool for SonicOS.

## ***This project is a work in progress.***

It is currently functional but requires configuration directly in the script file.

The tool will be updated to support the following:

- [ ] Logging output split into multiple files. Probably something like **<launch_timestamp>\<scheduled_job_execution_timestamp>.log**


- [ ] CLI arguments/help.


- [ ] Friendly configuration file.


- [ ] Input files with the list of CLI commands to run.


---
## **So what can you do with it?**

- Log console output to separate text files without any special configuration.


- Automatically gather diagnostic data (once or on a configurable interval) from a firewall connected via the serial console.


- Type up your own text file of SonicOS CLI commands to run and pass that to the tool to run for you at an interval or once manually.


- Quickly configure devices over CLI!


- Monitor active VPN tunnels, uptime, etc!


- Pull just about anything. If the SonicOS CLI can spit out the info, you can log the info to the output file or add your own functions to handle the console response differently.


- Choose to display the console output on the screen or hide it to only display limited status information.


---
## **Requirements:**

1. Python 3.6 or later.


2. There are some modules that need to be installed. Use "pip3 install -r requirements.txt" to install the dependencies.


3. Optional: Use the Windows Terminal app instead of a CMD or PowerShell window. It is a nicer experience :).

---
## **Features:**

Automatically authenticates to the console session and detects if there's an existing logged-in session.
Detects if the device stops responding and recovers.
Automatically re-authenticates when the session is logged out.
Option to display console output on the screen, with color text.
Commands and CLI prompts are displayed in color to easily differentiate them from other console output.
Fancy colors and spinner in the terminal – Use the 'Windows Terminal' app for the best experience.
Windows PowerShell app and Windows Command Prompt do not display the spinner. Instead, there are characters that can't be displayed properly.


---
## **Notes:**

- Only tested on Windows 10. I imagine it can work on other operating systems, but I haven't tested them.


- I have not tested this on macOS or any Linux distros.


- I have not tested this with any multi-blade firewalls.


---
## **FAQ:**

Does this work with SSH Management or SonicOS API?

**No. This is for the Serial Console CLI only.**



---
## **How to run the script:**

> py snwl-serial.py

OR

> python3 snwl-serial.py


