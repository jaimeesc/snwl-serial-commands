# snwl-serial-commands


## SonicWall Serial Console Automation Tool for SonicOS

### ***This project is a work in progress.***


TO-DO list:

- [ ] Logging output split into multiple files. Probably something like **<launch_timestamp>\<scheduled_job_execution_timestamp>.log**


- [X] CLI arguments/help. (added in 0.4)

Use the -h argument for more information.


- [X] Friendly configuration file. (added in 0.4)

Configuration is done *snwl_config.ini*.


- [X] Input files with the list of CLI commands to run. (added in 0.4)

Check out the updated **how to use the program** section.

---
## **So what can you do with it?**

- Log console output to separate text files without any special configuration.


- Automatically gather diagnostic data (once or on a configurable interval) from a firewall connected via the serial console.


- Type up your own text file of SonicOS CLI commands to run and pass that to the tool to run for you at an interval or once manually.


- Quickly configure devices over CLI!


- Monitor active VPN tunnels, uptime, etc!


- Pull just about anything. If the SonicOS CLI can spit out the info, you can log the info to the output file or add your own functions to handle the console response differently.


- Choose to display the console output on the screen or hide it to only display limited status information. Use the -d CLI argument to display all output from the console. There's colored output so this argument is definitely worth checking out! I recommend it when first testing jobs to make sure they work the way you're expecting.


- Write snippets of CLI commands into jobs (TXT files) and group them into a scheduled job configuration INI files. These files can be used as templates to automate configuration of firewalls via the CLI.



## **Requirements:**

1. Python 3.6 or later.


2. There are some modules that need to be installed. Use "pip3 install -r requirements.txt" to install the dependencies.


3. Optional: Use the Windows Terminal app instead of a CMD or PowerShell window. It is a nicer experience :).



## **Features:**

Automatically authenticates to the console session and detects if there's an existing logged-in session.
Detects if the device stops responding and recovers.
Automatically re-authenticates when the session is logged out.
Option to display console output on the screen, with color text.
Commands and CLI prompts are displayed in color to easily differentiate them from other console output.
Fancy colors and spinner in the terminal – Use the 'Windows Terminal' app for the best experience.
Windows PowerShell app and Windows Command Prompt do not display the spinner. Instead, there are characters that can't be displayed properly.



## **Notes:**

- Only tested on Windows 10. I imagine it can work on other operating systems, but I haven't tested them.


- I have not tested this on macOS or any Linux distros.


- I have not tested this with any multi-blade firewalls.



## **FAQ:**

Does this work with SSH Management or SonicOS API?

**No. This is for the Serial Console CLI only.**



## **How to use the program:**

This program has 2 modes: 'Single Job Mode' and 'Scheduled Job Mode'.

Single Job Mode executes an input job file once, logs the output, and quits. A job file is a TXT file containing CLI commands (one command per line).

Scheduled Job Mode reads a scheduled job INI file and runs the configured jobs on an interval. 
An example scheduled job configuration INI is included with this program.

By default, displayed output is limited. Use -d to display all output.

**Quick Start:**
1. Configure the serial port, SonicOS credentials, and other settings in snwl_config.ini.


2. Write your custom jobs. There are some example jobs in the jobs folder.


3. To use Scheduled Job Mode, edit scheduled_jobs.ini or make a copy and edit it. Configure any number of scheduled jobs that each reference a job TXT file. Set an interval for each job (in seconds).


4. Open Windows Terminal You can use CMD or PowerShell too, but Windows Terminal's output looks better and supports the spinner.


Single Run Mode:
> python3 snwl-serial.py job.txt

> python3 snwl-serial.py job.txt -d

Scheduled Job Mode:
> python3 snwl-serial.py scheduled_jobs.ini

> python3 snwl-serial.py scheduled_jobs.ini -d


5. Use CTRL+C to quit.
