# SonicWall Serial Console Automation Tool for SonicOS


![Screenshot](https://github.com/jaimeesc/snwl-serial-commands/blob/c5cf760729200223eba4ff36d1f7c89c8ca55851/screenshot.png)

Check out the updated **how to use the program** section.

---
## **So what can you do with it?**

- Log console output to separate text files without any special configuration. Logs files are split by hour, place into a folder created at launch.

**<launch_timestamp>\<date_hour>.log**


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
Fancy colors and spinner in the terminal – Use the 'Windows Terminal' app for the best experience.
Windows PowerShell app and Windows Command Prompt do not display the spinner. Instead, there are characters that can't be displayed properly.



## **Notes:**

- Tested mainly on Windows 10, but also works on macOS.


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

The -u argument accepts your management username and prompts you for the password so it doesn't have to be stored in plain text in snwl_config.ini. You still have the option to save the credentials in snwl_config.ini, but using -u overrides that configuration.

**Quick Start:**
1. Configure the serial port, SonicOS credentials (or use -u), and other settings in snwl_config.ini.


2. Write your custom jobs. There are some example jobs in the jobs folder.


3. To use Scheduled Job Mode, edit scheduled_jobs.ini or make a copy and edit it. Configure any number of scheduled jobs that each reference a job TXT file. Set an interval for each job (in seconds).


4. Open Windows Terminal You can use CMD or PowerShell too, but Windows Terminal's output looks better and supports the spinner.


Pass in a TXT file to run in Single Run Mode:
> python3 snwl-serial.py job.txt

Optionally run with all console output displayed:
> python3 snwl-serial.py job.txt -d

Optionally supply credentials at run time without saving to the config file:
> python3 snwl-serial.py job.txt -u admin

> python3 snwl-serial.py job.txt -d -u admin

Pass in an ini file to run in Scheduled Job Mode:
> python3 snwl-serial.py scheduled_jobs.ini

> python3 snwl-serial.py scheduled_jobs.ini -d

> python3 snwl-serial.py scheduled_jobs.ini -d -u admin

Use -h for help.

> python3 snwl-serial.py scheduled_jobs.ini -h

5. Use CTRL+C to quit.
