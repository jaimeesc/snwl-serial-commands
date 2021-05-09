# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# .d88888b                    oo          dP   dP   dP          dP dP
# 88.    "'                               88   88   88          88 88
# `Y88888b. .d8888b. 88d888b. dP .d8888b. 88  .8P  .8P .d8888b. 88 88
#       `8b 88'  `88 88'  `88 88 88'  `"" 88  d8'  d8' 88'  `88 88 88
# d8'   .8P 88.  .88 88    88 88 88.  ... 88.d8P8.d8P  88.  .88 88 88
#  Y88888P  `88888P' dP    dP dP `88888P' 8888' Y88'   `88888P8 dP dP
#
#	     -- Serial Console Automation Tool for SonicOS --
#
#		Development Team -- The SMART Associates
# 			Jaime Escalera (jescalera@sonicwall.com)
# 			Alexis Diaz (adiaz@sonicwall.com)
#
# Written with love by The SMART Associates
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
version_string = "0.7"


# Import these modules
import serial
import schedule
import os
import argparse
import configparser
from time import sleep
from datetime import datetime, timezone
from getpass import getpass
from rich import print
from yaspin import yaspin, kbi_safe_yaspin
from yaspin.spinners import Spinners


# Argument handling
argP = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                               description="""This program has 2 modes: 'Single Job Mode' and 'Scheduled Job Mode'.

Single Job Mode executes an input job file once, logs the output, and quits.
    A job file is a TXT file containing CLI commands (one command per line).

Scheduled Job Mode reads a scheduled job INI file and runs the configured jobs on an interval.
    All console output is logged while the program is running.
    An example scheduled job configuration INI is included with this program.

By default, displayed output is limited. Use -d to display all output.

Configure the serial port and other settings in snwl_config.ini.""")
argP.add_argument("filename",
                  metavar="<SCHEDULED JOB CONFIGURATION INI OR JOB TXT FILE>",
                  help="Provide an INI or TXT file as input. A TXT file containing CLI commands to run (one command per line) or a scheduled job configuration INI file.",
                  type=str)
argP.add_argument("--display_all_output", "-d",
                  help="Display all console output. If this argument is not used (default), less output is displayed. ",
                  action="store_true")
argP.add_argument("--user", "-u",
                  help="Provide the management username. You will be prompted to enter the password.",
                  type=str)
args = argP.parse_args()


# Set a variable for the path to the local files (serverconfig.ini, etc.)
script_path = os.path.dirname(os.path.realpath(__file__))
config_file = os.path.join(script_path, 'snwl_config.ini')

# Initialize the configuration parser
config = configparser.ConfigParser()
scheduled_jobs_config = configparser.ConfigParser()
config.read(config_file)


# Print console output False prints start/end messages for each command executed.
# True prints all console output. Either way, output is still saved to a log file.
if args.display_all_output:
    display_all_output = True
else:
    # Spinner initialized if printing output is disabled
    display_all_output = False
    spinner = yaspin()
    spinner.color = 'cyan'
    spinner.spinner = Spinners.earth


# Custom exit function
def custom_exit():
    if not display_all_output:
        spinner.stop()
        # In case CTRL+C is sent before hitting the main function.
    print()
    print("[bold red]Terminated![/]\n")
    exit()


# Settings
# Firewall credentials.
if args.user:
    try:
        credentials = {
            "user": args.user,
            "password": getpass()
        }
    except KeyboardInterrupt:
        custom_exit()
else:
    credentials = {
        "user": config['CREDENTIALS']['user'],
        "password": config['CREDENTIALS']['password']
    }

# Parameters for use within SonicOS.
sonicos_params = {
    "disable_cli_paging": config.getboolean('SONICOS', 'disable_cli_paging')
}

# Prompts dictionary
prompts = {
    'sos_prompt': credentials['user'] + "@",
    'sos_prompt_config': ")# ",
    'shell_prompt': "-> ",
    'ospf_prompt': "ARS OSPF>",
    'ospfv3_prompt': "ARS OSPFv3>"
}

# Serial connection parameters.
# SonicWall: 115200 baud, 8 data bits, 1 stop bit, no parity, no flow control.
# RX/TX buffer size: on Windows, send a recommendation to the driver to use this buffer size.
serial_params = {
    'com_port': config['DEFAULT']['com_port'],
    'baud': 115200,
    'data_bits': serial.EIGHTBITS,
    'stop_bits': serial.STOPBITS_ONE,
    'parity': serial.PARITY_NONE,
    'xonxoff': False,
    'rx_buffer_size': int(config['DEFAULT']['rx_buffer_size']), # (512800: 512.8 Kilobytes)
    'tx_buffer_size': int(config['DEFAULT']['tx_buffer_size']) # (512800: 512.8 Kilobytes)
}


# Timestamp generator
def generate_timestamp():
    current_time = datetime.now(timezone.utc).astimezone()
    current_time = str(current_time)
    return current_time


# Send input to the console and wait a short time for the response
def send_to_console(ser: serial.Serial, command: str,
                    prepend_enter_key: float = True,  # Explained below
                    wait_time: float = 0.5, # Time to wait for command to process
                    process_response: float = False,  # Process response immediately (don't wait for loop)
                    print_before='',
                    print_after=''):

    # If printing something before executing the command.
    if print_before:
        if len(print_before) > 0:
            print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: {print_before}")


    # In some cases, you may need to send the command without first hitting Enter.
    # I prepend \r for cosmetic purposes... so the command runs on a line w/ a prompt.
    # Sometimes the command will run on what appears to be a new line and can look odd. For example, a command
    # may appear to run while at a User: prompt when the user is already logged in thus should be a SonicOS prompt.
    # When you don't want to first send ENTER (like at the user and password prompts), use prepend_enter_key=False
    if not prepend_enter_key:
        # prepend_enter_key = False
        command_to_send = command + "\r"
    else:
        # prepend_enter_key = True
        command_to_send = "\r" + command + "\r"

    # Write the command to the serial console.
    ser.write(command_to_send.encode('utf-8'))

    # Try to wait for a short time for the command to complete.
    try:
        if not display_all_output:
            spinner.start()
        sleep(wait_time)
    except KeyboardInterrupt:
        custom_exit()
#        print("Cancelled!")
#        exit()

    # If the command was sent with kwarg process_response True, process the command now.
    if process_response:
        # If the command was sent with a message to print after processing
        if print_after:
            # Process the console response with the message attached.
            process_console_response(after_process_msg=print_after)
        else:
            # Process the console response without a message.
            process_console_response()


# Shortcut function to disable paging in the CLI
def disable_cli_paging():
    # Disable the CLI paging in SonicOS for this login session.
    if sonicos_params["disable_cli_paging"]:

        # Stop the spinner before printing.
        if not display_all_output:
            spinner.stop()

        print(f"[green]Disabling CLI paging for this login session.[/green]")
        if not display_all_output:
            spinner.start()

        # Send the command.
        send_to_console(sc, "no cli pager session", wait_time=0.1)

        # Process the command now. This limits the return buffer size/length of the response.
        # If we don't process the response now, the buffer response is included in the next command.
        process_console_response()


# Extract active VPN tunnel names and gateway IP.
def report_active_tunnels():
    # Verify a prompt is up/device response.
    # Use scheduled_job=True to avoid additional prints that one would usually only want to see the first time.
    verify_console_response(scheduled_job=True)

    # Run the command to show the active IPSec tunnels.
    # Force processing to occur within this function w/ process_response=False.
    # The processing for this command is being handled differently than other console responses
    # that are processed by process_console_response()
    send_to_console(sc, "show vpn tunnels ipsec", process_response=False)

    # Get the console response.
    r = sc.readlines()

    # Write output to the console log file.
    write_output_to_file(r)

    # Stop the spinner and print a message.
    if not display_all_output:
        spinner.stop()
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [cyan]Displaying active IPSec VPN tunnels (show vpn tunnels ipsec)[/cyan]")

    # Empty dictionary and list for active VPNs.
    active_tunnels = {}
    active_tunnel_names = []

    # Iterate over the command response.
    c = 0
    for i in r:
        # Find the policy name
        if i.decode().startswith("Policy:"):
            #active_tunnels.get(i.decode().split('Policy: ')[-1], "")
            # Append the name to a list for later use.
            active_tunnel_names.append(i.decode().split('Policy: ')[-1].strip('\r\n'))
        # Find the IPSec Gateway
        elif i.decode().lstrip().startswith("GW:"):
            # Update the dictionary with the active tunnel info. Print the info.
            active_tunnels.update({active_tunnel_names[c]: i.decode().split('GW: ')[-1]})
            print(f"[yellow]{active_tunnel_names[c]}:[/] [yellow]{active_tunnels[active_tunnel_names[c]]}[/]")
            c += 1

    # Redundant code. Code above prints out the same.
    # An example of more stuff you can do with the dictionary of active VPNs.
    # Maybe use another module to send a notification.
    # If the list of tunnel is at least 1
    # if len(active_tunnels) > 0:
    #     # Print out the active tunnel info.
    #     for k, v in active_tunnels.items():
    #         print(f"[magenta]{k}: {v}[/magenta]")
    # else:
    #     print("[yellow]No active tunnels.[/yellow]")

    if len(active_tunnels) < 1:
        print("[yellow]No active tunnels.[/yellow]\n")
        print(active_tunnels)
        print(active_tunnel_names)


# Shortcut function to enable HTTPS/SSH management on X1.
# This is an example of a set of commands where you might want to process the response
# after sending a series of commands. One downside is that you won't see any output until the final command is done.
# Another downside is that any prints you place in between commands will be displayed before any console output.
# For example, if you print("done!") after a send_to_console() call but before process_console_response(), print will
# appear to be premature. Instead, you may opt to send_to_console(process_response=True) on some commands.
# Doing that also allows you to add pre- and post- prints with print_before and print_after.
def enable_interface_management(interface=''):
    # If not printing output, we display a spinner instead. This helps manage the spinner display.
    if not display_all_output:
        spinner.stop()

    # Printing before sending any commands.
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [green]Enabling HTTPS/SSH/Ping Management on {interface.capitalize()}[/green]")

    # Series of commands needed to enable management on an interface.
    send_to_console(sc, "config")
    send_to_console(sc, f"interface {interface.capitalize()}")
    send_to_console(sc, "management https")
    send_to_console(sc, "management ssh")
    send_to_console(sc, "management ping")
    send_to_console(sc, "management snmp")
    send_to_console(sc, "commit")
    send_to_console(sc, "end") # End interface configuration, back to config prompt.
    send_to_console(sc, "exit") # Exit configuration prompt.

    # In this example, we process the commands after sending them all
    process_console_response()


# Shortcut function for gathering important diagnostic data
# The send_to_console command sends the commands, but does not read the response itself.
# Instead, the while loop within the main() function displays the console output.
# The result of this is that any prints not sent with the command will occur before any command
# output is seen/handled. I added the process_response= keyword argument to the send_to_console()
# function to address this logic. That new kwarg allows you to process the command immediately
# before moving on to the main loop (ensures command completes) before moving out of the function.
# Additionally, you can use the print_before/print_after kwargs to print a message after
# confirming completion after the command processing is complete.
# This is an example of a function that contains a list of command dictionaries, and sends
# each command with the custom configuration using a for loop. With each command we process
# the response, which confirms the completion of the command and may display output that's returned.
def collect_diagnostic_data():
    # Start the spinner if console output is disabled.
    if not display_all_output:
        spinner.stop()

    # Verify the console prompt before running the jobs.
    verify_console_response(scheduled_job=True)

    # Print before sending commands.
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [green]Starting diagnostic data collection.[/green]")

    # List of dictionaries containing commands and arguments
    # Notice these commands do not include print_before or print_after.
    # In this example, I wanted to post a similar message for each command start/end so I set those
    # keyword arguments below within the for loop, in the call to send_to_console().
    command_list = [
        # Example:
        # {
        #     'cmd': 'CLI command goes here',
        #     'process_response': True, # True or False
        #     'wait_time': 0.5, # Seconds
        #     'prepend_enter_key': True, # True or False (True adds enter keystroke before command)
        #     'print_before': 'Print this before sending the command.',
        #     'print_after': 'Print this after the command and confirming the prompt is returned.',
        # },
        {'cmd': 'show status', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show alerts', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show cpu', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show multicore', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show memory', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show fpa', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show mem-pools', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show memzone summary', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show memzone verbose', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show tracelog', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show tracelog current', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'diag show tracelog last', 'process_response': True, 'wait_time': 0.5},
        {'cmd': 'show tech-support-report', 'process_response': True, 'wait_time': 0.5},
    ]

    # For each command in the list.
    for c in command_list:
        # Send the command!
        # In this example, I set an f-string for print_before and print_after.
        # You can choose to include custom prints within the command dictionaries above and reference
        # that key in the command below.
        send_to_console(sc, c['cmd'],
                        process_response=c['process_response'], # Process the response now or
                        wait_time=c['wait_time'],  # Seconds to wait before processing the console's response.
                        print_before=f"[yellow]Executing: '{c['cmd']}'[/yellow]",
                        print_after=f"[green]Finished: '{c['cmd']}'[/green]")

    # This is the end of the function. This function does not directly call
    # the process_console_response() function. Instead, by using process_response I
    # don't need to directly call it here as it is already done at each command sent.


# Open the serial port.
# This will fail if another terminal app or script instance is running and connected to the port.
# The port will open even if your serial cable is not connected to the firewall.
def open_serial_connection():
    # Initial connection flag is 0
    connected = False

    # Wrapping in try/except so I can catch KeyboardInterrupt
    try:
        print(f"[bold]Connecting to [yellow bold]{serial_params['com_port']}...[/]")
        # While not connected, try to connect.
        while not connected:
            try:
                # Create the serial instance.
                sc = serial.Serial(
                    serial_params['com_port'],
                    serial_params['baud'],
                    bytesize=serial_params['data_bits'],
                    stopbits=serial_params['stop_bits'],
                    parity=serial_params['parity'],
                    xonxoff=serial_params['xonxoff'],
                    timeout=0,
                )
                connected = 1
            except serial.SerialException as e:
                print(f"[red bold]Serial Error: {e}. [cyan]Retrying...[/cyan][/red bold] (CTRL+C to quit)")
                sleep(2)
            except serial.SerialTimeoutException as e:
                print(f"[red bold]Serial Timeout Error: {e}. [cyan]Retrying...[/cyan][/red bold] (CTRL+C to quit)")
                sleep(2)
            except KeyboardInterrupt:
                if not display_all_output:
                    spinner.stop()
                custom_exit()
            except Exception as e:
                print('open_serial_connection: error ->', e)
                sleep(2)
            # Else if no exception occurred.
            else:
                # Confirm the serial port is open.
                if sc.is_open:
                    print(f"[green bold]{serial_params['com_port']} is OPEN[/green bold]!")
                    return sc
    # Handle manually quitting.
    except KeyboardInterrupt:
        if not display_all_output:
            spinner.stop()
        custom_exit()


# Verify that the firewall responds to commands
# scheduled_job kwarg set to True will change displayed text.
def verify_console_response(scheduled_job=False):
    # If the serial connection is open
    if sc.is_open:
        # Create a blank list for later use.
        r = []

        # Responding flag for use in the while loop.
        responding = False

        # Wrapping in tr/except to catch KeyboardInterrupt.
        try:
            # While the responding flag is False...
            while not responding:
                # Send an ENTER keystroke.
                send_to_console(sc, "", wait_time=3)

                # Get the current output/prompt.
                try:
                    r = sc.readlines()
                except serial.SerialException as e:
                    print("Error:", e)
                    continue

                # If the response list is empty we assume the device is not responding.
                # Generally we expect to see a prompt when we hit Enter unless the box is down
                # or is restarting.
                if len(r) < 1:
                    # If display_all_output is False, clear the spinner text and stop the spinner.
                    if not display_all_output:
                        spinner.text = ""
                        spinner.stop()
                    # Print a line. Stopped/cleared spinner so it is properly displayed/not duplicated.
                    #print("[red bold]Device is not responding. It may be powered off or rebooting. Make sure the console cable is secure.[/]")
                    if not display_all_output:
                        spinner.text = "Device is not responding. It may be powered off or rebooting. Make sure the console cable is secure. Please wait..."
                        spinner.start()
                    continue
                # Else (the console response is at least 1 line)
                else:
                    if not display_all_output:
                        spinner.text = ""

                    # Write the console response to a log file.
                    write_output_to_file(r)

                    # Iterate over the console response to check for a prompt.
                    for x in r:
                        #This print will hit if the response gets something back.
                        #print(line.decode().rstrip('\n'))

                        # If the prompt text is detected in the line.
                        if prompts['sos_prompt'].encode('utf-8') in x:
                            if not scheduled_job:
                                if not display_all_output:
                                    spinner.stop()
                                print("[green]Detected SonicOS CLI prompt [yellow](already logged in)[/yellow].[/green]")
                                # Disable paging just in case we jump into an existing authenticated console session.
                                disable_cli_paging()
                                responding = True
                                break
                            else:
                                #spinner.start()
                                responding = True
                                break
                        elif "User:".encode('utf-8') in x:
                            if not display_all_output:
                                spinner.stop()
                            print("[green]Detected SonicOS CLI prompt [yellow](User:)[/yellow].[/green]")
                            responding = True
                            auth_serial_connection()
                            break
                        elif "Password:".encode('utf-8') in x:
                            if len(x) < 20:
                                if not display_all_output:
                                    spinner.stop()
                                print("[green]Detected SonicOS CLI prompt [yellow](Password:)[/yellow].[/green]")
                                responding = True
                                auth_serial_connection()
                            break
                        if prompts['sos_prompt_config'].encode('utf-8') in x:
                            if not scheduled_job:
                                if not display_all_output:
                                    spinner.stop()
                                print(
                                    "[green]Detected SonicOS CLI configuration prompt. [yellow](already logged in)[/yellow].[/green]")
                                # Disable paging just in case we jump into an existing authenticated console session.
                                disable_cli_paging()
                                responding = True
                                break
                            else:
                                #spinner.start()
                                responding = True
                                break
                        elif prompts['shell_prompt'].encode('utf-8') in x:
                            if len(x) < 12:
                                if not display_all_output:
                                    spinner.stop()
                                print("[green]Detected debug shell prompt.[/green]", "--->", line2.decode())
                                responding = True
                        # If login fails (occurs when we hit ENTER at a half-logged in console (at a passwd prompt)
                        elif "Access denied".encode('utf-8') in x:
                            if not display_all_output:
                                spinner.stop()
                            # Print a message showing access denied, set the responding flag to True, then
                            # authenticate the console session. Once the code flow returns back to this function,
                            # break out of the loop. Avoids duplication of the disable_cli_paging() in some situations.
                            print("[yellow]Access Denied response. Check your password if this continues. Please wait...[/yellow]")
                            responding = True
                            auth_serial_connection()
                            # Break out of the loop.
                            break
                        elif "--MORE--".encode('utf-8') in x:
                            if not display_all_output:
                                spinner.stop()
                            # If the line includes --MORE-- indicating a previous command that paginated output.
                            print(f"[yellow]A paginated command is still running. Sending 'q' to cancel that command's output.[/yellow]")
                            responding = True
                            # Send a Q and ENTER keystroke so we get something back.
                            send_to_console(sc, "q")
                        else:
                            if not display_all_output:
                                spinner.stop()
                            if display_all_output:
                                print(x.decode().rstrip('\n'))
                            #print("[yellow]Detected a response, but not a prompt. Device may be rebooting.[/yellow]")
#                            responding = True
        except KeyboardInterrupt:
            custom_exit()
            # spinner.stop()
            # print("Cancelled!")
            # exit()
        return

    # Else, the connection is down. Print a message. (if sc.open is False)
    else:
        if not display_all_output:
            spinner.stop()
        print("[red]Console connection is down.[/red]")


# Checks if authenticated. If not, authenticates.
def auth_serial_connection():
    # Stop the spinner before printing.
    if not display_all_output:
        spinner.stop()

    # If the serial connection is open
    if sc.is_open:
        # Send an ENTER keystroke.
        send_to_console(sc, "", wait_time=2)

        # Get the current output/prompt.
#        serial_output = sc.readlines()

        # Check for a prompt indicating user is logged in via serial console.
        for line1 in sc.readlines():
            if prompts['sos_prompt'] in line1.decode():
                # If the user is already logged in
                # I commented this out since the "detected sonicos cli prompt (already logged in)" is already displayed.
                #print(f"[green]{credentials['user']} is already logged in.[/green]")
                disable_cli_paging()
                return
            elif "--MORE--" in line1.decode():
                # Stop the spinner before printing.
                if not display_all_output:
                    spinner.stop()
                # If the user is already logged in, return.
                print(f"[yellow]A paginated command is still running. Sending 'q' to cancel that command's output.[/yellow]")
                # Send a Q and ENTER keystroke so we get something back.
                # Console will get stuck/hang if we try to readlines without having new output to read.
                send_to_console(sc, "q")
                disable_cli_paging()
            else:
                # Stop the spinner before printing.
                if not display_all_output:
                    spinner.stop()
                # Send an ENTER keystroke so we get something back.
                # Console will get stuck/hang if we try to readlines without having new output to read.
                send_to_console(sc, "")

        # If a user login prompt is returned, authenticate.
        if "User:".encode('utf-8') in sc.readlines():
            # Stop the spinner before printing.
            if not display_all_output:
                spinner.stop()
            print(f"[yellow]Authenticating as [bold]'{credentials['user']}'[bold][yellow]")
            send_to_console(sc, credentials['user'], prepend_enter_key=False, wait_time=2)

        # After sending the username, check the response for the password prompt.
        if "Password:".encode('utf-8') in sc.readlines():
            # Stop the spinner before printing.
            if not display_all_output:
                spinner.stop()
            print(f"[yellow]Sending password.[/yellow]")
            # This wait time may need to be changed. It needs to be long enough for SonicOS to return a response.
            send_to_console(sc, credentials['password'], prepend_enter_key=False, wait_time=6)

        # This next section handles login failures.
        new_lines = sc.readlines()
        for i in new_lines:
            # Stop the spinner before printing.
            if not display_all_output:
                spinner.stop()

            if "Access denied".encode('utf-8') in i:
                print(f"[red]Login failed. Access denied. Check your credentials and try again.[/red]")
                custom_exit()
            if "% Maximum login attempts exceeded.".encode('utf-8') in i:
                print(f"[red]Login failed. Maximum login attempts exceeded. Check your credentials and try again.[/red]")
                custom_exit()
            if prompts['sos_prompt'].encode('utf-8') in i:
                print(f"[green]Authenticated![/green]")
                # Disable the CLI paging in SonicOS for this login session.
                disable_cli_paging()
                return

    # Else, the connection is down. Print a message.
    else:
        print("[red]Console connection is down.[/red]")


# Process the response from the console.
def process_console_response(after_process_msg=''):
    processed = False

    while not processed:
        # This sleep helps with console display. Without it, some lines are truncated to a new line.
        try:
            sleep(0.4)
        except KeyboardInterrupt:
            custom_exit()

        # Read the console response. Set lines var to the console response list.
        try:
            lines = sc.readlines()
        except serial.SerialException as e:
            print(f"[red]Serial Error: {e}. [cyan]...[/cyan][/red] (CTRL+C to quit)")
            print(sc.readlines())
            sleep(2)
        except KeyboardInterrupt:
            custom_exit()

        # Write the list to the output file.
        write_output_to_file(lines)

        # For each line in the response list
        for line in lines:
            # Print out each line from the console response.
            try:
                # If the line is a SonicOS prompt, colorize the print out.
                if prompts['sos_prompt'].encode('utf-8') in line:
                    if display_all_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is a SonicOS prompt, colorize the print out.
                elif prompts['sos_prompt_config'].encode('utf-8') in line:
                    if display_all_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is the echo of the "no cli pager session" command...
                elif "no cli pager session".encode('utf-8') in line:
                    if display_all_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is the echo of the "no cli pager session" command...
                elif "diag show".encode('utf-8') in line:
                    if not display_all_output:
                        spinner.stop()
                    if display_all_output:
                        lx = line.decode().rstrip('\n')
                        print(f"[cyan]{lx}[/cyan]")
                # If the line is a "% " response such as Applying changes or errors, colorize print out.
                elif line.startswith("% ".encode('utf-8')) and "of maximum connections".encode('utf-8') not in line:
                    if not display_all_output:
                        spinner.stop()
                    lx = line.decode().rstrip('\n')
                    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]:   [bold yellow]{lx}[/bold yellow]")
                # If the line is the commit line from status returned processing command, colorize print out.
                elif "  commit".encode('utf-8') in line:
                    if not display_all_output:
                        spinner.stop()
                    lx = line.decode().rstrip('\n')
                    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]{lx}[/bold yellow]")
                # If the line is % Changes made colorize the print out.
                elif "% User logout.".encode('utf-8') in line:
                    if not display_all_output:
                        spinner.stop()
                    lx = line.decode().rstrip('\n')
                    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]{lx}[/bold yellow]")
                else:
                    # Else don't colorize.
                    try:
                        if display_all_output:
                            print(line.decode().rstrip('\n'))
                    except KeyboardInterrupt:
                        print("Cancelled!")
            except UnicodeDecodeError as e:
                if display_all_output:
                    print("WARNING: Unicode decode error:", e, "-->", line)

            # If the command was paginated, the response will include --MORE--.
            try:
                if "--MORE--".encode('utf-8') in line:
                    # Send a space character to request another "page" of information.
                    send_to_console(sc, " ")

                # In the event of a user logout, log back in.
                if line == "User:".encode('utf-8'):
                    auth_serial_connection()
            except UnicodeDecodeError:
                if display_all_output:
                    print(line)

        # Check if the last line in the response is a SonicOS prompt or if the command is still running.
        try:
            #print(len(lines), lines)
            # If the response list of lines is at least 1.
            if len(lines) > 0:
                # Check for a SonicOS prompt.
                try:
                    if prompts['sos_prompt'].encode('utf-8') in lines[-1]:
                        # If a message was set to print after the command runs and is at least 1 char, print it.
                        if after_process_msg:
                            # Print the message if the length is at least 1.
                            if len(after_process_msg) > 0:
                                if not display_all_output:
                                    spinner.stop()
                                print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: {after_process_msg}")
                    # Else if the response is not a SonicOS prompt (indicating the command is still running)
                    else:
                        # If there's a message to print after processing
                        if after_process_msg:
                            # Print a 'still running' message.
                            if len(after_process_msg) > 0:
                                if print_command_status:
                                    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [yellow]Still running...[/yellow]")
                                else:
                                    try:
                                        if not display_all_output:
                                            spinner.start()
                                    except KeyboardInterrupt:
                                        if not display_all_output:
                                            spinner.stop()
                                        #print("Cancelled!")
                                        #exit()
                                        custom_exit()
                                continue
                        continue
                except UnicodeDecodeError as e:
                    if not display_all_output:
                        spinner.stop()
                    print(f"[bold red]WARNING: {e}. This can occur when there's a sudden loss of serial connectivity.[/]")
            # This commented else below is hit when the console response is empty.
            # This could simply be an empty line response after sending a command.
            # I've seen it with command sets that require multiple commands, like configuring interface settings.
            #else:
            #    print("Console response is empty. -->", lines)
        except IndexError as e:
            print(after_process_msg, "-->", e, "-->", len(lines), "-->", lines)
#            print(after_process_msg)

        # Processed
        processed = True

        # Stop the spinner.
        if not display_all_output:
            spinner.stop()


# Runs a single job with a passed in list of commands.
def single_job(cl: list):
    # Start the spinner if console output is disabled.
    if not display_all_output:
        spinner.start()

    # Verify the console prompt before running the jobs.
    # Setting the scheduled_job flag hides some redundant messages that are
    # printed when verifying the console response.
    verify_console_response(scheduled_job=True)
#    verify_console_response()

    # Run these jobs
#    send_to_console(sc, "")
    for c in cl:
        c = c.strip('\n')
        send_to_console(sc, c, process_response=True,
                        print_before=f"[yellow]Sending '{c}'[/yellow].",
                        print_after=f"[green]Finished: '{c}'[/green]."
                        )

    if not display_all_output:
        spinner.start()

    # Make sure the commands are done and process the output.
    process_console_response()

    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]Done![/]")
    print()


# Builds a scheduled job that is executed by the schedule module. Pass in the command list, job name, and interval.
# This function executes the command and processes the response from the console.
def scheduled_job(cmd_list: list, job_name: str, interval: int):
    # Start the spinner if console output is disabled.
    if not display_all_output:
        spinner.start()

    # Verify the console prompt before running the jobs.
    verify_console_response(scheduled_job=True)

    # When starting the scheduled jobs, after verifying the console response.
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]Scheduled job '[bold cyan]{job_name}[/bold cyan]' started. Interval: {interval} seconds.[/]")

    # For each command in the list.
    for c in cmd_list:
        # Send the command!
        # In this example, I set an f-string for print_before and print_after.
        # You can choose to include custom prints within the command dictionaries above and reference
        # that key in the command below.
        c = c.strip('\n')
        send_to_console(sc, c, process_response=True,
                        print_before=f"[yellow]Executing: '{c}'[/yellow]",
                        print_after=f"[green]Finished: '{c}'[/green]"
                        )

    # When starting the scheduled jobs, after verifying the console response.
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]Job '[bold cyan]{job_name}[/bold cyan]' [bold green]completed![/]")

    # This is the end of the function. This function does not directly call
    # the process_console_response() function. Instead, by using process_response I
    # don't need to directly call it here as it is already done at each command sent.


# Write output to a text file.
def write_output_to_file(output):
    # Build the filename string.
    file_time = str(generate_timestamp()).rsplit(':')[0].replace(' ', '_') + ".log"
    filename = f"{start_timestamp.replace(' ', '_').replace(':', '-')}\{file_time}"

    # Try the write operation.
    try:
        with open(filename, 'ab') as output_file:
            output_file.writelines(output)
    except KeyboardInterrupt:
        custom_exit()
    except Exception as e:
        print(e)
    except FileExistsError as e:
        print(e)
    except FileNotFoundError as e:
        custom_exit()


# Banner
# Function that handles printing the intro banner.
def print_banner():
    bannerText = '''
   [red].d88888b                    oo          dP   dP   dP          dP dP 
   88.    "'                               88   88   88          88 88 
   `Y88888b. .d8888b. 88d888b. dP .d8888b. 88  .8P  .8P .d8888b. 88 88 
         `8b 88'  `88 88'  `88 88 88'  `"" 88  d8'  d8' 88'  `88 88 88 
   d8'   .8P 88.  .88 88    88 88 88.  ... 88.d8P8.d8P  88.  .88 88 88 
    Y88888P  `88888P' dP    dP dP `88888P' 8888' Y88'   `88888P8 dP dP[/red] 
                                                                        '''
    introText = f"[red bold]         -- Serial Console Automation Tool for SonicOS (v{version_string}) --[/]"
    print(bannerText)
    print(introText)
    print("[red]---------------------------------------------------------------------------[/]")


# Starts the scheduled routine on launch of the script.
# Runs the routine once initially before starting the loop.
if __name__ == '__main__':
    # True prints a "Still running..." message when commands are taking time to complete.
    # False prints nothing while long-running commands are executing.
    # These messages are NOT written to the log.
    # Using False may lead you to think the script hung during long-running commands.
    # Using True will flood the user's terminal/cmd prompt window, but at least you can see there's progress.
    # With the addition of the spinner, I think this should just stay False.
    print_command_status = False

    # Display banner.
    print_banner()

    # Warn the user if output is not displayed on console.
    if not display_all_output:
        print(f"[cyan bold]Display All Output: [bold yellow]DISABLED[/bold yellow]. The console output will be logged.[/]")
    else:
        print(f"[cyan bold]Display All Output: [bold yellow]ENABLED[/bold yellow]. The console output will be logged.[/]")

    # Check if input file is a job file or ini file.
    if str(args.filename).endswith(".txt"):
        print(f"[bold yellow]Single Job Mode.[/] TXT File: [yellow]{os.path.join(args.filename)}[/]")
    elif str(args.filename).endswith(".ini"):
        print(f"[bold yellow]Scheduled Job Mode.[/] INI File: [yellow]{os.path.join(args.filename)}[/]")
        scheduled_jobs_file = os.path.join(args.filename)
        scheduled_jobs_config.read(scheduled_jobs_file)

    # Print a timestamp
    start_timestamp = generate_timestamp().split('.')[0]

    # Create the directory based on the script's start time.
    try:
        os.mkdir(start_timestamp.replace(' ', '_').replace(':', '-'))
    except Exception as e:
        print(f"[bold red]Error: {e}[/]")

    print(f"[cyan bold]Saving console output to the [bold yellow]'{start_timestamp.replace(' ', '_').replace(':', '-')}'[/bold yellow] folder. Logs are split by hour.[/]")

    # Blank line
    print()

    # Open the serial connection. Return serial connection object.
    sc = open_serial_connection()

    # On Windows, send a recommendation to the driver to use this buffer size.
    try:
        sc.set_buffer_size(rx_size=serial_params['rx_buffer_size'], tx_size=serial_params['tx_buffer_size'])
    except KeyboardInterrupt:
        if not display_all_output:
            spinner.stop()
        custom_exit()

    # Verify that we get a response from the console before moving forward.
    verify_console_response()

    # Check if authenticated on the console.
    # Also verifies if the firewall is responding over console.
    #auth_serial_connection()

    # Schedule the jobs to run. The jobs do not run initially.
    # You can run the functions manually if you want them to run initially.
#    schedule.every(10).seconds.do(collect_diagnostic_data)

    # Process scheduled jobs ini file.
    if str(args.filename).endswith(".ini"):
        for section in scheduled_jobs_config.sections():
            with open(os.path.join(scheduled_jobs_config[section]['job_file']), 'r') as f:
                cl = f.readlines()
                schedule.every(int(scheduled_jobs_config[section]['run_job_every'])).seconds.do(
                    scheduled_job,
                    cmd_list=cl,
                    job_name=scheduled_jobs_config[section]['job_name'],
                    interval=int(scheduled_jobs_config[section]['run_job_every'])
                )
        # Scheduling jobs.
        print(f"[bold yellow]All jobs in {args.filename} were scheduled successfully.[/]")

    # Start the spinner if display_all_output is False.
    if not display_all_output:
        spinner.start()


    # Manual one-time jobs to run before starting the loop.
    # Create your own functions to handle console output in a special way.
    # Some example functions:
#    collect_diagnostic_data()  # Initially run the job
#    enable_interface_management(interface='x0')
#    enable_interface_management(interface='x1')
#    exit()

    # If the input file is a scheduled job file, start the loop.
    if str(args.filename).endswith(".ini"):
        # Runs the pending jobs if they need to run.
        if not display_all_output:
            spinner.stop()

        # Run all scheduled jobs now, with a 5 second delay in between jobs.
        print(f"[bold yellow]Executing all scheduled jobs now.[/]")
        try:
            schedule.run_all(delay_seconds=5)
        except KeyboardInterrupt:
            custom_exit()

        # Start a loop to process any console output and run scheduled jobs.
        # Displays console output if enabled, otherwise displayed out is limited.
        while True:
            # Runs the pending jobs if they need to run.
            if not display_all_output:
                spinner.start()

            schedule.run_pending()

            # Process any available console response, if any.
            process_console_response()

    elif str(args.filename).endswith(".txt"):
        # Stop the spinner
        if not display_all_output:
            spinner.stop()
        print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]Starting single job now.[/]")
        try:
            with open(args.filename) as f:
                cl = f.readlines()
                single_job(cl)
        except KeyboardInterrupt:
            custom_exit()
