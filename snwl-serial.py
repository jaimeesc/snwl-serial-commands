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
version_string = "0.1"

# Import these modules
import serial
import schedule
import signal
import sys
from time import sleep
from datetime import datetime, timezone
from getpass import getpass
from rich import print
from yaspin import yaspin, kbi_safe_yaspin
from yaspin.spinners import Spinners


# Settings
# Firewall credentials.
credentials = {
    "user": "admin",
    "password": "password"
}

# Parameters for use within SonicOS.
sonicos_params = {
    "disable_cli_paging": True
}

# Prompts dictionary
prompts = {
    'sos_prompt': credentials['user'] + "@",
    'sos_prompt_config': ")# ",
    'shell_prompt': "-> "
}

# Interval at which to run the scheduled commands (in seconds)
job_run_every = 5

# Print console output False prints start/end messages for each command executed.
# True prints all console output. Either way, output is still saved to a log file.
print_console_output = False

# True prints a "Still running..." message when commands are taking time to complete.
# False prints nothing while long-running commands are executing.
# These messages are NOT written to the log.
# Using False may lead you to think the script hung during long-running commands.
# Using True will flood the user's terminal/cmd prompt window, but at least you can see there's progress.
print_command_status = False

# Serial connection parameters.
# SonicWall: 115200 baud, 8 data bits, 1 stop bit, no parity, no flow control.
# RX/TX buffer size: on Windows, send a recommendation to the driver to use this buffer size.
serial_params = {
    'com_port': 'COM5',
    'baud': 115200,
    'data_bits': serial.EIGHTBITS,
    'stop_bits': serial.STOPBITS_ONE,
    'parity': serial.PARITY_NONE,
    'xonxoff': False,
    'rx_buffer_size': 512800, # (512800: 512.8 Kilobytes)
    'tx_buffer_size': 512800 # (512800: 512.8 Kilobytes)
}

# Custom exit function
def custom_exit():
    if not print_console_output:
        spinner.stop()
    print("\n[bold red]Terminated![/]\n")
    exit()


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
        if not print_console_output:
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

    #print("----", ser.read(ser.inWaiting()).decode('utf-8'), end="")


# Shortcut function to disable paging in the CLI
def disable_cli_paging():
    # Stop the spinner before printing.
    if not print_console_output:
        spinner.stop()

    # Disable the CLI paging in SonicOS for this login session.
    if sonicos_params["disable_cli_paging"]:
        print(f"[green]Disabling CLI paging for this login session.[/green]")
        if not print_console_output:
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
    if not print_console_output:
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
#            active_tunnels.get(i.decode().split('Policy: ')[-1], "")
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
def enable_x1_management():
    send_to_console(sc, "config")
    send_to_console(sc, "interface X1")
    send_to_console(sc, "management https")
    send_to_console(sc, "management ssh")
    send_to_console(sc, "commit")
    send_to_console(sc, "end") # End interface configuration, back to config prompt.
    send_to_console(sc, "exit") # Exit configuration prompt.


# Shortcut function for gathering important diagnostic data
# The send_to_console command sends the commands, but does not read the response itself.
# Instead, the while loop within the main() function displays the console output.
# The result of this is that any prints not sent with the command will occur before any command output is seen/handled.
# I added the process_response= keyword argument to the send_to_console() function to address this logic.
# That new kwarg allows you to process the command immediately before moving on to the main loop (ensures command completes)
# before moving out of the function. Additionally, you can use the print_after kwarg to print a message
# confirming completion after the command processing is complete.
def collect_diagnostic_data():
    # Start the spinner if console output is disabled.
    if not print_console_output:
        spinner.stop()

    # Verify the console prompt before running the jobs.
    verify_console_response(scheduled_job=True)

    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [green]Starting diagnostic data collection.[/green]")

    # List of dictionaries containing commands and arguments
    command_list = [
         {'cmd': 'show status', 'process_response': True, 'wait_time': 0.5},
         {'cmd': 'diag show alerts', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show cpu', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show multicore', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show memory', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show fpa', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show mem-pools', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show memzone summary', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show memzone verbose', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show tracelog', 'process_response': True, 'wait_time': 0.5},
         {'cmd': 'diag show tracelog current', 'process_response': True, 'wait_time': 0.5},
        # {'cmd': 'diag show tracelog last', 'process_response': True, 'wait_time': 0.5},
        #{'cmd': 'show tech-support-report', 'process_response': True, 'wait_time': 0.5},
#        {'cmd': 'dd', 'process_response': True, 'wait_time': 0.5},
    ]

    # For each command in the list.
    for c in command_list:
        # Send the command!
        send_to_console(sc, c['cmd'],
                        process_response=c['process_response'], # Process the response now or
                        wait_time=c['wait_time'],  # Seconds to wait before processing the console's response.
                        print_before=f"[yellow]Executing: '{c['cmd']}'[/yellow]",
                        print_after=f"[green]Finished: '{c['cmd']}'[/green]")


# Open the serial port
def open_serial_connection():
    # Initial connection flag is 0
    connected = False

    # Wrapping in try/except so I can catch KeyboardInterrupt
    try:
        # While not connected, try to connect.
        while not connected:
            try:
                print(f"[bold]Connecting to [yellow bold]{serial_params['com_port']}...[/]")
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
        print("Cancelled!")


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
                send_to_console(sc, "", wait_time=5)

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
                    if not print_console_output:
                        spinner.text = ""
                        spinner.stop()
                    print("[red bold]Device is not responding. It may be powered off or rebooting. Make sure the console cable is secure.[/]")
                    if not print_console_output:
                        spinner.text = "Please wait..."
                        spinner.start()
                    continue
                else:
                    if not print_console_output:
                        spinner.text = ""

                    # Write the console response to a log file.
                    write_output_to_file(r)

                    # Iterate over the console response to check for a prompt.
                    for line2 in r:
                        #This print will hit if the response gets something back.
                        #print(line.decode().rstrip('\n'))
                        if prompts['sos_prompt'] in line2.decode():
                            if not scheduled_job:
                                if not print_console_output:
                                    spinner.stop()
                                print("[green]Detected SonicOS CLI prompt [yellow](already logged in)[/yellow].[/green]")
                                responding = True
                                break
                            else:
#                                spinner.start()
                                responding = True
                                break
                        elif "User:" in line2.decode():
                            if not print_console_output:
                                spinner.stop()
                            print("[green]Detected SonicOS CLI prompt [yellow](User:)[/yellow].[/green]")
                            responding = True
                            break
                        elif "Password:" in line2.decode():
                            if len(line2.decode()) < 20:
                                if not print_console_output:
                                    spinner.stop()
                                print("[green]Detected SonicOS CLI prompt [yellow](Password:)[/yellow].[/green]")
                                responding = True
                            break
                        elif prompts['shell_prompt'] in line2.decode():
                            if len(line2.decode()) < 12:
                                if not print_console_output:
                                    spinner.stop()
                                print("[green]Detected debug shell prompt.[/green]")
                                responding = True
                        # If login fails (occurs when we hit ENTER at a half-logged in console (at a passwd prompt)
                        elif "Access denied" in line2.decode():
                            if not print_console_output:
                                spinner.stop()
                            print("[yellow]Access Denied response. Check your password if this continues.[/yellow]")
                            responding = True
                        elif "--MORE--" in line2.decode():
                            if not print_console_output:
                                spinner.stop()
                            # If the line includes --MORE-- indicating a previous command that paginated output.
                            print(f"[yellow]A paginated command is still running. Sending 'q' to cancel that command's output.[/yellow]")
                            responding = True
                            # Send a Q and ENTER keystroke so we get something back.
                            send_to_console(sc, "q")
                        else:
                            if not print_console_output:
                                spinner.stop()
                            if print_console_output:
                                print(line2.decode().rstrip('\n'))
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
        if not print_console_output:
            spinner.stop()
        print("[red]Console connection is down.[/red]")


# Checks if authenticated. If not, authenticates.
def auth_serial_connection():
    # Stop the spinner before printing.
    if not print_console_output:
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
                if not print_console_output:
                    spinner.stop()
                # If the user is already logged in, return.
                print(f"[yellow]A paginated command is still running. Sending 'q' to cancel that command's output.[/yellow]")
                # Send a Q and ENTER keystroke so we get something back.
                # Console will get stuck/hang if we try to readlines without having new output to read.
                send_to_console(sc, "q")
                disable_cli_paging()
            else:
                # Stop the spinner before printing.
                if not print_console_output:
                    spinner.stop()
                # Send an ENTER keystroke so we get something back.
                # Console will get stuck/hang if we try to readlines without having new output to read.
                send_to_console(sc, "")

        # If a user login prompt is returned, authenticate.
        if b"User:" in sc.readlines():
            # Stop the spinner before printing.
            if not print_console_output:
                spinner.stop()
            print(f"[yellow]Authenticating as [bold]'{credentials['user']}'[bold][yellow]")
            send_to_console(sc, credentials['user'], prepend_enter_key=False, wait_time=2)

        # After sending the username, check the response for the password prompt.
        if b"Password:" in sc.readlines():
            # Stop the spinner before printing.
            if not print_console_output:
                spinner.stop()
            print(f"[yellow]Sending password.[/yellow]")
            # This wait time may need to be changed. It needs to be long enough for SonicOS to return a response.
            # Sometimes it can take a
            send_to_console(sc, credentials['password'], prepend_enter_key=False, wait_time=6)

        # This next section handles login failures.
        new_lines = sc.readlines()
        for i in new_lines:
            # Stop the spinner before printing.
            if not print_console_output:
                spinner.stop()

            if "Access denied" in i.decode():
                print(f"[red]Login failed. Access denied. Check your credentials and try again.[/red]")
                #exit()
                custom_exit()
            if "% Maximum login attempts exceeded." in i.decode():
                print(f"[red]Login failed. Maximum login attempts exceeded. Check your credentials and try again.[/red]")
                #exit()
                custom_exit()
            if prompts['sos_prompt'] in i.decode():
                print(f"[green]Authenticated![/green]")

                # Disable the CLI paging in SonicOS for this login session.
                disable_cli_paging()

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
            #print("Cancelled!")
            #exit()
            custom_exit()

        # Read the console response. Set lines var to the console response list.
        try:
            lines = sc.readlines()
        except serial.SerialException as e:
            print(f"[red]Serial Error: {e}. [cyan]...[/cyan][/red] (CTRL+C to quit)")
            print(sc.readlines())
            sleep(2)
        except KeyboardInterrupt:
            #print("Cancelled!")
            #exit()
            custom_exit()

        # Write the list to the output file.
        write_output_to_file(lines)

        # For each line in the response list
        for line in lines:
            # Print out each line from the console response.
            try:
                # If the line is a SonicOS prompt, colorize the print out.
                if prompts['sos_prompt'] in line.decode():
                    if print_console_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is a SonicOS prompt, colorize the print out.
                elif prompts['sos_prompt_config'] in line.decode():
                    if print_console_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is the echo of the "no cli pager session" command...
                elif "no cli pager session" in line.decode():
                    if print_console_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is the echo of the "no cli pager session" command...
                elif "diag show" in line.decode():
                    if print_console_output:
                        lx = line.decode().rstrip('\n')
                        print(f'[cyan]{lx}[/cyan]')
                # If the line is % Applying changes... colorize the print out.
                elif "% Applying changes..." in line.decode():
                    lx = line.decode().rstrip('\n')
                    print(f'[yellow]{lx}[/yellow]')
                # If the line is % Status returned... colorize the print out.
                elif "% Status returned processing command:" in line.decode():
                    lx = line.decode().rstrip('\n')
                    print(f'[yellow]{lx}[/yellow]')
                # If the line is % No changes made colorize the print out.
                elif "% No changes made." in line.decode():
                    lx = line.decode().rstrip('\n')
                    print(f'[green]{lx}[/green]')
                # If the line is % Changes made colorize the print out.
                elif "% Changes made." in line.decode():
                    lx = line.decode().rstrip('\n')
                    print(f'[green]{lx}[/green]')
                # If the line is % Changes made colorize the print out.
                elif "% User logout." in line.decode():
                    lx = line.decode().rstrip('\n')
                    print(f'[yellow]{lx}[/yellow]')
                else:
                    # Else don't colorize.
                    try:
                        if print_console_output:
                            print(line.decode().rstrip('\n'))
                    except KeyboardInterrupt:
                        print("Cancelled!")
            except UnicodeDecodeError:
                if print_console_output:
                    print(line)

            # If the command was paginated, the response will include --MORE--.
            try:
                if "--MORE--" in line.decode():
                    # Send a space character to request another "page" of information.
                    send_to_console(sc, " ")

                # In the event of a user logout, log back in.
                if line.decode() == "User:":
                    auth_serial_connection()
            except UnicodeDecodeError:
                if print_console_output:
                    print(line)

        # Check if the last line in the response is a SonicOS prompt or if the command is still running.
        try:
            # If the response list of lines is at least 1.
            if len(lines) > 0:
                # Check for a SonicOS prompt.
                try:
                    if prompts['sos_prompt'] in lines[-1].decode():
                        # If a message was set to print after the command runs and is at least 1 char, print it.
                        if after_process_msg:
                            # Print the message if the length is at least 1.
                            if len(after_process_msg) > 0:
                                if not print_console_output:
                                    spinner.stop()
                                print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: {after_process_msg}")
    #                            spinner.ok("✔")
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
    #                                    print("hit", len(lines), lines)
                                        if not print_console_output:
                                            spinner.start()
                                    except KeyboardInterrupt:
                                        if not print_console_output:
                                            spinner.stop()
                                        #print("Cancelled!")
                                        #exit()
                                        custom_exit()
                                continue
                        continue
                except UnicodeDecodeError as e:
                    print("Alex error:", e, len(lines), lines[-1])
        except IndexError as e:
            print(after_process_msg, "-->", e, "-->", len(lines), "-->", lines)
#            print(after_process_msg)

        # Processed
        processed = True

        # Stop the spinner.
        if not print_console_output:
            spinner.stop()


# Run these commands.
def job():
    # Start the spinner if console output is disabled.
    if not print_console_output:
        spinner.start()

    # Verify the console prompt before running the jobs.
    verify_console_response(scheduled_job=True)

    # When starting the scheduled jobs, after verifying the console response.
    print(f"[blue]{generate_timestamp().split('.')[0]}[/blue]: [bold yellow]Scheduled jobs in job() were executed. Interval: {job_run_every}[/]")

    # Run these jobs
#    send_to_console(sc, "")
    report_active_tunnels()


# Write output to a text file.
def write_output_to_file(output):
    # Build the filename string.
    filename = f"{start_timestamp.replace(' ', '_').replace(':', '-')}.log"

    # Try the write operation.
    try:
        with open(filename, 'ab') as output_file:
            output_file.writelines(output)
    except KeyboardInterrupt:
#        print("Cancelled!")
#        exit()
        custom_exit()
    except Exception as e:
        print(e)
    except FileExistsError as e:
        print(e)
    except FileNotFoundError as e:
#        print(e)
#        exit()
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
    # Spinner initialized if printing output is disabled
    if not print_console_output:
        spinner = yaspin()
        spinner.color = 'cyan'
        spinner.spinner = Spinners.earth

    # Display banner.
    print_banner()

    # Warn the user if output is not displayed on console.
    if not print_console_output:
        print(f"[cyan bold]NOTE: PRINTING CONSOLE OUTPUT HAS BEEN DISABLED. THE CONSOLE SESSION'S OUTPUT IS STILL WRITTEN TO FILE.[/]")

    # Print a timestamp
    start_timestamp = generate_timestamp().split('.')[0]
    print(f"[cyan bold]{start_timestamp} - Saving output to {start_timestamp}.log [/]")

    # Blank line
    print()

    # Open the serial connection. Return serial connection object.
    sc = open_serial_connection()

    # On Windows, send a recommendation to the driver to use this buffer size.
    sc.set_buffer_size(rx_size=serial_params['rx_buffer_size'], tx_size=serial_params['tx_buffer_size'])

    # Verify that we get a response from the console before moving forward.
    verify_console_response()

    # Check if authenticated on the console.
    # Also verifies if the firewall is responding over console.
    auth_serial_connection()

    # Run the show status command.
#    send_to_console(sc, "show status")
#    report_active_tunnels()
#    enable_x1_management()
#    send_to_console(sc, "show vpn tunnels ipsec")
#    send_to_console(sc, "show user status")
#    send_to_console(sc, "show tech-support-report")

    # Schedule the jobs to run. The jobs do not run initially.
    # You can run the functions manually if you want them to run initially.
#    schedule.every(job_run_every).seconds.do(job)
    schedule.every(1).hours.do(collect_diagnostic_data)

    # Scheduling jobs.
    print("[bold yellow]Jobs were scheduled successfully.[/]")
    if not print_console_output:
        spinner.start()

    # Manual one-time jobs to run before starting the loop.
    collect_diagnostic_data()  # Initially run the job

    # Start an infinite loop. Runs scheduled functions on an interval. Displays console output if enabled.
    while True:
        # Runs the pending jobs if they need to run.
        if not print_console_output:
            spinner.start()
        schedule.run_pending()

        # Process any available console response, if any.
        process_console_response()

