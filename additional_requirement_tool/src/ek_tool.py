'''
Limitations/Future TODOs
1. Multiline strings are broken into different line in strings output even
   if the original string contained \n itself

2. Adding support for CLI argument passing to malware file (right now its
   executed with 0 cli args)

3. Make duration to run dynamic (take from the user)
'''
import argparse
import subprocess
import time
import pefile
import csv
import json
import os
import sys

import logging
logging.basicConfig(
        level = logging.INFO,
        format = '%(asctime)s - %(levelname)s - %(message)s',
        handlers = [
            # log to a file and terminal
            logging.FileHandler('ek_tool_log.txt'),
            logging.StreamHandler(sys.stdout)
            ])

def get_strings_from_pe_file(strings_executable_path, pe_file_path):
    if not os.path.exists(pe_file_path):
        raise ValueError(f'file {pe_file_path} not found')

    if not os.path.exists(strings_executable_path):
        raise ValueError(f'strings.exe not found at {strings_executable_path}')

    p = subprocess.run(
            [strings_executable_path, pe_file_path],
            capture_output = True, # we should catch them instead of being printed on terminal
            text = True, # decode output bytes to text
            check = True # raise exception if the process exectuon fails
            )

    strings_list = p.stdout.splitlines()
    logging.info(f'Pe file {pe_file_path} contains strings {strings_list}')

    return strings_list

def add_entry_to_import_export_list(target_list, entry):
    '''
    target_list: the list to add the import/export entry to
    entry: import entry or export symbol object
    '''
    if entry.name:
        target_list.append(entry.name.decode('utf-8'))
    else:
        # import/export via ordinal number
        target_list.append(f'ordinal_{entry.ordinal}')

    logging.info(f'Added import/export entry {target_list[-1]}')

def get_imports_from_pe_file(pe_file_path):
    """
    Fetch imports from a pe file and return in a 
    dictionary (key dll name, list against that imports by the dll
    via function names or ordinal numbers) 
    """
    imports_dict = {}
    pe = pefile.PE(pe_file_path)

    logging.info('scanning imports')
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            logging.info(f'dll import {dll_name} found')

            imports_dict[dll_name] = []
            for imp in entry.imports:
                add_entry_to_import_export_list(imports_dict[dll_name], imp)

    return imports_dict

def get_exports_from_pe_file(pe_file_path):
    """
    Returns the list of functions that the pe file exports
    (via names or ordinal numbers)
    """
    exports_list = []
    pe = pefile.PE(pe_file_path)

    logging.info('Scanning exports')
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            add_entry_to_import_export_list(exports_list, sym)

    return exports_list

def get_event_list_from_procmon_output_csv_file(procmon_output_csv_file_path):
    if not os.path.exists(procmon_output_csv_file_path):
        raise ValueError(f'No procmon output csv file at {procmon_output_csv_file_path}!')

    events_list = []

    with open(procmon_output_csv_file_path, 'r', encoding = 'utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events_list.append(
                    {
                        "time": row.get("Time of Day"),
                        "process": row.get("Process Name"),
                        "operation": row.get("Operation"),
                        "path": row.get("Path"),
                        "result": row.get("Result"), # success/failure
                        "detail": row.get("Detail") # extra stuff
                    })

    return events_list

def get_procmon_events_list_on_malware_execution(
        procmon_executable_file_path,
        procmon_config_file_path,
        malware_file_path):
    
    if not os.path.exists(procmon_executable_file_path):
        raise ValueError(f'procmon exectuable not found at : {procmon_executable_file_path}')

    if not os.path.exists(procmon_config_file_path):
        raise ValueError(f'procmon config file not found at: {procmon_config_file_path}')

    procmon_output_log_file_path = "tmp_ek_tool_procmon_output_log_file.pml"
    procmon_output_csv_file_path = "tmp_ek_tool_procmon_output_csv_file.csv"

    # start Procmon capture in background (this starts it and returns)
    logging.info('Starting procmon capture')
    procmon_process = subprocess.Popen(
            [procmon_executable_file_path,

             # e.g. allows setting custom filters
             "/LoadConfig", procmon_config_file_path,

             # no UI window on launch
             "/Quiet",
             "/Minimized", 

             # write/log events directly to this file instead of VRAM
             "/BackingFile", procmon_output_log_file_path
             ])

    logging.info('Sleeping for 3s to let procmon start')
    time.sleep(3)

    # Start malware (but don't wait for it to end, hence Popen instead
    # of run)
    logging.info(f'Starting malware {malware_file_path}')
    malware_process = subprocess.Popen(malware_file_path)

    # log events for 10 seconds
    logging.info(f'Sleeping for 10 seconds to capture events')
    duration_to_wait = 10
    time.sleep(duration_to_wait)

    # if not already closed, notify the malware process to close
    malware_process.terminate()

    # Notify procmon to stop procmon capture
    logging.info('Notifying procmon to stop capture')
    subprocess.run(
            [procmon_executable_file_path, "/Terminate", "/Quiet"],
            check = True
            )

    # wait for it to close
    procmon_process.wait()

    # Convert procmon log file (custom format) to more  parseable
    # csv format
    logging.info('Converting procmon log file to csv format')
    subprocess.run(
            [procmon_executable_file_path,
             "/OpenLog", procmon_output_log_file_path,
             "/SaveAs", procmon_output_csv_file_path],
            check = True
            )

    event_list = get_event_list_from_procmon_output_csv_file(procmon_output_csv_file_path)

    # remove the tmp output files
    os.remove(procmon_output_log_file_path)
    os.remove(procmon_output_csv_file_path)

    return event_list

def parse_cli_args():
    """
    Parse command line arguments and return the args object (argparse)
    representing the parsed cli args
    """
    parser = argparse.ArgumentParser(description="EK Tool: Extract strings from executables.")

    parser.add_argument("-c",
                        "--config-file-path",
                        required = True,
                        help = "Path to the config file, see config.txt.template for sample/template config")

    parser.add_argument("-i",
                        "--input-malware-file-path",
                        required = True,
                        help = "Path to the malware executable to analyze.")

    parser.add_argument("-o",
                        "--output-json-file-path",
                        default = 'ek_tool_analysis.json',
                        help = "Output json file to write analysis details to"
                        )

    return parser.parse_args()

CONFIG_KEY_STRINGS_EXECUTABLE_FILE_PATH = "STRINGS_EXECUTABLE_FILE_PATH"
CONFIG_KEY_PROCMON_EXECUTABLE_FILE_PATH = "PROCMON_EXECUTABLE_FILE_PATH"
CONFIG_KEY_PROCMON_CONFIG_FILE_PATH = "PROCMON_CONFIG_FILE_PATH"
CONFIG_EXPECTED_KEYS = [
        CONFIG_KEY_STRINGS_EXECUTABLE_FILE_PATH,
        CONFIG_KEY_PROCMON_EXECUTABLE_FILE_PATH,
        CONFIG_KEY_PROCMON_CONFIG_FILE_PATH
        ]
def parse_config_file(config_file_path):
    """
    Reads the config file and returns a dictionary of key-value pairs.
    empty lines and lines starting with # are ignored.
    """
    config_dict = {}
    
    if not os.path.exists(config_file_path):
        raise FileNotFoundError(f"Config file not found at: {config_file_path}")

    with open(config_file_path, "r") as f:
        for line in f:
            line = line.strip()

            # Ignore empty lines and comments starting with #
            if not line or line.startswith("#"):
                continue
            
            if "=" in line:
                key, value = line.split("=", 1)

                # Clean up whitespace and quotes before storing in dict
                config_dict[key.strip()] = value.strip()

    logging.info(f'Parsed config file as {config_dict}')

    for key in CONFIG_EXPECTED_KEYS:
        if key not in config_dict:
            raise ValueError(f'config file {config_file_path} does not contain expected key {key}')
    
    return config_dict

def dump_details_to_json(malware_file_path,
                         strings_list,
                         imports_dict,
                         exports_list,
                         procmon_events_list,
                         output_json_file_path):
    output_json_dict = {
            "file_path": malware_file_path,
            "strings": strings_list,
            "imports": imports_dict,
            "exports": exports_list,
            "procmon_events_list": procmon_events_list
            }

    with open(output_json_file_path, "w", encoding = "utf-8") as f:
        json.dump(output_json_dict, f, indent = 4)
        logging.info(f'Dumped analysis details successfully to {output_json_file_path}')

if __name__ == "__main__":
    args = parse_cli_args()

    config = parse_config_file(args.config_file_path)

    malware_file_path = args.input_malware_file_path
    output_json_file_path = args.output_json_file_path

    strings_executable_file_path = config[CONFIG_KEY_STRINGS_EXECUTABLE_FILE_PATH]
    procmon_executable_file_path = config[CONFIG_KEY_PROCMON_EXECUTABLE_FILE_PATH]
    procmon_config_file_path = config[CONFIG_KEY_PROCMON_CONFIG_FILE_PATH]

    strings_list = get_strings_from_pe_file(strings_executable_file_path,
                                            malware_file_path)

    imports_dict = get_imports_from_pe_file(malware_file_path)
    exports_list = get_exports_from_pe_file(malware_file_path)

    procmon_events_list = get_procmon_events_list_on_malware_execution(
            procmon_executable_file_path,
            procmon_config_file_path,
            malware_file_path
            )

    dump_details_to_json(malware_file_path,
                         strings_list,
                         imports_dict,
                         exports_list,
                         procmon_events_list,
                         output_json_file_path)
