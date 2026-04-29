'''
Limitations:
1. Multiline strings are broken into different line in strings output even
   if the original string contained \n itself
'''
import argparse
import subprocess

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
CONFIG_EXPECTED_KEYS = [
        CONFIG_KEY_STRINGS_EXECUTABLE_FILE_PATH
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
                         output_json_file_path):
    output_json_dict = {
            "file_path": malware_file_path,
            "strings": strings_list
            }

    with open(output_json_file_path, "w", encoding = "utf-8") as f:
        json.dump(output_json_dict, f, indent = 4)
        logging.info(f'Dumped analysis details successfully to {output_json_file_path}')

if __name__ == "__main__":
    args = parse_cli_args()

    config = parse_config_file(args.config_file_path)

    malware_file_path = args.input_malware_file_path
    output_json_file_path = args.output_json_file_path

    strings_list = get_strings_from_pe_file(config[CONFIG_KEY_STRINGS_EXECUTABLE_FILE_PATH],
                                            malware_file_path)

    dump_details_to_json(malware_file_path,
                         strings_list,
                         output_json_file_path)

