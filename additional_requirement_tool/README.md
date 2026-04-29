The ek\_tool was written to satisfy the additional requirement of CSCE 652.

## What does the ek\_tool do?

The tool (executable generated from python source via pyinstaller)
tries to club functionalities of multiple reverse engineering tools.

Specifically, it takes in a malware and produces a
json output file containing:

1. strings present in the malware pe file (via strings.exe)
2. imports and exports in the pe file (similar to as seen in PE editors)
3. events occuring on running the malware (via procmon)

## Setup Steps

To get the tool executable using the python source, the following
steps should be followed.

```
# Windows command prompt

# 1. Start the virtual environment
$ <path to venv>\venv\scripts\Activate

# 2. Install pyinstaller
$ pip install pyinstaller

# 3. Use pyinstaller to create standalone tool executable
$ pyinstaller --onefile src/ek_tool.py
```

This will create ek\_tool.exe at dist/ek\_tool.exe that can
be copied over to the VM for use.

## How to use the tool?

1. Copy the ek\_tool.exe over to your VM (see Setup section above on how
   to obtain the exe file from the python source)

2. Copy the src/config.txt template over to your VM. This will be used
   as a configuration file for the tool.

3. Modify the copied config.txt as per preferences, i.e.:
  - Set `STRINGS_EXECUTABLE_FILE_PATH` to path of "strings.exe" executable
  - Set `PROCMON_EXECUTABLE_FILE_PATH` to path of procmon executable

4. For getting the path of the `PROCMON_CONFIG_FILE_PATH` to set in
   the config.txt:
- Open Procmon manually
- Set filters as per preference (based on the events you want the ek\_tool
  to log)
- Check Filter -> Drop Filtered Events (so that only filtered events
  get logged in the output json file produced by the tool)
- Click File -> Export Configuration to export the configuration file
  to a ".pmc" file, and specify the path as `PROCMON_CONFIG_FILE_PATH` in
  the config.txt

5. Now, start the command prompt as an admin (ek\_tool uses Procmon
   which needs admin privileges)

6. Use the tool executable as follows:
```
$ ek_tool.exe -c <path to your config.txt> -i <path to malware to analyze>
```

7. The tool will produce an `ek_tool_analysis.json` output file containing
the analysis details for the run malware. (similar to sample provided below)

```
{
    "file_path": "eg1.exe",
    "strings": [
        "!This program cannot be run in DOS mode.",
        ".text",
        "`.data",
        ".rdata",
        ...
       "__mingw_app_type"
    ],
    "imports": {
        "KERNEL32.dll": [
            "DeleteCriticalSection",
            "EnterCriticalSection",
            "FreeLibrary",
            ...
            "VirtualProtect",
            "VirtualQuery"
        ],
        ...
        "api-ms-win-crt-string-l1-1-0.dll": [
            "strlen",
            "strncmp"
        ]
    },
    "exports": [],
    "procmon_events_list": [
        {
            "time": null,
            "process": "eg1.exe",
            "operation": "WriteFile",
            "path": "D:\\SoftwareReverseEngineering\\Project\\Tool\\malware_indicator.txt",
            "result": "SUCCESS",
            "detail": "Offset: 0, Length: 56, Priority: Normal"
        }
    ]
}
```

8. Any GUI JSON viewer as per preference can be used to view this json file.

