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


# 4. This will create ek_tool.exe at dist/ek_tool.exe
#    which can be copied over to the VM for use
```
