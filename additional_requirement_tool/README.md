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
# this will create ek_tool.exe at dist/ek_tool.exe
$ pyinstaller --onefile src/ek_tool.py
```
