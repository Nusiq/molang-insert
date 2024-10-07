# Description
Molang insert is a simple tool that allows you to watch a JSON file and insert Molang expressions into it, based on a temporary ".molang" file. The goal is to make it easier to work with Minecraft's files that use Molang expressions that often need to be inserted into very long and unreadable strings.

# Installation
1. Install Python 3.12 or newer
2. Simply run the following command:
```
pip install git+https://github.com/Nusiq/molang-insert.git
```

# Usage
Molang-Insert is a script that watches the `.particle.json` files, finds all of thee strings in them and creates a temporary `.molang` with the Molang expressions extracted and separated by semicolons into multiple lines. After that, it goes into a loop that synchronizes the changes applied to `.molang` into the `.particle.json` file and vice versa.

Run the following command:
```
molang-insert
```
You can terminate the script by pressing `Ctrl+C` in the terminal that runs the app. When the program is terminated it asks you whether the temporary file should be deleted or not.

You can run the following command for more details.
```
molang-insert --help
```
# Showcase
![](./docs-resources/showcase.gif)
