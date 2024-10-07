import asyncio
from watchfiles import awatch, Change
from pathlib import Path
import json
from better_json_tools import load_jsonc, CompactEncoder, JSONWalker, JSONPath
import argparse
import logging
from typing import Iterator

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)




class MolangInsertWatcher():
    '''
    A class that watches a directory for changes in Molang and particle files,
    and syncs the changes between the two types of files.
    '''
    def __init__(self, watched_path: str, particle_ext: str, molang_ext: str) -> None:
        self.watched_path = watched_path
        self.particle_ext = particle_ext
        self.molang_ext = molang_ext
        self._ignored_files: set[Path] = set()
        self._created_files: set[Path] = set()

    def get_matching_path(self, path: Path) -> Path:
        '''
        Takes a path to a particle or Molang file and returns the path to the
        corresponding Molang or particle file.

        Raises a ValueError if the path does not match the expected extensions.
        '''
        if path.name.endswith(self.particle_ext):
            return path.parent / (
                path.name[:-len(self.particle_ext)] + self.molang_ext)
        elif path.name.endswith(self.molang_ext):
            return path.parent / (
                path.name[:-len(self.molang_ext)] + self.particle_ext)
        else:
            raise ValueError(
                f"Failed to find the matching file for path: "
                f"{path.as_posix()}")

    def _get_molang_json_paths(
            self, particle_file_walker: JSONWalker,
            result: dict[str, str]) -> None:
        '''
        Recursively walks the JSON structure of a particle file and collects
        all the paths to string leaf nodes in the structure (in most cases
        it's Molang strings). Inserts the results into the `result` dictionary,
        which should be an empty dictionary when calling this function.
        '''
        for child in particle_file_walker // None:
            if isinstance(child.data, str):
                result[child.path_str] = child.data
            self._get_molang_json_paths(child, result)

    def _yield_molang_parts(self, molang_str: str) -> Iterator[str]:
        '''
        Yields the parts of the Molang string, separating them by special
        characters: ';', '{', '}'.
        '''
        split_start = 0
        if molang_str.startswith("{"):
            # An edge case where the Molang starts with a bracket. The
            # sync_into_particle_file appeds '{' at the end of the previously
            # yielded string and this is simply the easiest workaround to
            # make the function not crash, when the strings starts '{' (which
            # is invalid btw but who cares).
            yield ""
        for i, char in enumerate(molang_str):
            if char in (";", "{", "}"):
                if split_start < i:
                    # Previous range
                    yield molang_str[split_start:i]
                # The special character
                yield molang_str[i:i+1]
                split_start = i + 1
        if split_start < len(molang_str)-1:
            # Add the last range
            yield molang_str[split_start:]

    def sync_into_molang_file(self, particle_path: Path) -> None:
        '''
        Sunchronizes the Molang strings from the particle file into the Molang
        file.
        '''
        logger.info(f"Syncing particle file {particle_path} into Molang file.")
        molang_path = self.get_matching_path(particle_path)
        try:
            particle_walker = load_jsonc(particle_path)
        except Exception as e:
            logger.error(
                f"Failed to load particle file {particle_path}. Error: {e}")
            return
        molang_json_paths: dict[str, str] = {}
        self._get_molang_json_paths(particle_walker, molang_json_paths)
        # Write the Molang strings into the Molang file
        first = True
        self._ignored_files.add(molang_path)
        
        path_existed =  molang_path.exists()
        write_lines: list[str] = []
        for json_path, molang_str in molang_json_paths.items():
            if first:
                write_lines.append(f">>> {json_path}\n")
                first = False
            else:
                write_lines.append(f"\n>>> {json_path}\n")
            while molang_str.startswith(">>> "):
                # Escape special prefix in case of annoying users trying
                # to break the system
                molang_str = molang_str[4:]
            if ";" in molang_str or "{" in molang_str or "}" in molang_str:
                indent = 0
                for molang_line in self._yield_molang_parts(molang_str):
                    if molang_line == "{":
                        # Don't worry. If the Molang string starts with '{',
                        # it's handled in the _yield_molang_parts so there is
                        # never an error here. The [-1] always exists and is
                        # not the path string (not this: ">>> ").
                        write_lines[-1] = write_lines[-1].rstrip("\n\r") + "{\n"
                        indent += 1
                        # No need to write anything, we modified the previous
                        # line instead.
                        continue
                    elif molang_line == "}":
                        indent -= 1
                    elif molang_line == ";":
                        continue  # We add new lines instead of that
                    indent_str = '\t' * indent
                    write_lines.append(f"{indent_str}{molang_line}\n")
            else:
                write_lines.append(f"{molang_str}\n")
        with molang_path.open("w") as f:
            f.writelines(write_lines)
        if not path_existed:
            logger.info(f"Created new Molang file: {molang_path}")
            self._created_files.add(molang_path)

    def sync_into_particle_file(self, molang_path: Path) -> None:
        '''
        Sunchronizes the content of the Molang file into the particle file.
        '''
        logger.info(f"Syncing Molang file {molang_path} into particle file.")
        particle_path = self.get_matching_path(molang_path)
        try:
            molang_lines = molang_path.read_text().splitlines()
        except Exception:
            logger.error(
                f"Failed to read Molang file {molang_path}, syncing back.")
            self.sync_into_molang_file(particle_path)
            return
        particle_data: dict[str, list[str]] = {}
        curr_group: str = ""
        for molang_line in molang_lines:
            molang_line = molang_line.strip()
            if molang_line.startswith(">>> "):
                curr_group = molang_line[4:]
                particle_data[curr_group] = []
            elif molang_line.startswith("//") or molang_line == "":
                continue
            else:
                if curr_group == "":
                    logger.error(
                        f"Failed to parse Molang line: {molang_line}")
                    continue
                particle_data.get(curr_group, []).append(molang_line)
        # Load the particle file
        try:
            particle_walker = load_jsonc(particle_path)
        except Exception as e:
            logger.error(
                f"Failed to load particle file to sync data from Molang "
                f"file. Error: {e}")
            return
        # Insert the Molang strings into the particle file
        for json_path, molang_strs in particle_data.items():
            if len(molang_strs) > 1:
                # Complex expressions needs adding semicolons but not when the
                # line ends with '{' (it's a block start).
                processed_molang_strs: list[str] =[]
                for molang_str in molang_strs:
                    molang_str = molang_str.strip()
                    if any(
                            molang_str.endswith(char)
                            for char in ("{", ",", "(")):
                        processed_molang_strs.append(molang_str)
                    elif molang_str == ")":
                        # Prevents adding semicolon after the last argument of
                        # a multi-line function call.
                        if len(processed_molang_strs) > 0:
                            prev_str = processed_molang_strs[-1]
                            # Remove the semicolon from the last arg of the
                            # function call
                            if prev_str.endswith(";"):
                                processed_molang_strs[-1] = prev_str[:-1]
                        processed_molang_strs.append(molang_str + ";")
                    else:
                        processed_molang_strs.append(molang_str + ";")
                molang_strs = processed_molang_strs
            molang = "".join(molang_strs)
            target = particle_walker / JSONPath(json_path)
            if not target.exists:
                continue
            target.data = molang
        # Save the particle file
        self._ignored_files.add(particle_path)
        with particle_path.open("w") as f:
            json.dump(particle_walker.data, f, cls=CompactEncoder)

    def _handle_file_change(
            self, change: Change, path_str: str) -> None:
        '''
        Handles a file change event detected by the file watcher, by syncing the
        molang files into the particle files or vice versa.
        '''
        if change == Change.deleted:
            # TODO - handle deleting matching file if it's a particle file
            # that was deleted
            return
        path = Path(path_str)
        if path in self._ignored_files:
            # This file was modified by us, so we don't care about it this time
            self._ignored_files.discard(path)
            return
        if not path.is_file():
            # We don't care about directories
            return
        
        # Sync the files
        if path_str.endswith(self.particle_ext):
            self.sync_into_molang_file(path)
        elif path_str.endswith(self.molang_ext):
            self.sync_into_particle_file(path)

    async def _watch_files(self) -> None:
        try:
            # Files that should be ignored (prevents infinite loops when
            # modifying files)
            async for changes in awatch(self.watched_path):
                for file_change in changes:
                    self._handle_file_change(*file_change)
        except asyncio.CancelledError:
            pass
    
    def _delete_molang_prompt(self) -> None:
        '''
        Prompts the user if they want to delete the newly created Molang files.
        '''
        if len(self._created_files) == 0:
            return  # Nothing to delete
        while True:
            user_input = input(
                "Do you want to delete the newly created Molang files? [y/n] ")
            if user_input.lower() in ("y", "yes"):
                for path in self._created_files:
                    path.unlink()
                logger.info("Deleted the newly created Molang files.")
                break
            elif user_input.lower() in ("n", "no"):
                logger.info("Leaving the newly created Molang files.")
                break
            else:
                logger.error("Invalid input, please enter 'y' or 'n'.")

    def watch_files(self) -> None:
        '''
        Starts and async loop that watches the files in the directory specified in
        the context for changes.
        '''
        logger.info("Starting to watch files...")
        logger.info("Creating the Molang files...")
        for path in Path(self.watched_path).rglob(f"*{self.particle_ext}"):
            if not path.is_file():
                continue
            self.sync_into_molang_file(path)

        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self._watch_files())
        except KeyboardInterrupt:
            logger.info("Caught KeyboardInterrupt, exiting...")
            loop.run_until_complete(self._shutdown(loop))
        finally:
            loop.close()
        self._delete_molang_prompt()

    async def _shutdown(self, loop: asyncio.AbstractEventLoop) -> None:
        '''
        Cancelled all running tasks and shuts down the program.
        '''
        logger.info("Shutting down...")
        # Cancel all running tasks
        tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Shutdown complete.")

def main():
    '''
    The main function of the program. This script is called when the user runs
    the program from the command line using `molang-insert` command.
    '''
    # Parse the the arguments from the user
    parser = argparse.ArgumentParser(description="Watch files for changes.")
    parser.add_argument(
        "--particle-ext", type=str, default=".particle.json",
        help="The extension used by the Minecraft particle files.")
    parser.add_argument(
        "--molang-ext", type=str, default=".molang",
        help="The extension used by the Minecraft Molang files.")
    parser.add_argument(
        "--watched-path", type=str, default=".",
        help="The path to watch for changes.")
    args = parser.parse_args()

    # Start the watcher
    MolangInsertWatcher(
        args.watched_path,
        args.particle_ext,
        args.molang_ext
    ).watch_files()

