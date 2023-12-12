#!/usr/bin/env python3

import os, re, shutil

# Path requires Python version 3.4+
from pathlib import Path

from CTFd.utils import get_config

class SiPluginTools(object):
	@staticmethod
	def get_absolute_plugin_path() -> str:
		# Returns current plugins path on success.
		return Path(__file__).parent.resolve()
	@staticmethod
	def get_plugin_folder_name() -> str:
		# Returns string of the directory name containing current script.
		return SiPluginTools.get_absolute_plugin_path().name
	@staticmethod
	def get_relative_plugin_asset_path() -> str:
		# Returns the relative string path to this plugins assets directory
		base_path = os.path.join("plugins", SiPluginTools.get_plugin_folder_name(), "assets")
		slash_char = base_path[7:8:1]
		return (slash_char + base_path + slash_char)
	@staticmethod
	def get_absolute_theme_path(theme_name: str = get_config("ctf_theme")) -> str:
		# Returns string path to the target theme directory on success.
		plugins_dir = Path(SiPluginTools.get_absolute_plugin_path()).parent.resolve()
		ctfd_dir = Path(plugins_dir).parent.resolve()
		theme_dir = os.path.join(ctfd_dir, 'themes', theme_name, "templates")
		return theme_dir
	@staticmethod
	def get_absolute_plugin_template_path() -> str:
		# Returns the string path to this plugins templates folder
		return os.path.join(SiPluginTools.get_absolute_plugin_path(), 'templates')
	@staticmethod
	def peek_line(handle) -> str:
		# Returns result of readline() on file handle: handle.
		# Restores pointer of handle after read.
		pos = handle.tell()
		line = handle.readline()
		handle.seek(pos)
		return line
	@staticmethod
	def patch_line_in_file_2(file_path:Path, search_regex:str, insert_data:str, remove_line:bool = False, insert_offset:int = 1) -> bool:
		#TODO work line by line to minimize RAM usage.
		# Searches contents of file at file_path for match against search_regex pattern.
		# Upon match inserts/replaces file contents by line with insert_data offset by insert_offset.
		# Returns True on success.
		# Returns False otherwise.
		line_found = False
		insert_lines = insert_data.split("\n")
		distance_to_insert = insert_offset
		try:
			handle = open(file_path.resolve(), "r+")
			next_line = SiPluginTools.peek_line(handle)
			if(not next_line):
				# Failed to read a line from file.
				return False
			if not line_found:
				if re.search(search_regex, next_line, re.MULTILINE) != None:
					# We found at least one match (which is good enough.)
					line_found = True
					if insert_offset > 0 and remove_line:
						insert_offset -= 1
					elif insert_offset == 0 and remove_line:
						handle.write(insert_data.pop())
					else:
						#Go back... TODO
						pass
				else:
					# Not what we are looking for.
					handle.write(next_line)
			else:
				# Line was found, but we havent returned yet.
				pass
		except IOError:
			print("[ERROR]: patch_line_in_file() encountered an IOError on opening file at path: '" + str(file_path.resolve()) + "'.") #!Debugging
			return False
		return True
	@staticmethod
	def patch_line_in_file_1(file_path:Path, search_regex:str, insert_data:str, remove_line:bool = False, insert_offset:int = 1) -> bool:
		# Searches contents from memory of file at file_path for match against search_regex pattern.
		# Upon match inserts/replaces file contents by line with insert_data offset by insert_offset.
		# Returns True on success.
		# Returns False otherwise.
		try:
			handle = open(file_path.resolve(), "r")
			lines = handle.readlines()
		except IOError:
			print("[ERROR]: patch_line_in_file() encountered an IOError on opening file at path: '" + str(file_path.resolve()) + "' for reading.") #!Debugging
			return False
		insertion_line = None
		for line in lines:
			if re.search(search_regex, line, re.MULTILINE) != None:
				print("[DEBUG]: Regex match: '" + search_regex + "' on line: '" + line + "'.") #!Debugging
				insertion_line = (lines.index(line) + insert_offset)
				if(insertion_line >= len(lines)):
					insertion_line = len(lines) - 1
				elif(insertion_line < 0):
					insertion_line = 0
				if(remove_line):
					lines[insertion_line] = insert_data
				else:
					lines.insert(insertion_line, insert_data)
				break
		if(insertion_line == None):
			print("[DEBUG]: regex match not found for pattern: '" + search_regex + "' in file: '" + str(file_path.resolve()) + "'.") #!Debugging
			return False
		try:
			handle = open(file_path.resolve(), "w")
			for line in lines:
				handle.write(line)
			handle.close()
		except IOError:
			print("[ERROR]: patch_line_in_file() encountered an IOError on opening file at path: '" + str(file_path.resolve()) + "' for writing.") #!Debugging
			return False
		return True
	@staticmethod
	def patch_theme_template(template_file: str = "base.html", theme_name:str = get_config("ctf_theme"), regex_match: str = ".", insert_value:str = "{% include '' %}", remove_line: bool = False, match_offset: int = 1) -> bool:
		# Patches file template_file relative to current theme specified by theme_name.
		# Replaces/Inserts data with/from insert_value based upon line matching regex: regex_match offset by: match_offset.
		# Returns True on success.
		# Returns False otherwise.
		# Initialize variables
		theme_dir = SiPluginTools.get_absolute_theme_path(theme_name)
		source = os.path.join(theme_dir, template_file)
		template_dir = SiPluginTools.get_absolute_plugin_template_path()
		target = os.path.join(template_dir, template_file)
		# Copy source file into plugin templates directory.
		shutil.copyfile(source, target)
		return SiPluginTools.patch_line_in_file_1(file_path=Path(target), search_regex=regex_match, insert_data=insert_value, remove_line=remove_line, insert_offset=match_offset)
	@classmethod
	def __init__():
		print("[WARN]: Static-only class SiPluginTools was accesssed in a non-static way!") #!Debugging