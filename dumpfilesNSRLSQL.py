# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import ntpath
import hashlib
import os
import re
from typing import List, Tuple, Type, Optional, Generator

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, UnreadableValue
from volatility3.plugins.windows import handles, pslist

import mysql.connector

vollog = logging.getLogger(__name__)

FILE_DEVICE_DISK = 0x7
FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x14
EXTENSION_CACHE_MAP = {
    "dat": "DataSectionObject",
    "img": "ImageSectionObject",
    "vacb": "SharedCacheMap",
}

class DumpFilesNSRLSQL(interfaces.plugins.PluginInterface):
    """Dumps cached file contents from Windows memory samples and checks against NSRL using an SQL database."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def connect_to_mysql(cls, host: str, user: str, password: str, database: str):
        try:
            return mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
        except mysql.connector.Error as err:
            vollog.error(f"Error connecting to MySQL: {err}")
            raise

    @classmethod
    def check_hash_in_db(cls, connection, sha256_hash: str) -> bool:
        """Query the database to check if the file's SHA-256 hash exists in the NSRL database."""
        try:
            cursor = connection.cursor()
            query = "SELECT COUNT(*) FROM nsrl_hashes WHERE sha256_hash = %s"
            cursor.execute(query, (sha256_hash,))
            result = cursor.fetchone()
            return result[0] > 0  # True if hash is found
        except mysql.connector.Error as err:
            vollog.error(f"Error querying the database for hash {sha256_hash}: {err}")
            raise

    @classmethod
    def is_positive_hit(cls, data: bytes, connection) -> bool:
        """Calculate the file's SHA-256 hash and check if it exists in the NSRL database."""
        sha256_hash = hashlib.sha256(data).hexdigest()
        return cls.check_hash_in_db(connection, sha256_hash)

    @classmethod
    def dump_file_producer(
        cls,
        file_object: interfaces.objects.ObjectInterface,
        memory_object: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        layer: interfaces.layers.DataLayerInterface,
        desired_file_name: str,
        connection
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        filedata = open_method(desired_file_name)
        bytes_written = 0
        try:
            for memoffset, fileoffset, datasize in memory_object.get_available_pages():
                data = layer.read(memoffset, datasize, pad=True)
                if data:
                    bytes_written += len(data)
                    filedata.seek(fileoffset)
                    filedata.write(data)
        except exceptions.InvalidAddressException:
            vollog.debug(f"Unable to dump file at {file_object.vol.offset:#x}")
            return None

        if not bytes_written:
            vollog.debug(f"No data cached for file at {file_object.vol.offset:#x}")
            return None

        if cls.is_positive_hit(data, connection):
            vollog.debug(f"File at {file_object.vol.offset:#x} is a positive NSRL hit (SQL query)")
            return None

        vollog.debug(f"File dumped at {filedata.preferred_filename}")
        return filedata

    @classmethod
    def process_file_object(
        cls,
        context: interfaces.context.ContextInterface,
        primary_layer_name: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        file_obj: interfaces.objects.ObjectInterface,
        connection
    ) -> Generator[Tuple, None, None]:
        if file_obj.DeviceObject.DeviceType not in [FILE_DEVICE_DISK, FILE_DEVICE_NETWORK_FILE_SYSTEM]:
            vollog.log(constants.LOGLEVEL_VVV, f"File object at {file_obj.vol.offset:#x} is not a disk file")
            return

        memory_layer_name = context.layers[primary_layer_name].config["memory_layer"]
        memory_layer = context.layers[memory_layer_name]
        primary_layer = context.layers[primary_layer_name]

        obj_name = file_obj.file_name_with_device()
        dump_parameters = []

        for member_name, extension in [("DataSectionObject", "dat"), ("ImageSectionObject", "img")]:
            try:
                section_obj = getattr(file_obj.SectionObjectPointer, member_name)
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                if control_area.is_valid():
                    dump_parameters.append((control_area, memory_layer, extension))
            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV, f"{member_name} unavailable for file at {file_obj.vol.offset:#x}")

        try:
            scm_pointer = file_obj.SectionObjectPointer.SharedCacheMap
            shared_cache_map = scm_pointer.dereference().cast("_SHARED_CACHE_MAP")
            if shared_cache_map.is_valid():
                dump_parameters.append((shared_cache_map, primary_layer, "vacb"))
        except exceptions.InvalidAddressException:
            vollog.log(constants.LOGLEVEL_VVV, f"SharedCacheMap unavailable for file at {file_obj.vol.offset:#x}")

        for memory_object, layer, extension in dump_parameters:
            cache_name = EXTENSION_CACHE_MAP[extension]
            desired_file_name = f"file.{file_obj.vol.offset:#x}.{memory_object.vol.offset:#x}.{cache_name}.{ntpath.basename(obj_name)}.{extension}"

            file_handle = cls.dump_file_producer(file_obj, memory_object, open_method, layer, desired_file_name, connection)
            file_output = file_handle.preferred_filename if file_handle else "Error dumping file"
            yield (cache_name, format_hints.Hex(file_obj.vol.offset), ntpath.basename(obj_name), file_output)

    def _generator(self, procs: List, offsets: List):
        kernel = self.context.modules[self.config["kernel"]]
        file_re = re.compile(self.config["filter"], re.I if self.config["ignore-case"] else 0) if self.config["filter"] else None
        dumped_files = set()

        connection = self.connect_to_mysql(
            host="your_mysql_host",
            user="your_mysql_user",
            password="your_mysql_password",
            database="your_mysql_database"
        )

        try:
            # Process files from handles
            if procs:
                handles_plugin = handles.Handles(context=self.context, config_path=self._config_path)
                type_map = handles_plugin.get_type_map(context=self.context, layer_name=kernel.layer_name, symbol_table=kernel.symbol_table_name)
                cookie = handles_plugin.find_cookie(context=self.context, layer_name=kernel.layer_name, symbol_table=kernel.symbol_table_name)

                for proc in procs:
                    try:
                        object_table = proc.ObjectTable
                    except exceptions.InvalidAddressException:
                        vollog.log(constants.LOGLEVEL_VVV, f"Cannot access _EPROCESS.ObjectTable at {proc.vol.offset:#x}")
                        continue

                    for entry in handles_plugin.handles(object_table):
                        try:
                            if entry.get_object_type(type_map, cookie) == "File":
                                file_obj = entry.Body.cast("_FILE_OBJECT")
                                if file_re and not file_re.search(file_obj.file_name_with_device()):
                                    continue
                                if file_obj.vol.offset in dumped_files:
                                    continue
                                dumped_files.add(file_obj.vol.offset)
                                for result in self.process_file_object(self.context, kernel.layer_name, self.open, file_obj, connection):
                                    yield (0, result)
                        except exceptions.InvalidAddressException:
                            vollog.log(constants.LOGLEVEL_VVV, f"Cannot extract file from _OBJECT_HEADER at {entry.vol.offset:#x}")

            # Process files by VADs (similar logic for VADs can be added here)
        finally:
            connection.close()

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        procs = []
        offsets = []

        if self.config["filter"] and (self.config["virtaddr"] or self.config["physaddr"]):
            raise ValueError("Cannot use filter flag with an address flag")
        
        if self.config.get("virtaddr"):
            offsets.append((self.config["virtaddr"], True))
        elif self.config.get("physaddr"):
            offsets.append((self.config["physaddr"], False))
        else:
            procs = pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name, pslist.PsList.create_pid_filter([self.config.get("pid", None)]))

        return renderers.TreeGrid([("Cache", str), ("FileObject", format_hints.Hex), ("FileName", str), ("Result", str)], self._generator(procs, offsets))
