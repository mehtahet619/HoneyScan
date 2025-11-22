import os
import sys

sys.path.insert(0, "/")

import argparse
import asyncio
import importlib.util
import json
import logging
import shutil
import subprocess
import time

from core.logger_container import setup_container_logger
from core.logger_plugin import clear_plugin_logs_if_needed

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
PLUGINS_DIR = os.path.join(ROOT_DIR, "plugins")

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

setup_container_logger()
clear_plugin_logs_if_needed(CONFIG)
PLUGINS = CONFIG.get("plugins", [])
SCAN_CONFIG = CONFIG.get("scan_config", {})
TARGET_IP = SCAN_CONFIG.get("target_ip")
TARGET_DOMAIN = SCAN_CONFIG.get("target_domain")

if not TARGET_IP and not TARGET_DOMAIN:
    raise ValueError(
        "Neither target_ip nor target_domain is specified in the config. Please provide at least one."
    )


def is_tool_installed(tool_name):
    try:
        plugin_path = os.path.join(PLUGINS_DIR, f"{tool_name}.py")
        if os.path.exists(plugin_path):
            spec = importlib.util.spec_from_file_location(tool_name, plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            if hasattr(plugin_module, "is_installed"):
                return plugin_module.is_installed()
    except Exception as e:
        logging.warning(f"Failed to check if {tool_name} is installed: {e}")

    return shutil.which(tool_name) is not None


def get_tool_version(tool_name, version_arg="--version"):
    try:
        result = subprocess.run(
            [tool_name, version_arg], capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


async def install_plugin(plugin):
    name = plugin["name"]
    required_version = plugin.get("version")
    install_cmds = plugin.get("install", [])

    if not install_cmds:
        return True

    already_installed = is_tool_installed(name)
    if already_installed:
        if required_version:
            version = get_tool_version(name)
            if version and required_version not in version:
                logging.info(f"{name} found but version is outdated! Updating...")
                for cmd in install_cmds:
                    if "install" in cmd:
                        cmd = cmd.replace("install -y", "install --reinstall -y")
                    logging.info(f"Executing command: {cmd}")
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                return True
            else:
                logging.info(f"{name} is already up to date.")
                return True
        else:
            logging.info(f"{name} is already installed. Skipping installation.")
            return True

    logging.info(f"Installing dependencies for {name}...")
    is_root = os.geteuid() == 0

    for cmd in install_cmds:
        if not is_root:
            cmd = f"sudo {cmd}"
        logging.info(f"Executing command: {cmd}")
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logging.error(
                f"Installation of {name} failed on command: {cmd}\n{stderr.decode().strip()}"
            )
            return False
    logging.info(f"{name} installed successfully.")
    return True


async def run_plugin(plugin):
    name = plugin["name"]

    if not plugin.get("enabled", False):
        logging.info(f"Plugin {name} is disabled in config. Skipping.")
        return name, ([], 0)

    success = await install_plugin(plugin)
    if not success:
        return name, ([], 0)

    plugin_path = os.path.join(PLUGINS_DIR, f"{name}.py")
    if not os.path.exists(plugin_path):
        logging.error(f"Plugin file {plugin_path} not found!")
        return name, ([], 0)

    try:
        spec = importlib.util.spec_from_file_location(name, plugin_path)
        loaded_plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded_plugin)

        if hasattr(loaded_plugin, "scan"):
            logging.info(f"Running scan() from plugin {name}...")
            start = time.time()
            temp_paths = await loaded_plugin.scan(CONFIG)
            duration = round(time.time() - start, 2)
            logging.info(f"Plugin {name} completed in {duration} sec.")

            paths = []
            if isinstance(temp_paths, list):
                for path in temp_paths:
                    if isinstance(path, str):
                        paths.append({"plugin": name, "path": path})
                    elif isinstance(path, dict):
                        paths.append(path)
            elif isinstance(temp_paths, str):
                paths.append({"plugin": name, "path": temp_paths})
            return name, (paths, duration)
        else:
            logging.error(f"Plugin {name} does not contain scan(). Skipping.")
            return name, ([], 0)
    except Exception as e:
        logging.exception(f"Error running plugin {name}: {e}")
        return name, ([], 0)


def plugins_have_dependencies(plugins):
    return any(
        p.get("enabled") and p.get("strict_dependencies", False) for p in plugins
    )


async def main():
    if plugins_have_dependencies(PLUGINS):
        from core.orchestrator import orchestrate

        logging.info("Dependencies between plugins detected, running orchestrator!")
        results, duration_map = await orchestrate(CONFIG)
        generated_temp_paths = []
        for plugin, plugin_paths in results.items():
            if isinstance(plugin_paths, list):
                generated_temp_paths.extend(plugin_paths)
            elif isinstance(plugin_paths, dict):
                generated_temp_paths.append(plugin_paths)
        return generated_temp_paths, duration_map
    else:
        logging.info("No dependencies found, running plugins in parallel.")
        tasks = [run_plugin(plugin) for plugin in PLUGINS if plugin.get("enabled")]
        results = await asyncio.gather(*tasks)

        generated_temp_paths = []
        duration_map = {}
        for name, (paths, duration) in results:
            if paths:
                generated_temp_paths.extend(paths)
            duration_map[name] = duration
        return generated_temp_paths, duration_map


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        required=True,
        help="Path to save the JSON file with scan results",
    )
    args = parser.parse_args()

    paths, duration_map = asyncio.run(main())

    combined_data = {
        "paths": paths,
        "durations": [{"plugin": k, "duration": v} for k, v in duration_map.items()],
    }

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Saved paths and duration data: {args.output}")
    except Exception as e:
        logging.error(f"Error writing JSON files: {e}")
        print(f"❌ Error writing JSON: {e}")
        exit(1)
