#!/usr/bin/env python
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
import configparser
import json
import os
import re
import subprocess
import sys
import zipfile
from logging import getLogger, INFO, StreamHandler, Formatter
from shutil import rmtree
from subprocess import CalledProcessError

from requests import get

BUILD_DIR = "build"
CODEQL_CLI_DEFAULT_VERSION = "v2.27.4"
CODEQL_CLI_URL = "https://github.com/github/codeql-cli-binaries/releases/download/{}/codeql-linux64.zip"
PROJECT_CODEQL_DB = "openenclave-codeql-db"
PROJECT_CODEQL_WORK_DIR = "openenclave-codeql-db.work"
STATIC_CODEQL_DIR = "src/static/codeql"
SUT_OPENENCLAVE_DIR = "sut/openenclave"
USER_SCAN_DIR = None
QUERY_SUITES_DIR = "queries/cpp/suites"
CODEQL_CLI_DIR = "codeql-cli"
CODEQL_CLI_PATH = "codeql-cli/codeql/codeql"
CODEQL_MODEL_PACK = "openenclave/sgx-models"
DB_BUILDER = "scripts/build_oe_codeql_db.py"
OE_AND_CODEQL_BUILTIN_QUERIES = "oe-codeql-security-queries.qls"
OE_QUERIES_ONLY = "oe-security-queries-only.qls"
SCAN_RESULTS_SARIF = "OpenEnclave.sarif"


class Status:
    r"""
    Error Status Code
    """
    SUCCESS = 0
    SUBPROCESS_INVOKE_FAILED = -1
    CODEQL_CLI_DOWNLOAD_FAILED = -2
    CODEQL_DATABASE_FAILED = -3
    CODEQL_ANALYSIS_FAILED = -4


class Severity:
    r"""
    Severity levels uses in CodeQL detections.
    """
    NONE = "none"
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


_root_path = None


def get_repo_root():
    r"""
    :return:(Str) Root folder path of this repository.
    """
    global _root_path
    if _root_path is None:
        root_path = subprocess.getstatusoutput("git rev-parse --show-toplevel")
        if root_path[0] == 0:
            _root_path = root_path[1]
    return _root_path


def get_build_path():
    r"""
    :return:(Str) Build folder path.
    """
    return os.path.join(get_repo_root(), BUILD_DIR)


def get_codeql_path():
    r"""
    :return:(Str) CodeQL project path.
    """
    return os.path.join(get_repo_root(), STATIC_CODEQL_DIR)


def get_scan_path():
    r"""
    :return:(Str) Path of project to be scanned.
    """
    if USER_SCAN_DIR is not None:
        return USER_SCAN_DIR
    else:
        return os.path.join(get_repo_root(), SUT_OPENENCLAVE_DIR)


def get_codeql_db_path():
    r"""
    :return: (Str) CodeQL database path.
    """
    return os.path.join(get_build_path(), PROJECT_CODEQL_DB)


def get_oe_suite_path():
    r"""
    :return:(Str) Open Enclave query suite path.
    """
    return os.path.join(get_codeql_path(), QUERY_SUITES_DIR)


def get_codeql_cli_version():
    r"""
    :return:(Str) CodeQL CLI version.
    """
    version = CODEQL_CLI_DEFAULT_VERSION
    try:
        config = configparser.ConfigParser()
        if not config.read(os.path.join(get_codeql_path(), "scripts/codeql.config")):
            logger.error("Failed to open CodeQL config")
            return version
        version = config.get("config", "version")
    except (configparser.NoSectionError, configparser.NoOptionError):
        logger.error("Error parsing CodeQL config, Fallback to default version{}".format(
            CODEQL_CLI_DEFAULT_VERSION))
    return version


def get_openencalve_exclusions():
    r"""
    :return:(List) Path to exclude in OpenEnclave in CodeQL scan results.
    """
    try:
        config = configparser.ConfigParser()
        if not config.read(os.path.join(get_codeql_path(), "scripts/codeql.config")):
            logger.error("Failed to open CodeQL config")
            return []
        paths = config.get("openenclave_exclusions", "paths")
        paths_list = json.loads(paths)
        return paths_list
    except (configparser.NoSectionError, configparser.NoOptionError):
        logger.error("Error parsing CodeQL config, Fallback to default version{}".format(
            CODEQL_CLI_DEFAULT_VERSION))
    return []


def get_codeql_cli():
    r"""
    :return:(Str) CodeQL CLI path.
    """
    return os.path.join(get_build_path(), CODEQL_CLI_PATH)


def get_logger(log_level=INFO):
    r"""
    :return:(Object) Logger object.
    """
    try:
        logger_obj = getLogger(sys._getframe(1).f_code.co_name)
        logger_obj.setLevel(log_level)
        if not logger_obj.handlers:
            log_handler = StreamHandler(sys.stdout)
            log_handler.setLevel(log_level)
            log_handler.setFormatter(
                Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
            logger_obj = getLogger(sys._getframe(1).f_code.co_name)
            logger_obj.addHandler(log_handler)
        return logger_obj
    except Exception as ex:
        print(str(ex))


def log_banner(str):
    r""" Prints with a banner line using logger.
    :return:(Void)
    """
    logger.info("*" * 80)
    logger.info(str)
    logger.info("*" * 80)


def invoke_process(cmd_line):
    r""" Invokes the process synchronously.
    :param cmd_line:(Str) Full process path with command line arguments.
    :return:(integer) Process exit status.
    """
    try:
        log_banner(f"Invoking: {cmd_line}")
        called_process = subprocess.run(
            cmd_line,
            stdout=None,
            stderr=subprocess.STDOUT,
            check=False,
            shell=True,
            encoding="utf-8"
        )
        logger.info(f"Process Exit Code: {called_process.returncode}")
        return called_process.returncode
    except CalledProcessError as msg:
        logger.error(f"subprocess.run failed, return code: {msg.returncode}")
        if msg.stderr is not None:
            logger.error("Command Error Output:\n" + msg.stderr.decode('utf-8'))
        if msg.output is not None:
            logger.error("Command Output:\n" + msg.output.decode('utf-8'))
        return Status.SUBPROCESS_INVOKE_FAILED


def unzip_file(zip_file, extract_dir):
    r""" Extracts the zip file to the specified directory.
    :param zip_file:(Str) Zip file path.
    :param extract_dir:(Str) Path to extract.
    :return:(Void)
    """
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        for info in zip_ref.infolist():
            zip_ref.extract(info.filename, path=extract_dir)
            out_path = os.path.join(extract_dir, info.filename)
            perm = info.external_attr >> 16
            os.chmod(out_path, perm)
            logger.info(out_path)


def installed_codeql_cli_version():
    r"""
    :return:(Str) Version of the CLI in the build path (e.g. v2.27.4), or None.
    """
    if not os.path.exists(get_codeql_cli()):
        return None
    status, output = subprocess.getstatusoutput(get_codeql_cli() + " version --format=terse")
    return "v" + output.strip() if status == 0 else None


def download_codeql_cli(clean=False):
    r""" Downloads CodeQL CLI and extracts it in build path.
    The CLI version must match the codeql submodule (codeql-cli/<version> tag).
    :param clean:(boolean)
    :return:(boolean) True on success, False otherwise.
    """
    version = get_codeql_cli_version()
    cli_url = CODEQL_CLI_URL.format(version)
    file_name = os.path.join(get_build_path(), "codeql-cli-{}.zip".format(version))
    extract_dir = os.path.join(get_build_path(), CODEQL_CLI_DIR)
    if not clean and installed_codeql_cli_version() == version:
        logger.info(f"CodeQL CLI {version} is installed!")
        return True
    for path in (file_name, extract_dir):
        if os.path.isdir(path):
            rmtree(path)
        elif os.path.exists(path):
            os.remove(path)
    logger.info(f"Downloading: {cli_url}")
    with open(file_name, "wb") as file:
        response = get(cli_url)
        file.write(response.content)
    if not os.path.exists(file_name):
        logger.error(f"Failed to download {file_name}")
        return False
    logger.info(f"Complete downloading: {cli_url}")
    logger.info(f"Unzipping file: {file_name}")
    unzip_file(file_name, extract_dir)
    if not os.path.exists(extract_dir):
        logger.error(f"Failed to extract {extract_dir}")
        return False
    logger.info(f"Complete unzipping file: {file_name} to {extract_dir}")
    return True


def create_codeql_database(clean=False):
    r""" Creates the CodeQL database with scripts/build_oe_codeql_db.py, which traces
    compile-only builds of the enclave, syscall, common and host sources together with
    oeedger8r-generated ECALL/OCALL stubs for all system EDLs (the CMake build of the
    SDK alone does not contain the stub bodies).
    :param clean:(boolean) True rebuilds the database even if it exists.
    :return:(boolean) True on success, False otherwise.
    """
    codeql_db_path = get_codeql_db_path()
    if os.path.exists(codeql_db_path) and not clean:
        logger.info(f"Using existing CodeQL database: {codeql_db_path}")
        return True
    log_banner(f"Start building CodeQL database: {codeql_db_path}")
    cmd_param = f"{sys.executable} {os.path.join(get_codeql_path(), DB_BUILDER)}" \
                f" --oe-src {get_scan_path()} --codeql {get_codeql_cli()}" \
                f" --db {codeql_db_path}" \
                f" --work-dir {os.path.join(get_build_path(), PROJECT_CODEQL_WORK_DIR)}" \
                f" --jobs {os.cpu_count() or 8} --overwrite"
    if invoke_process(cmd_param) != 0:
        logger.error("Failed to create CodeQL database")
        return False
    logger.info(f"CodeQL database created: {codeql_db_path}")
    return True


def run_codeql_analysis(scan_builtin_queries=True):
    r""" Performs CodeQL analysis on the database.
    :param scan_builtin_queries:(boolean) True, includes builtin CodeQL queries along with OpenEnclave specific queries.
                                          False, runs analysis only using Open Enclave specific queries.
    :return:(boolean) True on success, False otherwise.
    """
    queries = os.path.join(get_oe_suite_path(), OE_QUERIES_ONLY)
    if scan_builtin_queries:
        queries = os.path.join(get_oe_suite_path(),
                               OE_AND_CODEQL_BUILTIN_QUERIES)

    logger.info(f"Query Suite: {queries}")
    codeql_db_path = get_codeql_db_path()
    log_banner(f"Starting analysis on database {codeql_db_path}")
    codeql_suite_path = os.path.join(get_codeql_path(), "codeql")
    results_path = os.path.join(get_build_path(), SCAN_RESULTS_SARIF)
    # The model pack teaches the standard CodeQL queries the Open Enclave threat
    # model (OCALL results and ECALL inputs as remote sources, OE allocators).
    cmd_param = get_codeql_cli() + \
                f" database analyze {codeql_db_path} {queries} --search-path {codeql_suite_path}" \
                f" --additional-packs {get_codeql_path()} --model-packs {CODEQL_MODEL_PACK}" \
                f" --format=sarif-latest --threads=0 --output={results_path}"

    if invoke_process(cmd_param) != 0:
        logger.error(f"Failed to analyze database: {cmd_param}")
        return False
    logger.info(f"CodeQL database analyzed, Results: {codeql_db_path}")
    return True


def get_severity_issues(severity=[Severity.ERROR]):
    r""" Returns the number of security issues found during CodeQL scan by parsing SARIF results.
    Refer below links for SARIF schema used by CodeQL.
    https://codeql.github.com/docs/codeql-cli/sarif-output/
    https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json
    :param severity:(List of Integer) Filter of severities to look in the SARIF result.
    :return:(Integer) Number of issues found.
    """
    issues_detected = 0
    exclusions = get_openencalve_exclusions()
    sarif_results = os.path.join(get_build_path(), SCAN_RESULTS_SARIF)
    with open(sarif_results, mode="r") as report_file:
        report_data = json.loads(report_file.read())
        for run in report_data["runs"]:
            # Rules of queries from packs live in tool.extensions; the result
            # references them through rule.toolComponent.index.
            components = [run["tool"]["driver"]] + run["tool"].get("extensions", [])
            results = run.get("results", [])
            for result in results:
                rule_ref = result.get("rule", {})
                component = components[rule_ref.get("toolComponent", {}).get("index", -1) + 1]
                rule_index = rule_ref.get("index", result.get("ruleIndex"))
                rule_props = component.get("rules", [])[rule_index].get("properties", {})
                for sev in severity:
                    if rule_props.get("problem.severity") == sev:
                        for loc in result["locations"]:
                            path = loc.get("physicalLocation").get("artifactLocation").get("uri")
                            exclude_this_file = False
                            for xclu in exclusions:
                                if path.find(xclu) >= 0:
                                    logger.info(f"Excluded: {path}")
                                    exclude_this_file = True
                                    break
                            if exclude_this_file:
                                continue
                            logger.info(path)
                            issues_detected += 1
    return issues_detected


def run_codeql_scan(clean=True, scan_builtin_queries=False):
    r""" Orchestrates CodeQL scan in steps. (Download CLI, Build database, Perform analysis and Parse results)
    :param clean:(boolean) True deletes the CodeQL CLI, database and results first. False performs incremental scan.
    :param scan_builtin_queries:(boolean) True, includes builtin CodeQL queries along with OpenEnclave specific queries.
                                          False, runs analysis only using Open Enclave specific queries.
    :return:(List) [Status Code, Number of issues detected]
    """
    build_dir = get_build_path()
    # build/ is shared with the fuzzing builds (build.sh); only remove CodeQL artifacts.
    if clean:
        for name in (PROJECT_CODEQL_DB, PROJECT_CODEQL_WORK_DIR, SCAN_RESULTS_SARIF):
            path = os.path.join(build_dir, name)
            if os.path.isdir(path):
                rmtree(path)
            elif os.path.exists(path):
                os.remove(path)
    if not os.path.exists(build_dir):
        os.mkdir(build_dir)
    log_banner("Starting CodeQL Scan")
    if not download_codeql_cli(clean):
        logger.error("Failed to download CodeQL CLI")
        return [Status.CODEQL_CLI_DOWNLOAD_FAILED, 0]
    if not create_codeql_database(clean):
        logger.error("Failed to create CodeQL database, Try clean build")
        return [Status.CODEQL_DATABASE_FAILED, 0]
    if not run_codeql_analysis(scan_builtin_queries):
        logger.error("Failed to run CodeQL analysis")
        return [Status.CODEQL_ANALYSIS_FAILED, 0]
    return [Status.SUCCESS, get_severity_issues([Severity.ERROR, Severity.WARNING])]

def set_scan_path(path_arg):
    r""" Parses the Open Enclave SDK directory path given by the user.
    :param path_arg:(string) Path to Open Enclave SDK directory
    :return:(void)
    """

    if len(path_arg) == 0:
        return

    global USER_SCAN_DIR

    scan_path = os.path.expanduser(path_arg)

    # If both strings are equal, '~' is not given in the path; path given may be relative
    if scan_path == path_arg:
        # If the given path is not an absolute path, generate absolute path
        if not scan_path.startswith("/"):
            scan_path = os.path.abspath(scan_path)

    scan_path = os.path.normpath(scan_path)

    if os.path.exists(scan_path):
        USER_SCAN_DIR = scan_path
    else:
        logger.info(f"Given scan_path ({scan_path}) does not exist, using default path")

def print_usage():
    r""" Harness usage
    :return:(Void)
    """
    log_banner(
        "Usage:\n\n"
        "codeql.py [--clean][--builtin][--help]\n"
        "--help      : Shows this message\n"
        "--clean     : Clean build\n"
        "--scan_path : Path to the repository to scan --scan_path=<repository directory>\n"
        "--builtin   : Run CodeQL analysis with builtin queries along with OpenEnclave specific queries.\n"
    )


def main_fun():
    """ Harness function to invoke run_codeql_scan
    :return:(Void)
    """
    clean_build = False
    scan_built_in = False
    for arg in sys.argv:
        if arg == "--clean":
            clean_build = True
        elif arg == "--builtin":
            scan_built_in = True
        elif arg == "--help":
            print_usage()
            return
        elif arg.startswith("--scan_path="):
            set_scan_path(arg.split("=",1)[1])

    scan_path = get_scan_path()
    logger.info(f"Scan directory: {scan_path}")
    if not os.path.exists(scan_path):
        logger.error(f"...Scan directory does not exist, exiting...")
        return

    result = run_codeql_scan(clean=clean_build, scan_builtin_queries=scan_built_in)
    if result[0] != Status.SUCCESS:
        log_banner(f"Failed to run CodeQL Analysis, Error: {result[0]}")
        return
    if result[1] > 0:
        log_banner(f"CodeQL scan detected [{result[1]}] security issues")
    else:
        log_banner(f"CodeQL scan analysis completed, No security issues")


logger = get_logger()
if __name__ == "__main__":
    main_fun()
