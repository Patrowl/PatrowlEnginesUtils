# -*- coding: utf-8 -*-
"""This file manages PatrowlEngine and its common features."""

import os

from datetime import datetime, date, timezone
from flask import jsonify, url_for, redirect, send_file
import json
import optparse
import psutil
import shutil
import urllib
import ssl
import socket
import time
from uuid import UUID

from .PatrowlEngineExceptions import PatrowlEngineExceptions

APP_HOST = "127.0.0.1"
APP_PORT = 5000
APP_DEBUG = False
APP_MAXSCANS = 25


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime) or isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, UUID):
        # if the obj is uuid, we simply return the value of uuid
        return obj.hex
    raise TypeError("Type not serializable")


class PatrowlEngine:
    """Class definition of PatrowlEngine."""

    def __init__(self, app, base_dir, name, max_scans=APP_MAXSCANS, version=0):
        """Initialise a new PatrowlEngine."""
        self.app = app
        self.base_dir = str(base_dir)
        self.name = name
        self.version = version
        self.description = ""
        self.allowed_asset_types = []
        self.options = {}
        self.scan_id = 1
        self.scanner = {}
        self.scans = {}
        self.max_scans = max_scans
        self.status = "INIT"
        self.metadata = {}

    def __str__(self):
        """Return a string-formated object."""
        return "%s - %s" % (self.name, self.version)

    def __to_dict(self):
        """Return a dict-formated object."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "status": self.status,
            "allowed_asset_types": self.allowed_asset_types,
            "max_scans": self.max_scans,
            "nb_scans": len(self.scans.keys()),
        }

    def run_app(
        self,
        app_debug=APP_DEBUG,
        app_host=APP_HOST,
        app_port=APP_PORT,
        threaded=True,
    ):
        """Run the flask server."""
        if not os.path.exists(self.base_dir + "/results"):
            os.makedirs(self.base_dir + "/results")

        self._loadconfig()
        parser = optparse.OptionParser()
        parser.add_option(
            "-H",
            "--host",
            default=app_host,
            help="PatrowlEngine hostname [default %s]" % APP_HOST,
        )
        parser.add_option(
            "-P",
            "--port",
            default=app_port,
            help="Port for the Patrowl Engine [default %s]" % APP_PORT,
        )
        parser.add_option(
            "-d",
            "--debug",
            action="store_true",
            dest="debug",
            help=optparse.SUPPRESS_HELP,
        )
        parser.add_option(
            "", "--cert", dest="certfile", default=None, help="Certificate filename"
        )
        parser.add_option(
            "", "--key", dest="keyfile", default=None, help="Private key filename"
        )
        parser.add_option(
            "", "--password", dest="keypass", default=None, help="Private key password"
        )
        parser.add_option(
            "",
            "--auto-tls",
            dest="tls",
            action="store_true",
            help="Enable TLS with dummy certificate",
        )

        options, _ = parser.parse_args()

        if options.certfile and options.tls:
            parser.error("options --cert and --auto-tls are mutually exclusive")

        if options.certfile and not options.keyfile:
            parser.error("option --key missing")

        self.app.run(
            debug=options.debug,
            host=options.host,
            port=int(options.port),
            threaded=threaded,
            ssl_context=self._getsslcontext(options),
        )

    def liveness(self):
        """Return the liveness status."""
        return jsonify({"page": "liveness", "status": "success"}), 200

    def readiness(self):
        """Return the readiness status."""
        if self.scanner["status"] not in ["READY", "BUSY"]:
            return jsonify({"page": "readiness", "status": "error"}), 500
        else:
            return jsonify({"page": "readiness", "status": "success"}), 200

    def test(self):
        """Return the test page."""
        res = "<h2>Test Page (DEBUG):</h2>"
        for rule in self.app.url_map.iter_rules():
            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ",".join(rule.methods)
            url = url_for(rule.endpoint, **options)
            res += urllib.request.pathname2url(
                "{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(
                    rule.endpoint, methods, url
                )
            )
        return res

    def _loadconfig(self):
        """Load the configuration file"""
        conf_file = self.base_dir + "/" + self.name + ".json"
        if os.path.exists(conf_file):
            engine_config = json.load(open(conf_file))
            self.version = engine_config["version"]
            self.description = engine_config["description"]
            self.options = engine_config["options"]
            self.allowed_asset_types = engine_config["allowed_asset_types"]
            self.scanner["status"] = "READY"
        else:
            self.scanner["status"] = "ERROR"
            return {"status": "ERROR", "reason": "config file not found"}

    def reloadconfig(self):
        """Reload the configuration file."""
        res = {"page": "reloadconfig"}
        self._loadconfig()
        res.update({"status": "success", "config": self.scanner})
        return jsonify(res)

    def had_options(self, options):
        """Check if the engine is started with options."""
        opts = []
        if isinstance(options, str):
            opts.append(options)
        elif isinstance(options, list):
            opts = options

        for o in opts:
            if o not in self.options or self.options[o] is None:
                return False

        return True

    def _getsslcontext(self, options):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if options.tls:
            context = "adhoc"
        elif options.certfile:
            # set password to empty string not None to
            # avoid prompt if private key is protected
            # this had no effect if private key is not protected
            if options.keypass is None:
                options.keypass = ""

            context.load_cert_chain(
                certfile=options.certfile,
                keyfile=options.keyfile,
                password=options.keypass,
            )
        else:
            context = None

        return context

    def clean(self) -> tuple[dict, int]:
        """Clean all scans."""
        res = {"page": "clean"}
        # Terminate processes
        for scan_id in self.scans.keys():
            for thread_id in self.scans[scan_id]["threads"]:
                thread = self.scans[scan_id]["threads"][thread_id]
                if "proc" in thread and hasattr(thread["proc"], "pid"):
                    if psutil.pid_exists(thread["proc"].pid):
                        psutil.Process(thread["proc"].pid).terminate()
        # Remove scans from memory
        self.scans.clear()
        # Update scanner status
        self.get_status()
        res.update({"status": "success"})
        return jsonify(res), 200

    def clean_scan(self, scan_id: int) -> tuple[dict, int]:
        """Clean a scan identified by his 'id'."""
        res = {"page": "clean_scan"}
        res.update({"scan_id": scan_id})

        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(
                1002, "scan_id '{}' not found".format(scan_id)
            )

        # Terminate thread if any
        for thread_id in self.scans[scan_id]["threads"]:
            try:
                thread = self.scans[scan_id][thread_id]
                thread.join()
                self.scans[scan_id]["threads"].remove(thread)
            except Exception as e:
                print(e)
                pass

        self.scans.pop(scan_id)
        res.update({"status": "removed"})
        return jsonify(res), 200

    def _engine_is_busy(self):
        """Returns if engine is busy scanning."""
        scans_count = 0
        # for scan_id, scan_infos in this.scans:
        for scan_id in self.scans.keys():
            # do not use scan_status as it updates all scans
            # TODO rewrite function later
            if self.scans[scan_id]["status"] in ["SCANNING", "STARTED"]:
                scans_count += 1
            if scans_count >= self.max_scans:
                return True
        return False

    def getstatus_scan(self, scan_id):  # DEPRECATED
        """Get the status of a scan identified by his 'id'."""
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(
                1002, "scan_id '{}' not found".format(scan_id)
            )

        all_threads_finished = True
        for t in self.scans[scan_id]["threads"]:
            if t.is_alive():
                all_threads_finished = False
                break

        if all_threads_finished and len(self.scans[scan_id]["threads"]) >= 1:
            if self.scans[scan_id]["status"] == "SCANNING":
                # all threads are finished, ensure scan status is no more SCANNING
                self.scans[scan_id]["status"] = "FINISHED"
                self.scans[scan_id]["finished_at"] = datetime.now(
                    timezone.utc
                ).isoformat()

            if "finished_at" not in self.scans[scan_id].keys():
                # update finished time if not already set
                self.scans[scan_id]["finished_at"] = datetime.now(
                    timezone.utc
                ).isoformat()

        return jsonify({"status": self.scans[scan_id]["status"]})

    def get_full_status(self):
        """Return engine status with all assets on scans."""
        return self.get_status(True)

    def get_status(self, full_status=False):
        """Get the status of the engine and all its scans."""
        res = {"page": "status"}
        self.scanner["status"] = "READY"
        status_code = 200

        # display host + info on the scanner
        res.update({"scanner": self.scanner, "hostname": socket.gethostname()})

        # display the status of scans performed
        scans = {}
        all_scans = list(self.scans.keys()).copy()

        for scan in all_scans:
            try:
                data = self.status_scan(scan).json
                scans.update(
                    {
                        scan: {
                            "status": data["status"],
                            "options": data["options"],
                            "nb_findings": data["nb_findings"],
                            "nb_assets": len(data["assets"]),
                            "position": data["position"],
                            "root_scan_id": data["root_scan_id"],
                            "created_at": data["created_at"],
                            "finished_at": data["finished_at"],
                        }
                    }
                )
                if full_status:
                    scans[scan].update({"assets": data["assets"]})
            except Exception:
                pass
        res.update({"scans": scans})

        if self._engine_is_busy() is True:
            self.scanner["status"] = "BUSY"

        conf_file = self.base_dir + "/" + self.name + ".json"
        if not os.path.exists(conf_file):
            self.scanner["status"] = "ERROR"

        res.update({"status": self.scanner["status"]})
        if self.scanner["status"] == "ERROR":
            status_code = 500
        return jsonify(res), status_code

    def _get_attr(self, data: dict, value: str, return_value=None):
        if value in data:
            return data[value]
        return return_value

    def status_scan(self, scan_id: int):
        """Get status on scan identified by id."""
        res = {
            "page": "status_scan",
            "hostname": socket.gethostname(),
            "status": "UNKNOWN",
            "assets": [],
        }
        info_thread_in_progress = []
        if scan_id not in self.scans.keys():
            res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
            return jsonify(res)
        res.update({"scan_id": scan_id})

        if self.scans[scan_id]["status"] == "ERROR":
            res.update({"status": "error", "reason": "Something wrong happened"})
            return jsonify(res)

        # Fix when a scan is started but the thread has not been created yet
        if self.scans[scan_id]["status"] == "STARTED":
            res.update({"status": "SCANNING"})

        res.update(
            {
                "options": self._get_attr(self.scans[scan_id], "options", {}),
                "nb_findings": self._get_attr(self.scans[scan_id], "nb_findings"),
                "nb_assets": len(self._get_attr(self.scans[scan_id], "assets", [])),
                "assets": self._get_attr(self.scans[scan_id], "assets", []),
                "position": self._get_attr(self.scans[scan_id], "position", 0),
                "root_scan_id": self._get_attr(self.scans[scan_id], "root_scan_id", 0),
                "created_at": self._get_attr(self.scans[scan_id], "created_at"),
                "finished_at": self._get_attr(self.scans[scan_id], "finished_at"),
            }
        )

        for thread_id in self.scans[scan_id]["threads"]:
            thread = self.scans[scan_id]["threads"][thread_id]
            if "proc" not in thread:
                res.update(
                    {"status": "error", "reason": "Process for this scan not found."}
                )
                return jsonify(res)

            if not psutil.pid_exists(thread["proc"].pid):
                thread["status"] = "FINISHED"
            elif psutil.pid_exists(thread["proc"].pid) and psutil.Process(
                thread["proc"].pid
            ).status() in ["sleeping", "running"]:
                thread["status"] = "SCANNING"
                info = {
                    "thread_id": thread["thread_id"],
                    "cmd": thread["cmd"],
                    "pid": thread["proc"].pid,
                }
                info_thread_in_progress.append(info)

            elif (
                psutil.pid_exists(thread["proc"].pid)
                and psutil.Process(thread["proc"].pid).status() == "zombie"
            ):
                thread["status"] = "FINISHED"
                psutil.Process(thread["proc"].pid).terminate()

            # Debug in case of status pf disk-sleep
            else:
                # print(psutil.Process(thread['proc'].pid).status())
                thread["status"] = "SCANNING"

        for thread_id in self.scans[scan_id]["threads"]:
            thread = self.scans[scan_id]["threads"][thread_id]
            # if one thread is not finished, global scan is not finished
            if thread["status"] in ["SCANNING", "STARTED", "RUNNING"]:
                self.scans[scan_id]["status"] = "SCANNING"
                res.update(
                    {"status": "SCANNING", "info": [t for t in info_thread_in_progress]}
                )
                return jsonify(res)
            else:
                self.scans[scan_id]["status"] = "FINISHED"
                self.scans[scan_id]["finished_at"] = datetime.now(
                    timezone.utc
                ).isoformat()
                res.update({"status": "FINISHED"})
        return jsonify(res)

    def info(self):
        """Return the info page."""
        scans = {}
        for scan in self.scans.keys():
            # self.status_scan(scan)
            scans.update(
                {
                    scan: {
                        "status": self.scans[scan]["status"],
                        "nb_assets": len(self.scans[scan]["assets"]),
                        "options": self.scans[scan]["options"],
                        "nb_findings": self.scans[scan]["nb_findings"],
                    }
                }
            )

        res = {
            "page": "info",
            "hostname": socket.gethostname(),
            "engine_config": self.scanner,
            "scans": scans,
        }
        return jsonify(res), 200

    def stop_scan(self, scan_id):
        """Stop a scan identified by his 'id'."""
        res = {"page": "stop_scan"}
        pids = ""
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(
                1002, "scan_id '{}' not found".format(scan_id)
            )

        # Update scan status
        self.status_scan(scan_id)
        if self.scans[scan_id]["status"] not in ["STARTED", "SCANNING"]:
            res.update(
                {
                    "status": "ERROR",
                    "reason": "scan '{}' is not running (status={})".format(
                        scan_id, self.scans[scan_id]["status"]
                    ),
                }
            )
            return jsonify(res)
        for thread_id in self.scans[scan_id]["threads"]:
            thread = self.scans[scan_id][thread_id]
            if hasattr(thread["proc"], "pid"):
                if psutil.pid_exists(thread["proc"].pid):
                    psutil.Process(thread["proc"].pid).terminate()
                    pids += " " + str(thread["proc"].pid)

            # Stop scan
            try:
                thread.join()
                self.scans[scan_id]["threads"].pop(thread_id)
            except Exception:
                pass

        self.scans[scan_id]["status"] = "STOPPED"
        self.scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        res.update({"status": "success", "details": {"pid": pids, "scan_id": scan_id}})
        return jsonify(res), 200

    # Stop all scans
    def stop(self):
        """Stop all the scans."""
        res = {"page": "stop_scans"}
        for scan_id in self.scans.keys():
            self.stop_scan(scan_id)
        res.update({"status": "SUCCESS"})
        return jsonify(res)

    def start(self, params):
        """Initialize a scan."""
        res = {"page": "startscan"}

        # check the scanner is ready to start a new scan
        if len(self.scans) == self.max_scans:
            res.update(
                {
                    "status": "ERROR",
                    "reason": "Scan refused: max concurrent active scans reached \
                    ({})".format(self.max_scans),
                }
            )
            return res

        self.get_status()
        if self.scanner["status"] != "READY":
            res.update(
                {
                    "status": "ERROR",
                    "details": {
                        "reason": "scanner not ready",
                        "status": self.scanner["status"],
                    },
                }
            )
            return res

        data = json.loads(params)
        if "assets" not in data.keys():
            res.update(
                {
                    "status": "ERROR",
                    "details": {
                        "reason": "Arg error, something is missing ('assets' ?)"
                    },
                }
            )
            return res

        # Sanitize args :
        scan_id = str(data["scan_id"])
        res.update({"details": {"scan_id": scan_id}})
        new_scan = PatrowlEngineScan(
            assets=data["assets"], options=data["options"], scan_id=scan_id
        )

        self.scans.update({scan_id: new_scan.__dict__})
        return res

    def _parse_results(self, scan_id):
        """Parse the results."""
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(
                1002, "scan_id '{}' not found".format(scan_id)
            )

        issues = []
        summary = {}

        nb_vulns = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        for issue in self.scans[scan_id]["findings"]:
            issues.append(issue._PatrowlEngineFinding__to_dict())
            nb_vulns[issue.severity] += 1

        summary = {
            "nb_issues": len(issues),
            "nb_info": nb_vulns["info"],
            "nb_low": nb_vulns["low"],
            "nb_medium": nb_vulns["medium"],
            "nb_high": nb_vulns["high"],
            "nb_critical": nb_vulns["critical"],
            "engine_name": self.name,
            "engine_version": self.version,
        }

        return issues, summary

    def getfindings(self, scan_id):
        """Return the findings of a scan identified by it 'id'."""
        res = {"page": "getfindings", "scan_id": scan_id}
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(
                1002, "scan_id '{}' not found".format(scan_id)
            )

        # check if the scan is finished (thread as well)
        self.status_scan(scan_id)
        if self.scans[scan_id]["status"] != "FINISHED":
            raise PatrowlEngineExceptions(
                1003,
                "scan_id '{}' not finished (status={})".format(
                    scan_id, self.scans[scan_id]["status"]
                ),
            )

        issues = []
        summary = {}
        issues, summary = self._parse_results(scan_id)

        with open(
            f"{self.base_dir}/results/final/{self.name}-{scan_id}.json", "w"
        ) as report_file:
            json.dump(
                {"scan": {"scan_id": scan_id}, "summary": summary, "issues": issues},
                report_file,
                default=_json_serial,
            )

        # remove the scan from the active scan list
        self.clean_scan(scan_id)
        shutil.rmtree(f"{self.base_dir}/logs/{scan_id}")
        shutil.rmtree(f"{self.base_dir}/targets/{scan_id}")
        shutil.rmtree(f"{self.base_dir}/results/{scan_id}")

        res.update({"summary": summary, "issues": issues, "status": "success"})
        return jsonify(res)

    def getreport(self, scan_id: int):
        """Return the report of a scan identified by it 'id'.
        :scan_id: Scan ID"""
        # res = {"page": "getreport", "scan_id": scan_id}
        message = ""
        if scan_id not in self.scans.keys():
            message = f"{scan_id} (scan not found)"

        # remove the scan from the active scan list
        self.clean_scan(scan_id)

        filepath = f"{self.base_dir}/results/{self.name}-{scan_id}.json"
        if not os.path.exists(filepath):
            raise PatrowlEngineExceptions(
                1001, f"Report file for id '{scan_id}' not found" + message
            )

        return send_file(
            filepath,
            mimetype="application/json",
            attachment_filename=f"{self.name}-{scan_id}.json",
            as_attachment=True,
        )

    def page_not_found(self):
        """Return the default page."""
        return jsonify({"page": "Not found"})

    def default(self):
        """Return the default page."""
        return redirect(url_for("index"))

    def index(self):
        """Return the index page."""
        return jsonify({"page": "index"})


class PatrowlEngineFinding:
    """Class definition of PatrowlEngineFinding."""

    def __init__(
        self,
        issue_id,
        type,
        title,
        description,
        solution,
        severity,
        confidence,
        raw,
        target_addrs,
        target_proto="tcp",
        meta_links=[],
        meta_tags=[],
        meta_vuln_refs={},
        meta_risk={},
        timestamp=None,
    ):
        """Initialise a new PatrowlEngineFinding."""
        self.issue_id = issue_id
        self.type = type
        self.title = title
        self.description = description
        self.solution = solution
        self.severity = severity
        self.confidence = confidence
        self.raw = raw
        self.target_addrs = target_addrs
        self.target_proto = target_proto
        self.meta_links = meta_links
        self.meta_tags = meta_tags
        self.meta_vuln_refs = meta_vuln_refs
        self.meta_risk = meta_risk
        if timestamp:
            self.timestamp = timestamp
        else:
            self.timestamp = int(time.time() * 1000)

    def __to_dict(self):
        return {
            "issue_id": self.issue_id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "solution": self.solution,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": {"addr": self.target_addrs, "protocol": self.target_proto},
            "metadata": {
                "tags": self.meta_tags,
                "links": self.meta_links,
                "vuln_refs": self.meta_vuln_refs,
                "risk": self.meta_risk,
            },
            "raw": self.raw,
            "timestamp": self.timestamp,
        }


class PatrowlEngineScan:
    """Class definition of PatrowlEngineScan."""

    def __init__(self, assets, options, scan_id):
        """Initialise a new PatrowlEngineScan."""
        self.assets = assets
        self.options = options
        self.scan_id = scan_id
        self.threads = []
        self.status = "STARTED"
        self.started_at = int(time.time() * 1000)
        self.findings = []

    def __to_dict(self):
        return {
            "assets": self.assets,
            "options": self.options,
            "scan_id": self.scan_id,
            "status": self.status,
        }

    def add_issue(self, issue):
        """Add an issue to the list of findings."""
        self.findings.append(issue)

    def had_options(self, options):
        """Check if the scan is started with options."""
        opts = []
        if isinstance(options, str):
            opts.append(options)
        elif isinstance(options, list):
            opts = options

        for o in opts:
            if o not in self.options or self.options[o] is None:
                return False

        return True
