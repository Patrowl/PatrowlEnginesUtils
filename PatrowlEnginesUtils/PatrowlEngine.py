# -*- coding: utf-8 -*-
"""This file manages PatrowlEngine and its common features."""


import os
import urllib.parse as urlparse
# import urllib
import time
import datetime
import optparse
import json
import ssl
from uuid import UUID
from flask import jsonify, url_for, redirect, send_from_directory, abort
from .PatrowlEngineExceptions import PatrowlEngineExceptions

DEFAULT_APP_HOST = "127.0.0.1"
DEFAULT_APP_PORT = 5000
DEFAULT_APP_DEBUG = False
DEFAULT_APP_MAXSCANS = 25


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime.datetime) or isinstance(obj, datetime.date):
        return obj.isoformat()
    if isinstance(obj, UUID):
        # if the obj is uuid, we simply return the value of uuid
        return obj.hex
    raise TypeError("Type not serializable")


class PatrowlEngine:
    """Class definition of PatrowlEngine."""

    def __init__(self, app, base_dir, name, max_scans=DEFAULT_APP_MAXSCANS, version=0):
        """Initialise a new PatrowlEngine."""
        self.app = app
        self.base_dir = str(base_dir)
        self.name = name
        self.version = version
        self.description = ""
        self.allowed_asset_types = []
        self.options = {}
        self.scans = {}
        self.max_scans = max_scans
        self.status = "INIT"

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

    def run_app(self, app_debug=DEFAULT_APP_DEBUG, app_host=DEFAULT_APP_HOST,
                app_port=DEFAULT_APP_PORT, threaded=True):
        """Run the flask server."""
        if not os.path.exists(self.base_dir+"/results"):
            os.makedirs(self.base_dir+"/results")

        self._loadconfig()
        parser = optparse.OptionParser()
        parser.add_option(
            "-H", "--host", default=app_host,
            help="PatrowlEngine hostname [default %s]" % DEFAULT_APP_HOST)
        parser.add_option(
            "-P", "--port", default=app_port,
            help="Port for the Patrowl Engine [default %s]" % DEFAULT_APP_PORT)
        parser.add_option(
            "-d", "--debug", action="store_true", dest="debug",
            help=optparse.SUPPRESS_HELP)
        parser.add_option(
            "", "--cert", dest='certfile', default=None,
            help="Certificate filename")
        parser.add_option(
            "", "--key", dest='keyfile', default=None,
            help="Private key filename")
        parser.add_option(
            "", "--password", dest='keypass', default=None,
            help="Private key password")
        parser.add_option(
            "", "--auto-tls", dest='tls', action="store_true",
            help="Enable TLS with dummy certificate")

        options, _ = parser.parse_args()

        if options.certfile and options.tls:
            parser.error("options --cert and --auto-tls are mutually exclusive")

        if options.certfile and not options.keyfile:
            parser.error("option --key missing")

        self.app.run(
            debug=options.debug, host=options.host, port=int(options.port),
            threaded=threaded, ssl_context=self._getsslcontext(options))

    def liveness(self):
        """Return the liveness status."""
        return 'OK', 200

    def readiness(self):
        """Return the readiness status."""
        if len(self.scans) >= self.max_scans or self.status != "READY":
            abort(500)
        else:
            return 'OK', 200

    def test(self):
        """Return the test page."""
        res = "<h2>Test Page (DEBUG):</h2>"
        for rule in self.app.url_map.iter_rules():
            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ','.join(rule.methods)
            url = url_for(rule.endpoint, **options)
            res += urlparse.urlsplit(
                "{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(
                    rule.endpoint, methods, url))
        return res

    def info(self):
        """Return the info page."""
        self.getstatus()
        return jsonify({"page": "info", "engine_config": self.__to_dict()})

    def _loadconfig(self):
        """Load the configuration file."""
        conf_file = self.base_dir+'/'+self.name+'.json'
        if os.path.exists(conf_file):
            engine_config = json.load(open(conf_file))
            self.version = engine_config["version"]
            self.description = engine_config["description"]
            self.options = engine_config["options"]
            self.allowed_asset_types = engine_config["allowed_asset_types"]
            self.status = "READY"
        else:
            self.status = "ERROR"
            return {"status": "ERROR", "reason": "config file not found"}

    def _getsslcontext(self, options):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if options.tls:
            context = 'adhoc'
        elif options.certfile:
            # set password to empty string not None to
            # avoid prompt if private key is protected
            # this had no effect if private key is not protected
            if options.keypass is None:
                options.keypass = ""

            context.load_cert_chain(
                certfile=options.certfile,
                keyfile=options.keyfile,
                password=options.keypass
            )
        else:
            context = None

        return context

    def reloadconfig(self):
        """Reload the configuration file."""
        res = {"page": "reloadconfig"}
        self._loadconfig()
        res.update({"config": {
            "status": self.status
        }})
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

    def clean(self):
        """Clean all the scans."""
        res = {"page": "clean"}
        self.scans.clear()
        self._loadconfig()
        res.update({"status": "SUCCESS"})
        return jsonify(res)

    def clean_scan(self, scan_id):
        """Clean a scan identified by his 'id'."""
        res = {"page": "clean_scan"}
        res.update({"scan_id": scan_id})

        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

        self.scans.pop(scan_id)
        # Todo: force terminating all threads
        res.update({"status": "removed"})
        return jsonify(res)

    def getstatus_scan(self, scan_id):
        """Get the status of a scan identified by his 'id'."""
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

        all_threads_finished = True
        for t in self.scans[scan_id]['threads']:
            if t.is_alive():
                all_threads_finished = False
                break

        if all_threads_finished and len(self.scans[scan_id]['threads']) >= 1:

            if self.scans[scan_id]['status'] == "SCANNING":
                # all threads are finished, ensure scan status is no more SCANNING
                self.scans[scan_id]['status'] = "FINISHED"

            if 'finished_at' not in self.scans[scan_id].keys():
                # update finished time if not already set
                self.scans[scan_id]['finished_at'] = int(time.time() * 1000)

        return jsonify({"status": self.scans[scan_id]['status']})

    def getstatus(self):
        """Get the status of the engine and all its scans."""
        res = {"page": "status"}

        if len(self.scans) == self.max_scans:
            self.status = "BUSY"
        else:
            self.status = "READY"

        scans = []
        for scan_id in self.scans.keys():
            self.getstatus_scan(scan_id)
            scans.append({scan_id: {
                "status": self.scans[scan_id]['status'],
                "started_at": self.scans[scan_id]['started_at'],
                "assets": self.scans[scan_id]['assets']
            }})

        res.update({
            "nb_scans": len(self.scans),
            "status": self.status,
            "scans": scans})
        return jsonify(res)

    def stop_scan(self, scan_id):
        """Stop a scan identified by his 'id'."""
        res = {"page": "stop"}

        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

        self.getstatus_scan(scan_id)
        if self.scans[scan_id]['status'] not in ["STARTED", "SCANNING"]:
            res.update({
                "status": "ERROR",
                "reason": "scan '{}' is not running (status={})".format(
                    scan_id, self.scans[scan_id]['status'])
                })
            return jsonify(res)

        for t in self.scans[scan_id]['threads']:
            t.join()
            self.scans[scan_id]['threads'].remove(t)
            # t._Thread__stop()
        self.scans[scan_id]['status'] = "STOPPED"
        self.scans[scan_id]['finished_at'] = int(time.time() * 1000)

        res.update({"status": "SUCCESS"})
        return jsonify(res)

    # Stop all scans
    def stop(self):
        """Stop all the scans."""
        res = {"page": "stopscans"}
        for scan_id in self.scans.keys():
            self.stop_scan(scan_id)
        res.update({"status": "SUCCESS"})
        return jsonify(res)

    def init_scan(self, params):
        """Initialise a scan."""
        res = {"page": "startscan", "status": "INIT"}

        # check the scanner is ready to start a new scan
        if len(self.scans) == self.max_scans:
            res.update({
                "status": "ERROR",
                "reason": "Scan refused: max concurrent active scans reached \
                    ({})".format(self.max_scans)
            })
            return res

        self.getstatus()
        if self.status != "READY":
            res.update({
                "status": "ERROR",
                "details": {
                    "reason": "scanner not ready",
                    "status": self.status
                    }
                }
            )
            return res

        data = json.loads(params)
        if 'assets' not in data.keys():
            res.update({
                "status": "ERROR",
                "details": {
                    "reason": "Arg error, something is missing ('assets' ?)"
                    }
                }
            )
            return res

        # Sanitize args :
        scan_id = str(data['scan_id'])
        res.update({"details": {"scan_id": scan_id}})
        new_scan = PatrowlEngineScan(
            assets=data['assets'],
            options=data['options'],
            scan_id=scan_id
        )

        self.scans.update({scan_id: new_scan.__dict__})
        return res

    def _parse_results(self, scan_id):
        """Parse the results."""
        if scan_id not in self.scans.keys():
            raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

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
            "engine_version": self.version
        }

        return issues, summary

    def getfindings(self, scan_id):
        """Return the findings of a scan identified by it 'id'."""
        try:
            scan = self.scans[scan_id]
        except Exception:
            raise PatrowlEngineExceptions(1002, "scan_id '{}' not found".format(scan_id))

        res = {"page": "getfindings", "scan_id": scan_id}

        # check if the scan is finished
        self.getstatus_scan(scan_id)
        if scan['status'] != "FINISHED":
            raise PatrowlEngineExceptions(1003, "scan_id '{}' not finished (status={})".format(
                    scan_id, scan['status']))

        issues, summary = self._parse_results(scan_id)

        # Store the findings in a file
        report_filename = "{}/results/{}_{}.json".format(
            self.base_dir, self.name, scan_id)
        with open(report_filename, 'w') as report_file:
            json.dump({
                "scan": {
                    "scan_id": scan_id
                },
                "summary": summary,
                "issues": issues
            }, report_file, default=_json_serial)

        # remove the scan from the active scan list
        self.clean_scan(scan_id)

        res.update({
            "scan": scan_id,
            "summary": summary,
            "issues": issues,
            "status": "success"
        })
        return jsonify(res)

    def getreport(self, scan_id):
        """Return the report of a scan identified by it 'id'."""
        filepath = "{}/results/{}_{}.json".format(
            self.base_dir, self.name, scan_id)
        if not os.path.exists(filepath):
            raise PatrowlEngineExceptions(1001, "Report file for id '{}' not found".format(scan_id))

        return send_from_directory(
            self.base_dir+"/results/",
            "{}_{}.json".format(self.name, scan_id))

    def page_not_found(self):
        """Return the default page."""
        return jsonify({"page": "Not found"})

    def default(self):
        """Return the default page."""
        return redirect(url_for('index'))

    def index(self):
        """Return the index page."""
        return jsonify({"page": "index"})


class PatrowlEngineFinding:
    """Class definition of PatrowlEngineFinding."""

    def __init__(self, issue_id, type, title, description, solution, severity,
                 confidence, raw, target_addrs, target_proto="tcp",
                 meta_links=[], meta_tags=[], meta_vuln_refs={}, meta_risk={},
                 timestamp=None):
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
            "target": {
                "addr": self.target_addrs,
                "protocol": self.target_proto
            },
            "metadata": {
                "tags": self.meta_tags,
                "links": self.meta_links,
                "vuln_refs": self.meta_vuln_refs,
                "risk": self.meta_risk
            },
            "raw": self.raw,
            "timestamp": self.timestamp
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
            "status": self.status
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
