"""
  Mark Liebrand 2023
  This file is part of DataPeerExchange which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DataPeerExchange
"""

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from os.path import join, exists

from myio.liebrand.dpex.config import Config
from myio.liebrand.dpex.receiver import Receiver

APP = "dpexClient"
SECTION = "general"
CONFIG_DIR = "./"
CONFIG_FILE = "dpexClient.ini"


def setupLogger():
    global runAsDaemon
    try:
        _log = logging.Logger(APP)
        loghdl = RotatingFileHandler(cfg.logging_logFile, 'a', cfg.logging_maxFilesize, 4)
        loghdl.setFormatter(logging.Formatter(cfg.logging_msgFormat))
        loghdl.setLevel(cfg.logging_logLevel)
        _log.addHandler(loghdl)
        if cfg.logging_stdout and not runAsDaemon:
            loghdl = logging.StreamHandler(sys.stdout)
            loghdl.setFormatter(logging.Formatter(cfg.logging_msgFormat))
            loghdl.setLevel(cfg.logging_logLevel)
            _log.addHandler(loghdl)
        _log.disabled = False
        return _log
    except Exception as e:
        print("[%s] Unable to initialize logging. Reason: %s" % (APP, e))
        return None


if __name__ == "__main__":
    doTerminate = False
    runAsDaemon = False
    initialConfig = {
        "general": {
            "exchangeKeyDir": ["String", "./clientKey"],
            "uidFile": ["String", "uid.txt"],
            "keyBits": ["Integer", 4096],
            "incomingDir": ["String", "./incoming"]
        },
        "logging": {
            "logFile": ["String", "/tmp/dpexClient.log"],
            "maxFilesize": ["Integer", 1000000],
            "msgFormat": ["String", "%(asctime)s, %(levelname)s, %(module)s {%(process)d}, %(lineno)d, %(message)s"],
            "logLevel": ["Integer", 10],
            "stdout": ["Boolean", True],
        },
    }
    path = join(CONFIG_DIR, CONFIG_FILE)
    if not (exists(path)):
        print("[%s] No config file %s found at %s, using defaults" % (APP, CONFIG_FILE, CONFIG_DIR))
    cfg = Config(path)
    cfg.addScope(initialConfig)
    log = setupLogger()
    if log is None:
        sys.exit(-126)

    rcv = Receiver(cfg, log)

    if len(sys.argv) < 2:
        print("You must provide at least on argument as operation")
        sys.exit(-1)

    op = sys.argv[1]

    if op.lower() == "init":
        rcv.op("init")

    if op.lower() == "update":
        if len(sys.argv) < 3:
            print("'update' requires name of json file as argument")
            sys.exit(-1)

        flName = sys.argv[2]
        if not (exists(flName)):
            print(f"File {flName} does not exist")
            sys.exit(-1)

        with open(flName) as fp:
            dta = json.load(fp)
        rcv.op("update", dta)

    if op.lower() == "ls":
        rcv.op("ls")

    if op.lower() == "get":
        rcv.op("get", sys.argv[2:])

    if op.lower() == "getall":
        rcv.op("getall")

    if op.lower() == "update":
        if len(sys.argv) < 3:
            print("'update' requires at least one file name as argument")
            sys.exit(-1)
