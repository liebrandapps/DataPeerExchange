'''
  Mark Liebrand 2023
  This file is part of DataPeerExchange which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DataPeerExchange
'''

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from os.path import join, exists

from myio.liebrand.dpex.config import Config
from myio.liebrand.dpex.daemon import Daemon
from myio.liebrand.dpex.sender import Sender

APP = "dpexServer"
SECTION = "general"
CONFIG_DIR = "./"
CONFIG_FILE = "dpexServer.ini"


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
            "serverKeyDir": ["String", "./serverKey"],
            "clientRoot": ["String", "./clients"],
            "keyBits": ["Integer", 4096],
            "serverHost": ["String", None],
            "serverPort": ["Integer", 0],
            "chunkSize": ["Integer", 768],
            "maxChunks": ["Integer", 100000],
            "timeout": ["Integer", 30],
            "pidFile": ["String", "/tmp/" + APP + ".pid"],
        },
        "logging": {
            "logFile": ["String", "/tmp/dpexServer.log"],
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

    if len(sys.argv) > 1:
        todo = sys.argv[1]
        if todo in ['start', 'stop', 'restart', 'status']:
            runAsDaemon = True
            pidFile = cfg.general_pidFile
            logFile = cfg.logging_logFile
            d = Daemon(pidFile, APP, logFile)
            d.startstop(todo, stdout=logFile, stderr=logFile)

    log = setupLogger()
    if log is None:
        sys.exit(-126)

    sdr = Sender(cfg, log)
    sdr.op("init")

    if len(sys.argv)>1 and sys.argv[1].lower() == "add":
        if len(sys.argv) < 3:
            print("'add' requires name of json file as argument")
            sys.exit(-1)

        flName = sys.argv[2]
        if not (exists(flName)):
            print(f"File {flName} does not exist")
            sys.exit(-1)

        with open(flName) as fp:
            dta = json.load(fp)
        sdr.op("add", dta)
    else:
        sdr.serve()
