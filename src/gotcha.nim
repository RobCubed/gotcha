import std/inotify
import std/osproc
import std/parsecfg
import std/httpclient
import std/strutils
import std/strformat
import std/times
import std/os
import std/json
import std/posix

when not defined(linux): 
    echo "this only works on linux, sorry"
    exit(1)

var config = newConfig()
config.setSectionKey("", "hostname", readFile("/etc/hostname").strip())
config.setSectionKey("", "logfile", "./log.txt")
config.setSectionKey("", "watchPath", "~/passwords.txt")

config.setSectionKey("webhook", "enabled", "false")
config.setSectionKey("webhook", "url", "https://example.com/panic")

config.setSectionKey("email", "enabled", "false")
config.setSectionKey("email", "address", "security@example.com")
config.setSectionKey("email", "sendmailBin", "/usr/sbin/sendmail")

if fileExists("gotcha.cfg"):
    config = loadConfig("gotcha.cfg")
else:
    writeConfig(config, "gotcha.cfg")
    echo "Config written, please edit and re-run"
    quit(0)

var hostname = config.getSectionValue("", "hostname")
var watchPath = expandTilde(config.getSectionValue("", "watchPath"))

const emailTemplate = """Subject: [{hostname}] File opened: {watchPath}

The file '{watchpath}' was opened for read access at {$now()}"""

template dontError(code: untyped) =
  try:
    code
  except: discard

proc opened() =
    var log = open(config.getSectionValue("", "logfile"), fmAppend)
    var message = &"[{$now()}] File '{watchPath}' was opened."
    log.writeLine(message)
    log.close()
    echo message

    if config.getSectionValue("webhook", "enabled") == "true":
        var http = newHttpClient("Gotcha/0.1.0", headers = newHttpHeaders({"Content-Type": "application/json"}))
        var payload = %*{
            "hostname": hostname,
            "timestamp": epochTime()
        }
        dontError:
          discard http.postContent(config.getSectionValue("webhook", "url"), $payload)

    if config.getSectionValue("email", "enabled") == "true":
        dontError:
          discard execCmdEx(config.getSectionValue("email", "sendmailBin") & " " & config.getSectionValue("email", "address"), input=emailTemplate.fmt)

if not fileExists(watchPath):
    writeFile(watchPath, "root: y2bcAKGirEzVQVdqvDGwgyAd")
    echo "Created example file at ", watchPath, ", feel free to customize as necessary."
    echo "(If this is still running, you will trigger an alert)"

var notifier = inotify_init()
discard notifier.inotify_add_watch(watchPath.cstring, IN_OPEN)

var events = newSeq[byte](8192)

while (let n = posix.read(notifier, events[0].addr, 8192); n) > 0:     # read forever  echo n
  for e in inotify_events(events[0].addr, n):
    opened()

