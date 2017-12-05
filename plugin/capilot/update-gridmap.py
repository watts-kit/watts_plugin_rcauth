#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import json
import subprocess
import traceback

MAPFILE = "/home/watts/.config/watts/watts.map"
MAPCMD = "/home/watts/.config/watts/watts-mapfile.py"


def get_or_create_local_user(WattsId, Prefix):
    UserName = lookupPosix(WattsId)
    if UserName == None:
        return createUser(WattsId, Prefix)
    return UserName


def createUser(WattsId, UserPrefix):
    DevNull = open("/dev/null","a")
    Res = subprocess.call(["sudo", MAPCMD, "addcreate", WattsId, UserPrefix, MAPFILE], stdout=DevNull, stderr=DevNull)
    DevNull.close()
    if Res != 0:
        return None
    return lookupPosix(WattsId)


def add_user_to_gridmap(DN, UserName):
    DevNull = open("/dev/null","a")
    Res = subprocess.call(["sudo", "grid-mapfile-add-entry", "-dn", DN, "-ln", UserName], stdout=DevNull, stderr=DevNull)
    DevNull.close()
    if Res == 0:
        return json.dumps(
                {'result': 'ok', 'credential': [], 'state': DN})

    UserMsg = "adding you to the grid mapfile failed."
    LogMsg = "adding DN %s to gridmapfile failed with %s"
    return json.dumps(
                {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg%(DN,Res)})


def lookupPosix(WattsId):
    Result = subprocess.check_output([MAPCMD, "lookup", WattsId, MAPFILE])
    if len(Result) > 1:
        return Result.rstrip()
    return None


def main():
    try:
        if len(sys.argv) >= 2:
            Action = sys.argv[1]
            if Action == "add" and len(sys.argv) == 5:
                WattsId = sys.argv[2]
                DN = sys.argv[3]
                Prefix = sys.argv[4]
                UserName = get_or_create_local_user(WattsId, Prefix)
                if UserName == None:
                    LogMsg = "creation of user failed: %s %s"%(WattsId, Prefix)
                    UserMsg = "user creation failed, please contact the administrator"
                    print json.dumps(
                        {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
                else:
                    print add_user_to_gridmap(DN, UserName)

            elif Action == "add_gridmap" and len(sys.argv) == 4:
                DN = sys.argv[2]
                UserName = sys.argv[3]
                print add_user_to_gridmap(DN, UserName)

            else:
                LogMsg = "unknown action %s (len: %s)"%(Action, str(len(sys.argv)))
                UserMsg = "internal error, please contact the administrator"
                print json.dumps(
                    {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
        else:
            LogMsg = "no params given"
            UserMsg = "internal error, please contact the administrator"
            print json.dumps(
                {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})


    except Exception as E:
        TraceBack = traceback.format_exc(),
        print "sorry, I crashed: %s - %s" % (str(E), TraceBack)
        sys.exit(255)


if __name__ == "__main__":
    main()
