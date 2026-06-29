#!/usr/bin/env python3
"""
Constants, anchors, keywords, and default paths.
"""
DEFAULT_BINARY = r"C:\Users\USER\Downloads\roblox_output\native\arm64\libroblox.so"

# Anchor strings (for locating functions in the binary)
ANCHOR1 = "debug.loadmodule is not enabled."
ANCHOR2 = "Attempted to call loadmodule with invalid argument(s)."
ANCHOR3 = "onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld"
ANCHOR4 = "onGameLoaded() SessionReporterState_GameLoaded placeId:%lld"
ANCHOR5 = "Can't resume script in this context"
ANCHOR6 = "[FLog::TaskSchedulerRun] JobStart %s"
ANCHOR7 = "[FLog::TaskSchedulerRun] JobStop %s"

# Keywords for banner scanning
KEYWORDS = [
    b"lua",
    b"luau",
    b"roblox",
    b"script",
    b"module",
    b"game",
    b"player",
    b"error",
    b"debug",
    b"load",
    b"execute",
    b"yield",
    b"resume",
    b"coroutine",
    b"closure",
    b"proto",
    b"datamodel",
]

# ELF SHF flags
SHF_FLAGS = {"W": 0x1, "A": 0x2, "X": 0x4}

# Offset table labels & notes
#  key = result dict key,  label = display name
#  note is auto-generated from the found address (sub_XXXXXXXX equiv)
OFFSET_TABLE = [
    {"key": "rbx_loadmodule", "label": "rbx_loadmodule"},
    {"key": "EnableLoadModule", "label": "EnableLoadModule"},
    {"key": "err_reporter", "label": "rbx_throwf"},
    {"key": "OnGameLeave", "label": "OnGameLeave"},
    {"key": "OnGameBegin", "label": "OnGameBegin"},
    {"key": "ScriptContextResume", "label": "ScriptContextResume"},
    {"key": "JobStart", "label": "JobStart"},
    {"key": "JobStop", "label": "JobStop"},
    {
        "key": "ScriptContext_OnServiceProvider",
        "label": "ScriptContext_OnServiceProvider",
    },
]
