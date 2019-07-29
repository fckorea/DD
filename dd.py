#-*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        Detection Dog
# Purpose:
# Python version: 3.7.3
#
# Author:    fckorea
#
# Created:    2019-07-27
# (c) fckorea 2019
#-------------------------------------------------------------------------------

import sys
from optparse import OptionParser
import os.path
import logging
import logging.handlers
import datetime
import time
import json
import traceback
import re

PROG_VER = '0.1'
LOGGER = None
LOG_FILENAME = './detection-dog.log'
CONFIG = {}

#=============================== Check Functions ===============================#
def fnProcess(argTarget, argSubDir):
    global LOGGER
    global CONFIG

    try:
        target_list = []

        if os.path.isfile(argTarget):
            target_list.append(os.path.abspath(argTarget))
        elif os.path.isdir(argTarget):
            for (path, dir, files) in os.walk(argTarget):
                for filename in files:
                    target_list.append(os.path.abspath(os.path.join(path, filename)))
                if argSubDir is None or argSubDir is False:
                    break
        
        for check_path in target_list:
            LOGGER.debug(' * Check file("%s")' % (check_path))

            check_path_ext = os.path.splitext(check_path)[-1].lower()

            if check_path_ext in CONFIG['extension']:
                result = []
                LOGGER.info(' * Matched extension("%s")' % (check_path_ext))
                
                with open(check_path, encoding='UTF8') as read_file:
                    content = read_file.read()
                    for pattern in CONFIG['pattern']:
                        idx = fnCheck(content, pattern['type'], pattern['data'])
                        if idx > -1:
                            (line_at, column_at) = fnGetFindAt(content, idx)
                            LOGGER.debug(' * Matched pattern!!! (%s) - %s:%d, %d' % (pattern['data'], check_path, line_at, column_at))
                            result.append({
                                'type': pattern['type'],
                                'data': pattern['data'],
                                'line': line_at,
                                'column': column_at
                            })
                read_file.close()

                LOGGER.info(' * Check result (%s) - Find: %d' % (check_path, len(result)))
                for res in result:
                    LOGGER.info(' ** %s(%s):%d, %d' % (check_path, res['data'], res['line'], res['column']))

    except:
        LOGGER.debug(' *** Error in path traversal.')
        LOGGER.debug(traceback.format_exc())

def fnCheck(argContent, argCheckType, argCheckValue):
    global LOGGER
    
    result = False

    if argCheckType == 'string':
        LOGGER.debug(' * Check string type(%s), value(%s)' % (argCheckType, argCheckValue))
        return argContent.find(argCheckValue)
    elif argCheckType == 'regex':
        LOGGER.debug(' * Check regex type(%s), value(%s)' % (argCheckType, argCheckValue))
    
    return result

def fnGetFindAt(argContent, argIdx):
    column_count = argIdx
    line_count = argContent[:argIdx].count('\n') + 1

    if line_count > 0:
        before_lines = argContent[:argIdx].split('\n')[:-1]
        column_count -= len('\n'.join(before_lines))
        if argContent[:argIdx].count('\r') > 0:
            column_count -= len(before_lines)
        
        if line_count == 1:
            column_count += 1
    
    return (line_count, column_count)

#=============================== Config & Init Function ===============================#
def fnGetConfig(argOptions):
    global LOGGER
    global CONFIG

    try:
        if os.path.isfile(argOptions.o_sConfig):
            CONFIG = json.loads(open(argOptions.o_sConfig, encoding='UTF8').read())
            CONFIG['extension'] = [ item.lower() if item.startswith('.') else '.' + item.lower() for item in CONFIG['extension'] ]
            LOGGER.info(' * Read data')
            LOGGER.info(' * Updated: %s, Count of data: %d, Target extension: %s ' % (CONFIG['updated'], len(CONFIG['pattern']), ', '.join(CONFIG['extension'])))
            return True
        else:
            LOGGER.error(' * Config file not found.')
    except:
        LOGGER.debug(' *** Error read config file.')
        LOGGER.debug(traceback.format_exc())
    
    return False

#=============================== Main Functions ===============================#
def fnMain(argOptions, argArgs):
    global LOGGER
    global CONFIG

    try:
        # LOGGER.debug('in fnMain')

        if argOptions.o_sTarget is None:
            LOGGER.info(' * Target is not setted.')
            return

        if argOptions.o_bVerbose is True:
            LOGGER.setLevel(logging.DEBUG)

        if os.path.isfile(argOptions.o_sTarget) or os.path.isdir(argOptions.o_sTarget):
            LOGGER.info(' * Target("%s") is %s.' % (argOptions.o_sTarget, 'file' if os.path.isfile(argOptions.o_sTarget) else ('directory (sub: %s)' % argOptions.o_bSubDir)))
            fnProcess(argOptions.o_sTarget, argOptions.o_bSubDir)
        else:
            LOGGER.info(' * Target("%s") is not found.' % (argOptions.o_sTarget))
    except:
        raise

#=============================== OptionParser Functions ===============================#
def fnSetOptions():
    global PROG_VER

    l_hParser = None

    l_lOptions = [
        { 'Param': ('-c', '--config'), 'action': 'store', 'metavar': '<Config file path>', 'type': 'string', 'dest': 'o_sConfig', 'default': 'config.conf', 'help': 'Set config file path.\t\tdefault) config.conf (contents type is JSON)' },
        { 'Param': ('-t', '--target'), 'action': 'store', 'metavar': '<Detection target path>', 'type': 'string', 'dest': 'o_sTarget', 'help': 'Set target path.\t\t*Required' },
        { 'Param': ('-s', '--sub_dir'), 'action': 'store_true', 'metavar': '<Is sub directory>', 'dest': 'o_bSubDir', 'default': False, 'help': 'Set travel sub directory.\tdefault) False' },
        { 'Param': ('-v', '--verbose'), 'action': 'store_true', 'metavar': '<Verbose Mode>', 'dest': 'o_bVerbose', 'default': False, 'help': 'Set verbose mode.\t\tdefault) False' }
    ]
    l_sUsage = '%prog [options]\n ex) %prog ...'

    l_hParser = OptionParser(usage = l_sUsage, version = '%prog ' + PROG_VER)

    for l_dOption in l_lOptions:
        l_tParam = l_dOption['Param']
        del l_dOption['Param']
        l_hParser.add_option(*l_tParam, **l_dOption)

    return l_hParser

def fnGetOptions(argParser):
    if(len(sys.argv) == 1):
        return argParser.parse_args(['--help'])

    return argParser.parse_args()

def fnInit():
    global LOGGER
    global LOG_FILENAME

    LOGGER = logging.getLogger('Detection-Dog')
    LOGGER.setLevel(logging.INFO)

    formatter = logging.Formatter('[%(levelname)s] - %(filename)s:%(lineno)s\t- %(asctime)s - %(message)s')
    
    file_handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='midnight', backupCount=7, encoding='UTF-8')
    file_handler.suffix = '%Y%m%d'
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stream_handler)

    return True

if __name__ == '__main__':
    if fnInit():
        LOGGER.info('Start Detection Dog...')

        l_hParser = fnSetOptions()
        (l_hOptions, l_vArgs) = fnGetOptions(l_hParser)
        if fnGetConfig(l_hOptions):
            fnMain(l_hOptions, l_vArgs)

        LOGGER.info('Terminate Detection Dog...')
