#!/usr/bin/env python

__description__ = "Deobfuscate cobalt strike base64 beacon"
__author__ = "Pablo Rosado"

from base64 import b64decode
import sys
import logging
import re
import gzip
import optparse

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="[%(asctime)s][%(levelname)s]: %(message)s")

class CobaltConfiguration():
    def __init__(self, config):
        logging.debug(f" init {config}")
        self.c2, self.ua, self.endpoints = config

class CobaltDeobfuscator():
    def __init__(self, b64=''):
        if b64 == '':
            logging.error("Base64 to deobfuscate needed! Exiting...")
            exit(255)
        self.base64 = b64
        self.encoding = sys.getdefaultencoding()

    def deobfuscateBeacon(self):
        self.__correctPadding()
        decoded = b64decode(self.base64).decode(self.encoding, 'ignore').replace('\x00','')
        second_b64 = self.__cobaltCheckerGZIP(decoded)
        decoded2 = gzip.decompress(b64decode(second_b64)).decode(self.encoding, 'ignore').replace('\x00','')
        last_b64, xorKey = self.__cobaltCheckerXOR(decoded2)
        configuration = self.__getConfig(last_b64, xorKey)
        cobaltConfig = CobaltConfiguration(self.__parseConfig(configuration))
        return cobaltConfig

    def writeOutput(self, cobaltConfig):
        logging.info(f"Possible C2: {cobaltConfig.c2}")
        logging.info(f"Possible User-Agent: {cobaltConfig.ua}")
        logging.info(f"Possible endpoints: {cobaltConfig.endpoints}")

    def __correctPadding(self):
        while len(self.base64) % 4 != 0:
            self.base64 = self.base64[:-1]

    def __cobaltCheckerGZIP(self, decoded):
        if "FromBase64String" in decoded:
            logging.debug(f"GZIP checker - {decoded}")
            second_b64 = re.findall("FromBase64String\((\"[^\"]*|\'[^\']*)", decoded)
            logging.debug(f"second b64 - {second_b64[0]}")
            second_b64 = re.sub("(\"|\')", '', second_b64[0])
            logging.debug(f"Second b64 - {second_b64}")
        else:
            logging.error("Cobalt configuration not found!. Exiting...")
            exit(1)
        return second_b64

    def __cobaltCheckerXOR(self, decoded):
        if "FromBase64String" in decoded:
            logging.debug(f"entrando checker XOR - {decoded}")
            last_b64 = re.findall("FromBase64String\((\"[^\"]*|\'[^\']*)", decoded)
            logging.debug(f"Last b64 - {last_b64[0]}")
            last_b64 = re.sub("(\"|\')", '', last_b64[0])
            logging.debug(f"Last b64 - {last_b64}")
            xorKey = re.findall("bxor[^\n]*", decoded)
            if xorKey:
                xorKey = int(re.findall("bxor[^\n]*", decoded)[0].split(" ")[-1])
            logging.debug(f"XOR KEY - {xorKey}")
        else:
            logging.error("Cobalt configuration not found!. Exiting...")
            exit(2)
        return last_b64, xorKey
    
    def __getConfig(self, b64, xorKey):
        decoded = b64decode(b64)
        if xorKey:
            logging.debug(f"GET CONFIG DECODED - {type(decoded), type(xorKey)}")
            decoded = self.__bxor(decoded, xorKey)
        return decoded.decode(self.encoding, 'ignore').replace('\x00','')

    def __parseConfig(self, configuration):
        ua = re.findall("User-Agent:([^\n]*)", configuration)[0]
        endpoints = re.findall("/[0-9a-zA-Z]{1,6}", configuration)
        c2 = re.findall("(?:[a-z0-9]\-*[a-z0-9]*){1,}\.[a-z]{2,3}", configuration)
        logging.debug(f"len C2 - {len(c2)}")
        if len(c2) == 0:
            logging.debug(f"C2 Search -\n {configuration}")
            c2 = re.findall("(?:(?:[0-9]){1,3}\.){3}[0-9]{1,3}", configuration)
        logging.debug(f"Possible endpoints: - {endpoints} \n Possible User-Agent: {ua} \n Possible C2: {c2}")
        return c2[0], ua, endpoints

    def __bxor(self, bytes_, xorKey):
        return bytes([byte_ ^ xorKey for byte_ in bytes_])

def checkOptions(options):
    if options.base64 and options.file:
        logging.error(f"--file and --base64 not supported together!. Exiting...")
        exit(3)
    elif not options.base64 and not options.file:
        logging.error(f"No base64 provided . Exiting...")
        exit(3)
    elif options.base64:
        return 1
    elif options.file:
        return 2

def runBase64(options):
    deobfuscator = CobaltDeobfuscator(options.base64)
    output = deobfuscator.deobfuscateBeacon()
    deobfuscator.writeOutput(output)

def runFile(options):
    beacons = [""]
    try:
        with open(options.file, encoding="utf-8") as f:
            beacons = f.read().split("\n")
    except Exception as e:
        logging.error("Error al abrir archivo de configuración, %s" % e)
        exit(255)
    for b in beacons:
        options.base64 = b
        runBase64(options)

if __name__ == '__main__':
    oParser = optparse.OptionParser(usage='usage: python3 deobfuscateCobalt_beacon.py -b64 BASE64')
    oParser.add_option('-b', '--base64', action='store', default='', help='Base64 string to deobfuscate')
    oParser.add_option('-f', '--file', action='store', default='', help='File with base64 to deobfuscate')
    (options, args) = oParser.parse_args()
    menu = checkOptions(options)
    switch_mode = {
        1: runBase64,
        2: runFile
    }
    switch_mode.get(menu)(options)