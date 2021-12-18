from struct import pack
from colorama.ansi import Style
from scapy.all import *
from scapy.layers import *
from scapy.layers.http import HTTPRequest, HTTPResponse # import HTTP packet
from colorama import init, Fore
from url_notification import Notificaton
import sys
import re
import zlib
import json
import io
import ast

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET
class HellCapture:

    def __init__(self):
        self.__request_packet = None
    
    def after_capture_response(self):
        self.__request_packet = None

    def on_capture_hell(self, object):
        '''
        ex:
        {'is_quest': True,
        'quest_name': 'ディメンション・ヘイロー',
        'chapter_id': '51005',
        'location_id': '10000',
        'quest_skip': [],
        'open_chapter_id': '51005',
        'is_normal_hell': {'type': True},
        'group_id': '100',
        'quest_id': '510051',
        'quest_type': '5'}
        '''
        self.after_capture_response()
        print(RED)
        print('Hell出現!!')
        print(object)
        # TODO -> ドメイン/#quest/supporter/quest_id/quest_typeに遷移
        nf = Notificaton()
        nf.show('Hell出現!!!', f'http://game.granbluefantasy.jp/#quest/supporter/{object["quest_id"]}/{object["quest_type"]}')

    def request_filter(self, packet):
        if packet.haslayer(HTTPRequest):
            # 目的のRequestを探す
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            if packet[HTTPRequest].Host.decode() == 'game.granbluefantasy.jp':
                if re.match(r'^(game.granbluefantasy.jp/resultmulti/data/).*', url) or\
                re.match(r'^(game.granbluefantasy.jp/result/data/).*', url):
                    print(RED + url + Style.RESET_ALL)
                    self.__request_packet = packet
                    self.__request_packet.show()
                    return True
        return False
    
    def response_filter(self, packet, request_packet):
        if request_packet and packet.haslayer(Raw) and packet.haslayer(HTTPResponse):
            # Responseを探す
            if packet[HTTPResponse].answers(request_packet[HTTPRequest]):
                print(GREEN)
                payload = json.loads(packet['Raw'].load.decode('unicode-escape'))
                print(payload)
                return True
                if payload['appearance']:
                    self.on_capture_hell(payload['appearance'])
                else:
                    print(RED)
                    print('出現しませんでした。')
                    self.after_capture_response()
        return False

    def process_packet(self, packet):
        if packet.haslayer(HTTPRequest):
            # 目的のRequestを探す
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            if packet[HTTPRequest].Host.decode() == 'game.granbluefantasy.jp':
                if re.match(r'^(game.granbluefantasy.jp/resultmulti/data/).*', url) or\
                re.match(r'^(game.granbluefantasy.jp/result/data/).*', url):
                    print(RED + url + Style.RESET_ALL)
                    self.__request_packet = packet
                    self.__request_packet.show()
        if self.__request_packet and packet.haslayer(Raw) and packet.haslayer(HTTPResponse):
            # Responseを探す
            if packet[HTTPResponse].answers(self.__request_packet[HTTPRequest]):
                print(GREEN)
                payload = json.loads(packet['Raw'].load.decode('unicode-escape'))
                print(payload)
                if payload['appearance']:
                    self.on_capture_hell(payload['appearance'])
                else:
                    print(RED)
                    print('出現しませんでした。')
                    self.after_capture_response()
