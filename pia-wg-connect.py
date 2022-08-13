#!/usr/bin/python
####
# Copyright (C) 2020 Christopher Pritchard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Parts adapted from: https://github.com/pia-foss/manual-connections which is Copyright (C) 2020 Private Internet Access, Inc. 
# Adapted portions licenced under the same license as above
####
#### Begin imports and package metadata
import configparser
import argparse
import os
import sys
import subprocess
import urllib
import requests
import logging
import urllib
import time
import datetime
import json
import jsonpickle
import pycurl
import base64
import dbus
from dateutil import parser as dateparser
from collections import namedtuple
from xdg.BaseDirectory import xdg_config_dirs, xdg_data_dirs
from typing import List, Optional
from types import SimpleNamespace

package_name="pia-wg-connect"

#### Begin Class Definitions
class Group:
  name: str
  sn: Optional[str]
  ports: List[int]
  def __init__(self, name: str, ports: List[int], sn: Optional[str] = None):
    self.name  = name
    self.ports = ports
    self.sn = sn
  def __repr__(self):
    return "<%s object at %s (name: %s, sn: %s)>" % (self.__class__.__name__, id(self), self.name, self.sn)
  def __eq__(self, other):
    if isinstance(other, self.__class__):
      if self.name == other.name and self.sn == other.sn:
        return True
      else:
        return False
    elif isinstance(other, str):
      if self.name == other or self.sn == other:
        return True
      else:
        return False
    else:
      return NotImplemented

class ServerDetails:
  ip: str
  cn: str
  def __init__(self, ip: str, cn: str):
    self.ip = ip
    self.cn = cn
  def __repr__(self):
    return "<%s object at %s (ip: %s)>" % (self.__class__.__name__, id(self), self.ip)
  def __eq__(self, other):
    if isinstance(other, self.__class__):
      if self.ip == other.ip and self.cn == other.cn:
        return True
      else:
        return False
    else:
      return NotImplemented

class Server:
  group: Group
  details: ServerDetails
  def __init__(self, group: Group, details: ServerDetails):
    self.group = group
    self.details = details
  def __repr__(self):
    return "<%s object at %s (type: %s, ip: %s)>" % (self.__class__.__name__, id(self), self.group.name, self.details.ip)
  def __eq__(self, other):
    if isinstance(other, self.__class__):
      if self.group == other.group and self.details == other.details:
        return True
      else:
        return False
    else:
      return NotImplemented

class Region:
  id: str
  name: str
  country: str
  auto_region: bool
  dns: str
  port_forward: bool
  geo: bool
  latency: float
  servers: List[Server]
  def __init__(self, id: str, name: str, country: str, dns: str, servers: List[Server], auto_region: bool = False, port_forward: bool = False, geo: bool = False, latency: float = float("inf")):
    self.id = id
    self.name = name
    self.country = country
    self.auto_region = auto_region
    self.dns = dns
    self.port_forward = port_forward
    self.geo = geo
    self.servers = servers
    self.latency = latency
  def __repr__(self):
    return "<%s object at %s (name: %s, country: %s, latency: %s)>" % (self.__class__.__name__, id(self), self.name, self.country, self.latency)
  def __eq__(self, other):
    if isinstance(other, self.__class__):
      if self.id == other.id:
        return True
      else:
        return False
    elif isinstance(other, str):
      if self.id == other:
        return True
      else:
        return False
    else:
      return NotImplemented
  def __hash__(self):
    return hash((self.id))

class PiaRegion:
  groups: List[Group]
  regions: List[Region]
  def __init__(self, groups: List[Group], regions: List[Region]):
    self.groups = groups
    self.regions = regions

class PiaPayload:
  token: str
  port: int
  expires_at: datetime.datetime
  __base64payload: str
  @property
  def base64payload(self) -> str:
    return self.__base64payload
  @base64payload.setter
  def base64payload(self, new_pl):
    new_pl_dec = json.loads(base64.decodebytes(new_pl.encode('UTF-8')))
    self.__base64payload = new_pl
    self.token = str(new_pl_dec['token'])
    self.port = int(new_pl_dec['port'])
    self.expires_at = dateparser.isoparse(new_pl_dec['expires_at'])
  def __init__(self, base64payload = None):
    pl = json.loads(base64.decodebytes(base64payload.encode('UTF-8')))
    self.token = str(pl['token'])
    self.port = int(pl['port'])
    self.expires_at = dateparser.isoparse(pl['expires_at'])
    self.__base64payload = base64payload

class PiaPort:
  pf_host: str
  pf_gateway: str
  signature: str
  payload: PiaPayload
  piaJson: str
  piaToken: str
  piaRegion: Region
  def __init__(self, base64payload: str, signature: str, region: Region,piaToken: str, piaJson: str, pf_host: str, pf_gateway: str):
    self.signature = signature
    self.payload = PiaPayload(base64payload=base64payload)
    self.piaRegion = region
    self.piaToken = piaToken
    self.piaJson = piaJson
    self.pf_host = pf_host
    self.pf_gateway = pf_gateway

#### Begin Variable Definitions
log_level: str = "WARN"
cafile: str = None
groups: List[Group] = []
config = configparser.ConfigParser()

#### Begin Function Definitions
def validateJSON(jsonData):
    try:
        json.loads(jsonData)
    except ValueError as err:
        return False
    return True

def pia_json_to_objects(**kwargs):
  if 'ports' in kwargs:
    group: Group = Group(name=kwargs['name'],ports=kwargs['ports'])
    groups.append(group)
    return group
  elif 'ip' in kwargs:
    return ServerDetails(ip=kwargs['ip'],cn=kwargs['cn'])
  elif 'meta' in kwargs and isinstance(kwargs['meta'][0], Group):
    groupDict: dict = {}
    for k,v in kwargs.items():
      v[0].sn = k
      groupDict[k] = v[0]
    return groupDict
  elif 'meta' in kwargs:
    listOfServers = []
    for k,v in kwargs.items():
      listOfServers.append(Server(next(x for x in groups if x == k),v[0]))
    return listOfServers
  elif 'id' in kwargs:
    return Region(id = kwargs['id'], name=kwargs['name'], country=kwargs['country'], auto_region=kwargs['auto_region'], dns=kwargs['dns'], port_forward=kwargs['port_forward'],geo=kwargs['geo'],servers=kwargs['servers'])
  elif 'groups' and 'regions' in kwargs:
    return PiaRegion(list(kwargs['groups'].values()), kwargs['regions'])
  else:
    return SimpleNamespace(**kwargs)

def get_server_latency(ip: str, timeout: int=10) -> Optional[float]:
  c = pycurl.Curl()
  try:
    logging.debug("testing: "+ip)
    c.setopt(c.URL, 'https://'+ip+':443')
    c.setopt(c.NOBODY, 1)
    c.setopt(c.CONNECTTIMEOUT, timeout)
    c.perform()
    tc = c.getinfo(c.CONNECT_TIME)
    c.close()
  except pycurl.error:
    tc = c.getinfo(c.CONNECT_TIME)
    c.close()
  if tc == 0:
    logging.debug("Timed out")
    return float('inf')
  else:
    logging.debug("Latency:" + str(tc) + "s")
    return tc
 
def get_json(url: str) -> str:
  retry = True
  count = 0
  while retry:
    try:
      logging.debug("getting url: " + url)
      resp = requests.get(url)
      cont_type = resp.headers['Content-Type'].lower()
      resp_json = resp.text.partition('\n')[0]
      if (resp.status_code == 200 and cont_type is not None and validateJSON(resp_json) is True):
        retry = False
        return resp.text.partition('\n')[0]
      else:
        time.sleep(2)
        count += 1
        if(count == 5):
          retry = False
          raise TypeError("Content does not appear to be JSON")
    except Exception as e:
      logging.error(e)

def get_best_server_region(piaregions: PiaRegion, pf: bool = False, timeout: int=10) -> Optional[Region]:
  logging.info("Getting best region... this may take a while")
  for region in piaregions.regions:
    if(region.auto_region == True and (pf == False or region.port_forward == True)):
      ipaddr: str = next(x for x in region.servers if x.group.sn == 'meta').details.ip
      region.latency = get_server_latency(ip=ipaddr, timeout=timeout)
    else:
      region.latency = float('inf')
  return sorted(piaregions.regions,key=lambda r : r.latency)[0]

def generate_token_response(region: Region, username: str, password: str) -> Optional[str]:
  logging.info("Generating token from username and password")
  server = next(x for x in region.servers if x.group == 'meta')
  ip = server.details.ip
  cn = server.details.cn
  ct = "%s::%s:" % (cn, ip)
  tokenApiPath="/authv3/generateToken"
  c = pycurl.Curl()
  if log_level == "DEBUG":
    c.setopt(c.VERBOSE, True)
  c.setopt(c.CONNECT_TO, [ct])
  c.setopt(c.URL, 'https://'+cn+tokenApiPath)
  c.setopt(c.USERNAME, username)
  c.setopt(c.PASSWORD, password)
  c.setopt(c.CAINFO, cafile)
  body = json.loads(c.perform_rs())
  c.close()
  if body['status'] == 'OK':
    return body['token']
  else:
    raise ValueError("Unable to generate token: " + body['message'])

def pia_portforward_enable(piaJson: str, piaToken: str, piaRegion: Region) -> Optional[PiaPort]:
  c = pycurl.Curl()
  server = next(x for x in piaRegion.servers if x.group == 'wg')
  ip = piaJson['server_vip']
  cn = server.details.cn
  ct = "%s::%s:" % (cn, ip)
  payload_data = {'token': piaToken}
  payloadfields = urllib.parse.urlencode(payload_data)
  if log_level == "DEBUG":
    c.setopt(c.VERBOSE, True)
  c.setopt(c.CONNECT_TO, [ct])
  c.setopt(c.URL, 'https://'+cn+":19999/getSignature?"+payloadfields)
  c.setopt(c.CAINFO, cafile)
  b = c.perform_rs()
  body = json.loads(b)
  if body['status'] == "OK":
    piaPort: PiaPort = PiaPort(base64payload=body['payload'], signature=body['signature'], region=piaRegion, piaJson=piaJson, piaToken=piaToken, pf_host=cn, pf_gateway=ip)
    logging.info("The port is: " + str(piaPort.payload.port) + " and it expires at: " + str(piaPort.payload.expires_at))
    return piaPort
  else:
    raise ValueError("Unable to generate payload: " + body['message'])

def write_pia_wg_conf(piaJson: any, privKey: str, dns: bool = False):
  fn = "/etc/wireguard/pia.conf"
  logging.info("creating pia wireguard config: "+fn)
  if dns is True:
    dnsString = "DNS = " + piaJson['dns_servers'][0]
  else:
    dnsString = ""
  file: str = """[Interface]
Address = %s
PrivateKey = %s
%s
[Peer]
PersistentKeepAlive = 25
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:%s
""" % (piaJson['peer_ip'], privKey, dnsString, piaJson['server_key'], piaJson['server_ip'],piaJson['server_port'])
  logging.debug("Begin contents of config file:\n"+file)
  logging.debug("End contents of config file")
  os.makedirs(os.path.dirname(fn), exist_ok=True)
  with open(fn,"w") as f:
    f.write(file)

def pia_disconnect_wg():
    logging.info("Stopping any existing PIA wireguard connections")
    subprocess.run(['wg-quick', 'down', 'pia'])

def pia_connect_wg(region: Region, token: str, dns: bool = False) -> Optional[str]:
  server = next(x for x in region.servers if x.group == 'wg')
  ip = server.details.ip
  cn = server.details.cn
  ct = "%s::%s:" % (cn, ip)
  result = subprocess.run(['wg', 'genkey'], stdout=subprocess.PIPE)
  if result.returncode != 0:
    raise ValueError("Failed to generate wireguard private key")
  else:
    privkey = result.stdout
  result = subprocess.run(['wg', 'pubkey'], stdout=subprocess.PIPE, input=privkey)
  if result.returncode != 0:
    raise ValueError("Failed to generate wireguard public key")
  else:
    pubkey = result.stdout
  c = pycurl.Curl()
  login_data = {'pt': token, 'pubkey': pubkey.decode('utf-8').rstrip('\n')}
  loginfields = urllib.parse.urlencode(login_data)
  if log_level == "DEBUG":
    c.setopt(c.VERBOSE, True)
  c.setopt(c.CONNECT_TO, [ct])
  c.setopt(c.URL, 'https://'+cn+":1337/addKey?"+loginfields)
  c.setopt(c.CAINFO, cafile)
  body = json.loads(c.perform_rs())
  if body['status'] == 'OK':
    logging.info("Response OK")
    write_pia_wg_conf(piaJson=body, privKey=privkey.decode('utf-8').rstrip('\n'), dns=dns)
    logging.info("Starting wireguard")
    rc = subprocess.run(['wg-quick', 'up', 'pia']).returncode
    if rc == 0:
      return body
    else:
      raise ValueError("Wireguard exited with returncode: " + str(rc))
  else:
    raise ValueError("Server responded with an error: " + body['message'])

def pia_pf_bind(port: PiaPort) -> Optional[PiaPort]:
  if port.payload.expires_at <= datetime.datetime.now(datetime.timezone.utc):
    logging.info("Port expired... generating new port")
    port = pia_portforward_enable(piaJson=port.piaJson, piaToken=port.piaToken, piaRegion=port.piaRegion)
  logging.info("Binding to port")
  c = pycurl.Curl()
  ip = port.pf_gateway
  cn = port.pf_host
  ct = "%s::%s:" % (cn, ip)
  pf_data = {'payload': port.payload.base64payload, 'signature': port.signature}
  pffields = urllib.parse.urlencode(pf_data)
  if log_level == "DEBUG":
    c.setopt(c.VERBOSE, True)
  c.setopt(c.CONNECT_TO, [ct])
  c.setopt(c.URL, 'https://'+cn+":19999/bindPort?"+pffields)
  c.setopt(c.CAINFO, cafile)
  body = json.loads(c.perform_rs())
  if body['status'] == 'OK':
    logging.info("Port bound")
    return port
  else:
    raise ValueError("Port did not bind successfully: "+body['message'])

def write_pf_port(file: str, port: PiaPort):
  portjson=jsonpickle.encode(port)
  file = open(file, 'w')
  file.write(portjson)
  file.close()

def write_rtorrent_file(file: str, port: PiaPort, systemd: bool = False, systemdservicename: str = None):
  theString = """
network.port_range.set = %s-%s
dht_port = %s
"""% (str(port.payload.port), str(port.payload.port), str(port.payload.port))
  file = open(file, 'w')
  file.write(theString)
  file.close()
  if systemd == True:
    systemd1 = dbus.SystemBus().get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
    manager = dbus.Interface(systemd1,'org.freedesktop.systemd1.Manager')
    job = manager.ReloadOrTryRestartUnit(systemdservicename,'fail')

def update_transmission_port(transmission_username: str, transmission_password: str, port: PiaPort):
  logging.info("Updating transmission port")
  subprocess.run(['transmission-remote', '-n', transmission_username+':'+transmission_password, '--port', str(port.payload.port)])

def connect(args):
  try:
    serverlisturl: str = "https://serverlist.piaservers.net/vpninfo/servers/v6"
    username: Optional[str] = None
    password: Optional[str] = None
    pia_pf: bool = False
    pia_pf_file: Optional[str] = None
    pia_ur: bool = False
    pia_ur_file: Optional[str] = None
    pia_sd = False
    pia_sd_srv = None
    pia_dns: bool = False
    pia_timeout: int = 10
    try:
      if(args.serverlist):
        logging.warning("Overriding default server list from command line, I hope you know what you're doing!")
        serverlisturl = args.serverlist.strip()
      else:
        srv = config.get('connection','serverlist')
        logging.warning("Overriding default server list from config file, I hope you know what you're doing!")
        serverlisturl = srv
    except configparser.NoSectionError:
      pass

    try:
      if(args.portforward):
        pia_pf = True
        pia_pf_file = args.portforward
      else:
        pia_pf = config.get('connection', 'portforward')
        pia_pf_file = config.get('connection', 'portforwardfile')
    except configparser.NoSectionError:
      pass
    
    try:
      if(args.updatertorrent):
        pia_ur = True
        pia_ur_file = args.updatertorrent
      else:
        pia_ur = config.get('connection', 'updatertorrent')
        pia_ur_file = config.get('connection', 'updatertorrentfile')
    except configparser.NoSectionError:
      pass

    try:
      if(args.rtorrentsystemdservice):
        pia_sd = True
        pia_sd_srv = args.rtorrentsystemdservice
      else:
        pia_sd = config.get('programs', 'systemd')
        pia_sd_srv = config.get('programs', 'rtorrentservice')
    except configparser.NoSectionError:
      pass

    try:
      if(args.updatetransmission):
        pia_ut = True
        pia_ut_username = args.updatetransmissionusername
        pia_ut_password = args.updatetransmissionpassword
      else:
        pia_ut = config.get('transmission', 'update')
        pia_ut_username = config.get('transmission', 'username')
        pia_ut_password = config.get('transmission', 'password')
    except configparser.NoSectionError:
      pass

    try:
      if(args.dns):
        pia_dns = args.dns
      else:
        pia_dns = config.get('connection', 'dns')
    except configparser.NoSectionError:
      pass

    try:
      if(args.timeout):
        pia_timeout = args.timeout
      else:
        pia_pf = config.get('connection', 'timeout')
    except configparser.NoSectionError:
      pass

    try:
      if(args.username):
        username = args.username.strip()
      else:
        username = config.get('auth', 'username')
    except configparser.NoSectionError:
      pass
    try:
      if(args.password):
        password = args.password.strip()
      else:
        password = config.get('auth', 'password')
    except configparser.NoSectionError:
      pass
    if(username == None):
      raise ValueError("Username must be specified on the command line, or be in the config file")
    elif(password == None):
      raise ValueError("Password must be specified on the command line, or be in the config file")
    regionJson: str = get_json(serverlisturl)
    piaRegions: PiaRegion = json.loads(regionJson, object_hook=lambda d: pia_json_to_objects(**d))
    bestRegion: Region = get_best_server_region(piaregions=piaRegions, pf=True, timeout=10)
    if bestRegion.latency == float("inf"):
      raise ValueError("No region responded within "+ str(pia_timeout) +"s consider using a higher timeout.")
    logging.info("The best region is: " + bestRegion.name + " (" + bestRegion.id + ") with a latency of: " + str(int(bestRegion.latency*100000)/100) + "ms")
    token: str = generate_token_response(region=bestRegion, username=username, password=password)
    piaJson = pia_connect_wg(region=bestRegion, token=token, dns=pia_dns)
    if pia_pf == True:
        logging.info("Sleeping for 5 seconds to allow everything to come up")
        time.sleep(5)
        logging.info("getting a port from PIA")
        port = pia_portforward_enable(piaJson=piaJson, piaToken=token, piaRegion=bestRegion)
        logging.info("Trying to bind port")
        port = pia_pf_bind(port=port)
        write_pf_port(file=pia_pf_file, port=port)
        if pia_ur == True:
          write_rtorrent_file(file = pia_ur_file, port=port, systemd=pia_sd, systemdservicename=pia_sd_srv)
        if pia_ut == True:
          update_transmission_port(transmission_username=pia_ut_username, transmission_password=pia_ut_password, port=port)
  except:
    logging.error("Error... cleaning up and disconnecting before exiting")
    pia_disconnect_wg()
    raise

def disconnect(args):
  pia_disconnect_wg()
def refresh(args):
  pia_ur: bool = False
  pia_ur_file: Optional[str] = None
  pia_sd = False
  pia_sd_srv = None
  pia_ut: bool = False
  pia_ut_username: Optional[str] = None
  pia_ut_password: Optional[str] = None
  try:
    if(args.rtorrentsystemdservice):
      pia_sd = True
      pia_sd_srv = args.rtorrentsystemdservice
    else:
      pia_sd = config.get('programs', 'systemd')
      pia_sd_srv = config.get('programs', 'rtorrentservice')
  except configparser.NoSectionError:
    pass
  try:
    if(args.updatertorrent):
      pia_ur = True
      pia_ur_file = args.updatertorrent
    else:
      pia_ur = config.get('programs', 'updatertorrent')
      pia_ur = config.get('programs', 'updatertorrentfile')
  except configparser.NoSectionError:
    pass
  try:
    if(args.updatetransmission):
      pia_ut = True
      pia_ut_username = args.updatetransmissionusername
      pia_ut_password = args.updatetransmissionpassword
    else:
      pia_ut = config.get('transmission', 'update')
      pia_ut_username = config.get('transmission', 'username')
      pia_ut_password = config.get('transmission', 'password')
  except configparser.NoSectionError:
    pass
  file = open(args.file)
  port: PiaPort = jsonpickle.decode(file.read())
  orig_port: int = port.payload.port
  file.close()
  logging.info("Trying to bind port")
  port = pia_pf_bind(port=port)
  new_port: int = port.payload.port
  write_pf_port(file=args.file, port=port)
  if pia_ur == True and orig_port != new_port:
    write_rtorrent_file(file = pia_ur_file, port = port, systemd=pia_sd, systemdservicename=pia_sd_srv)
  if pia_ut == True and orig_port != new_port:
    update_transmission_port(transmission_username=pia_ut_username, transmission_password=pia_ut_password, port = port)
#### Begin Main Program
try:
  # Command line args
  parser = argparse.ArgumentParser(description='Setup and use PIA\'s wireguard VPN servers')
  parser.add_argument('--config', '-c', help="Path to configuration file", type=str)
  parser.add_argument('--cafile', '-a', help="Path to a CA bundle", type=str)
  parser.add_argument('--log', '-l', help="Log level (debug, info, warn, error)", type=str)
  parser.set_defaults(func=None)
  subparsers = parser.add_subparsers(title='subcommands',description='valid subcommands')
  parser_connect = subparsers.add_parser('connect', help='Connect to the most optimal PIA server')
  parser_connect.add_argument('--username', '-u', help="Your PIA username", type=str)
  parser_connect.add_argument('--password', '-p', help="Your PIA password", type=str)
  parser_connect.add_argument('--dns', '-d', help="update DNS using either resolvconf", action='store_true')
  parser_connect.add_argument('--portforward', '-f', help="Ask for a port to be forwarded to the local machine, saves the port object as JSON in PORTFORWARD", type=str)
  parser_connect.add_argument('--updatertorrent', '-r', help="Update an rtorrent drop in file with the port that's been forwarded", type=str)
  parser_connect.add_argument('--rtorrentsystemdservice', '-x', help="The systemd service to restart, if running", type=str)
  parser_connect.add_argument('--updatetransmission', '-a', help="update transmission to use the forwarded port", action='store_true')
  parser_connect.add_argument('--transmissionusername', '-n', help="The transmission RPC username", type=str)
  parser_connect.add_argument('--transmissionpassword', '-l', help="The transmission RPC password", type=str)
  parser_connect.add_argument('--timeout', '-t', help="Timeout when testing for best server (defaults to 10s)", type=int)
  parser_connect.add_argument('--serverlist', '-s', help="a URL to obtain a server list from in PIA's JSON format (advanced option)", type=str)
  parser_connect.set_defaults(func=connect)
  parser_disconnect = subparsers.add_parser('disconnect', help='Disconnect from the PIA server')
  parser_disconnect.set_defaults(func=disconnect)
  parser_refresh = subparsers.add_parser('refresh', help='Refresh port forwarding')
  parser_refresh.add_argument('file', help="Path to a file containing a PiaPort object in JSON format", type=str)
  parser_refresh.add_argument('--updatertorrent', '-r', help="Update an rtorrent drop in file with the port that's been forwarded", type=str)
  parser_refresh.add_argument('--rtorrentsystemdservice', '-x', help="The systemd service to restart, if running", type=str)
  parser_refresh.add_argument('--updatetransmission', '-a', help="update transmission to use the forwarded port", action='store_true')
  parser_refresh.add_argument('--transmissionusername', '-n', help="The transmission RPC username", type=str)
  parser_refresh.add_argument('--transmissionpassword', '-l', help="The transmission RPC password", type=str)
  parser_refresh.set_defaults(func=refresh)
  args = parser.parse_args()

  if(args.cafile):
    if(os.path.isfile(args.cafile)):
      cafile = args.cafile
    else:
      raise ValueError("Config file does not exist")
  else:
    xdg_data_dirs.reverse()
    for cadir in xdg_data_dirs:
      caf = cadir + '/' + package_name + '/' + 'ca.rsa.4096.crt'
      if(os.path.isfile(caf)):
        cafile = caf
  if cafile == None:
    raise ValueError("Cannot find CA bundle")
  # Config File
  if(args.config):
    if(os.path.isfile(args.config)):
      config.read(args.config)
    else:
      raise ValueError("Config file does not exist")
  else:
    xdg_config_dirs.reverse()
    for configdir in xdg_config_dirs:
      cfgfile = configdir + '/' + package_name + '/' + package_name + '.conf'
      config.read(cfgfile)

  # Set variables
  try:
    if(args.log):
      log_level = args.log.upper().strip()
    else:
      log_level = config.get('logging', 'level')
  except configparser.NoSectionError:
    pass
  
  logging.basicConfig(level=log_level)
  logging.info("Log level set to: " + log_level)
  
  # Call the appropriate function for the subcommand
  if args.func is not None:
    args.func(args)
  else:
    raise ValueError("You need to pass a command!")
except ValueError as e:
  logging.error(e)
  logging.error("Exiting!")
  raise SystemExit(21)
except PermissionError as e:
  logging.error("Permission error - you need to run this script as root!")
  logging.error(e)
  logging.error("Exiting!")
  raise SystemExit(22)
except:
  e = sys.exc_info()[0]
  logging.error("Other error!")
  logging.error(e)
  logging.error("Exiting!")
  raise SystemExit(19)