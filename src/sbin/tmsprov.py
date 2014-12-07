#!/usr/bin/env python
import getopt, sys, os
import json, yaml, logging.config
from traceback import format_exc
from themis import *

"""
./tmsprov.py -c --init configure

./tmsprov.py -a --policy mypolicy JailBy SASLUsername JailSpec 1:1000
./tmsprov.py -a --policy mypolicy2 JailBy SASLUsername JailSpec 1:1000

-a --policy default JailBy Sender+ JailSpec 1:1000

./tmsprov.py -d --policy mypolicy mypolicy2W
./tmsprov.py -d --policy mypolicy

./tmsprov.py -g --policy mypolicy mypolicy2
./tmsprov.py -g --policy mypolicy
./tmsprov.py -g --policy all

./tmsprov.py -a --group default '@domina.com @inova.net 192.168.6.0/24 @cloudmark.com'
./tmsprov.py -d --group default

./tmsprov.py -m --group default '@cloud.com sandro@'
./tmsprov.py -m --group default 'sandro@' --remove
./tmsprov.py -g --group default
./tmsprov.py -g --group all

./tmsprov.py -a --pool inbound 'mtain-01.domain.tld mtain-02.domain.tld mtain-03.domain.tld'
./tmsprov.py -a --pool outbound 'mtaout-01.domain.tld mtaout-02.domain.tld mtaout-03.domain.tld'
./tmsprov.py -a --policy outbound:default Source any Destination any JailSpec 1:1000
./tmsprov.py -a --policy inbound:default Source any Destination any JailSpec 1:1000

./tmsprov.py -d --pool inbound
./tmsprov.py -m --pool inbound 'mtain-04.domain.tld mtain-05.domain.tld'
./tmsprov.py -m --pool inbound 'mtain-01.domain.tld mtain-02.domain.tld' --remove

./tmsprov.py -g --pool all
./tmsprov.py -g --pool inbound outboud

./tmsprov.py -a --features global
./tmsprov.py -a --features bypool:custom
./tmsprov.py -m --features global global_conditions '[[5,10], [25,100]]'
./tmsprov.py -m --features global learnFeature TRUE
./tmsprov.py -m --features global global_ttl 10000

./tmsprov.py -g --features global
./tmsprov.py -g --features bypool:custom

./tmsprov.py -d --pool global
./tmsprov.py -d --pool bypool:custom

./tmsprov.py -d --flushdb
./tmsprov.py -f --flushdb

./tmsprov.py -a --resync

#python -m themis.tms -m --actionheaders default X-CMAE-Score '(9[6-8]|100).*' X-Spam-Flag YES X-New-Flag YES
#python -m themis.tms -d --actionheaders --clear
#python -m themis.tms -d --actionheaders default --clear
#python -m themis.tms -a --actionheaders default X-CMAE-Score '(9[6-9]|100).*' X-Spam-Flag YES

"""

# TODO: get operations should accept only one key too, E.G.: tmsprov -g --metadata metadata:lab01.domain.tld manual_block
# TODO: lock destination any with bypass
# TODO: Implement config/file/server options
# TODO: Test with several options
# TODO: Replace must treat bypass policies, remove all undesired fields
# TODO: Search filters, look enabled policies or only bypass policies

# TODO: MOVE TO PACKAGE or Policy class: from themis import REQUIRED_POLICY_PARAMS, DEFAULT_POLICY_PARAMS
REQUIRED_POLICY_PARAMS = ['Source', 'Destination']

class Prov(Policy):
  def __init__(self, rds, logger):
    super(Prov, self).__init__(rds)
    self.data = None
    self.prettify = True
    self.logger = logger

  def add_policy(self, dict_data):
    # Configure default values
    if not len(REQUIRED_POLICY_PARAMS) == len(set(REQUIRED_POLICY_PARAMS) & set(dict_data)):
      raise ValueError('Missing required values %s' % ', '.join(REQUIRED_POLICY_PARAMS))
    for default_key, value in DEFAULT_POLICY_PARAMS.items():
      if default_key not in dict_data:
        dict_data[default_key] = value

    jailspec = []  
    try:
      for spec in dict_data['JailSpec'].split(';'):
        if not spec:
          continue
        jailspec.append(tuple(spec.split(':')))
      dict_data['JailSpec'] = jailspec
    except Exception, e:
      raise ValueError('JailSpec in wrong format: %s' %e)

    dict_data['JailSpec'] = jailspec

    self._convert_strings_to_bool(dict_data)
    self.setpolicy(PolicyData(**dict_data))
    self.logger.info('New policy inserted: %s' % dict_data)
    return 'SUCCESS'

  def modify_policy(self, dict_data):
    self._convert_strings_to_bool(dict_data)
    self.modifypolicy(dict_data)
    self.logger.info('Modified policy: %s' % dict_data)
    return 'SUCCESS'

  def delete_policy(self, policy_name):
    self.delete(policy_name)
    self.logger.info('Policy deleted: %s' % policy_name)
    return 'SUCCESS'

  def get_policy(self, params):
    policies = {}
    if params[0] == 'all':
      policies = self.get_all_policies()
      for policy_name in policies:
        pdata = policies[policy_name]
        policies[pdata.policy_name] = pdata.as_dict
    else:
      for policy_name in params:
        pdata = self.getpolicy(policy_name)
        policies[policy_name] = pdata.as_dict
    self.data = policies
    return self.json

  def add_group(self, group_name, group_members):
    group_members = group_members[0].split()
    self.setgroup(group_name, group_members)
    self.logger.info('New group added. Name: %s Members: %s' % (group_name, ', '.join(group_members)))
    return 'SUCCESS'

  def modify_group(self, group_name, group_members, add=True):
    if add:
      self.editgroup(group_name, group_members)
      self.logger.info('Group member added. Name: %s Members: %s' %(group_name, ', '.join(group_members)))
    else:
      self.delgroup_member(group_name, group_members)
      self.logger.info('Group member deleted. Name: %s Members: %s' %(group_name, ', '.join(group_members)))
    return 'SUCCESS'

  def delete_group(self, group_names):
    deleted = []
    for group_name in group_names:
      try:
        self.delgroup(group_name)
      except GroupError:
        continue
      deleted.append(group_name)
    self.logger.info('Group(s) deleted. Name(s): %s' % (', '.join(group_name)))
    return 'SUCCESS - Group(s) deleted:', ', '.join(deleted)

  def get_group(self, params):
    if params[0] == 'all':
      groups = self.get_all_group_members()
    else:
      groups = {}
      for group_name in params:
        groups[group_name] = self.getgroup(group_name)
    self.data = groups
    return self.json

  def listpools(self):
    self.data = self.list_pools()
    return self.json

  def get_pool(self, params):
    pool = {}
    for pool_name in params:
      currentpool = self.getpool(pool_name)
      pool[pool_name] = currentpool[pool_name]
    self.data = pool
    return self.json

  # Override
  def get_features(self, namespace):
    self.data = super(Prov, self).get_features(namespace)
    if not self.data:
      return 'Could not find any features. Namespace: %s' % namespace
    return self.json

  def get_metadata(self, namespace, target):
    self.data = super(Prov, self).get_metadata(namespace, target)
    if not self.data:
      return 'Could not find any metadata account. Namespace: %s' % ':'.join((namespace, target))
    return self.json

  def _convert_strings_to_bool(self, dict_data):
    for key, value in dict_data.items():
      if value in ['TRUE', 'FALSE']:
        dict_data[key] = 'TRUE' == value or False

  @property
  def json(self):
    if self.prettify:
      return json.dumps(self.data, indent=2)
    else:
      return json.dumps(self.data)

def usage(error=None):
  print """Cli interface for configuring themis
tmsprov {args} {params} {param-name} [attr value [...]] [opts]
  
  -h/--help        display usage 
  -a               add operations
  -d               delete operations
  -m               modify operations
  -g               get operations
  --server         redis-server to connect to
  --config         config file alternative. Default: /etc/themis/themis.cfg
  --file           use file as input stream
  --json           json format without indentation

  --policy {policy_name} [attr1 value attr2 value ...]           change policy params
  --group  {group_name} [value value ...]                        change group members
  --headers {policy_name}

  Examples: 
    $ tmsprov -a --policy mypolicy Source default Destination default JailBy SASLUsername JailSpec 1d:1000
    $ tmsprov -a --group mygroup '@domain.com account@ @mydomain.net 192.168.6.0/24'
    $ tmsprov -g --group mygroup --json
"""
  if not error:
    sys.exit(0)
  print 'ERROR -', error
  sys.exit(2)

def list_to_dict(lst, n=2, err=None):
  """group([0,3,4,10,2,3], 2) => [(0,3), (4,10), (2,3)]
  
  Group a list into consecutive n-tuples. Incomplete tuples are
  discarded e.g.
  
  >>> group(range(10), 3)
  [(0, 1, 2), (3, 4, 5), (6, 7, 8)]
  """
  if not len(lst) % 2 == 0:
    if not err:
      raise ValueError('Wrong parameters detected, expect: %s' % ', '.join(Policy.POLICY_PARAMS))
    else:
      raise ValueError('Wrong parameters detected, expect: %s' % err)
  return dict(zip(*[lst[i::n] for i in range(n)]))

if __name__ == '__main__':
  # TODO: Remove this - testing
  os.environ['THEMIS_CFG'] = 'config/config.yaml'
  # Initial config
  config_file = os.getenv('THEMIS_CFG')
  if not config_file:
    config_file = '/etc/themis/config.yaml'
  
  if not os.path.isfile(config_file):
    print 'Could nof find config file: %s' % config_file
    sys.exit(2)
  try:
    with open(config_file) as f:
      config, global_config, logger_config = yaml.load_all(f)
    feat = Features(**global_config)


    rds = MarshalRedis(config['redis_server'], password=config['redis_password'])

    logging.config.dictConfig(logger_config['logger'])
    logger = logging.getLogger('TMS')
  except Exception, e:
    print 'Config Problem: %s' % e
    sys.exit(2)

  response, debug, exErr = ['SUCCESS', False, '']
  try:
    opts, args = getopt.getopt(sys.argv[1:], 'a:d:m:s:f:g:h', ['help', 'file', 'resync', 'flushdb', 'policy', 'group', 'pool', 
      'actionheaders', 'features', 'metadata', 'requests', 'debug'])
    if not opts:
      usage()
    action = None
    for o, a in opts:
      #print o, a, args
      if o == '-a':
        action = 'add'
      elif o == '-m':
        action = 'modify'
      elif o == '-g':
        action = 'get'
      elif o == '-d':
        action = 'delete'
      elif o == '-h' or o == '--help':
        usage()

      if '--debug' in args:
        args.remove('--debug')
        debug = True

      prov = Prov(rds, logger)
      if a == '--resync' and o == '-a':
        prov.redis.hset('config:themis:resync', 'config_file', config_file)
        logger.info('Resync ON')
        print response, '- Resync set'
        sys.exit(0)
      elif a == '--flushdb' and o == '-f':
        prov.redis.flushdb()
        logger.info('redis database flushed')
        print response, '- flush executed successfuly'
        sys.exit(0)
      elif a == '--flushdb' and action == 'delete':
        question = raw_input('Are you sure you want to drop all data from redis? Press [Y/N]\n')
        if question == 'Y':
          prov.redis.flushdb()
          logger.info('redis database flushed')
          print response, '- flush executed successfuly'
        sys.exit(0)

      if not args:
        usage()

      if '--json' in args:
        args.remove('--json')
        prov.prettify = False

      if 'any' in args and action in ['modify', 'delete']:
        raise ValueError('Could not change system group "any"')

      target_object_name = args[0]
      args.remove(target_object_name)
      

      if a == '--policy':
        if action in ['add', 'modify']:
          # Check for policy name and prevent wrong parameters
          if target_object_name in prov.POLICY_PARAMS:
            print 'Missing policy name'
            sys.exit(2)

          if action == 'modify':
            args = list_to_dict(args)
            args['policy_name'] = target_object_name
            print prov.modify_policy(args)
            sys.exit(0)

          # Check for required keys
          for reqkey in REQUIRED_POLICY_PARAMS:
            if reqkey not in args:
              print 'Required key not found:', reqkey, 'Required Keys:', ', '.join(REQUIRED_POLICY_PARAMS)
              sys.exit(2)

          args = list_to_dict(args)
          args['policy_name'] = target_object_name
          print prov.add_policy(args)
        elif action == 'get':
          args.append(target_object_name)
          print prov.get_policy(args)

        elif action == 'delete':
          print prov.delete_policy(target_object_name)
        else:
          usage
        sys.exit(0)

      elif a == '--group':
        if action == 'add':
          prov.add_group(target_object_name, args)
          print response
        elif action == 'get':
          args.append(target_object_name)
          print prov.get_group(args)
        elif action == 'modify':
          add = True
          if '--remove' in args:
            args.remove('--remove')
            add = False
          print prov.modify_group(target_object_name, args, add=add)
        elif action == 'delete':
          args.append(target_object_name)
          print prov.delete_group(args)
        else:
          usage()
      elif a == '--pool':
        if action == 'add':
          args = args[0].split()
          prov.addpool(target_object_name, args)
          logger.info('Add pool successfuly: %s, server(s): %s' % (target_object_name, ', '.join(args)))
        elif action == 'modify':
          if '--remove' in args:
            args.remove('--remove')
            args = args[0].split()
            output = prov.remove_server_from_pool(target_object_name, args)
            logger.info('Server(s) %s removed from pool %s successfuly' % (', '.join(args), target_object_name))
            response += ' - %s server(s) removed' % output
          else:
            args = args[0].split()
            prov.editpool(target_object_name, args)
            logger.info('Server(s) %s added successfuly into pool %s' % (', '.join(args), target_object_name))
        elif action == 'delete':
          prov.remove_pool(target_object_name)
          logger.info('Pool removed successfuly: %s' % target_object_name)
        elif action == 'get':
          if target_object_name == 'all':
            response = prov.listpools()
          else:
            args.append(target_object_name)
            response = prov.get_pool(args)
        else:
          usage()
        print response
        sys.exit(0)
      elif a == '--actionheaders':
        if action in ['add', 'modify']:
          sourcehdr, rgxp = args[:2]
          actionheaders = list_to_dict(args[2:], err='policy_name, regexp, new_header01, new_value, new_header02, new_value, ...').items()
        if action == 'add':
          prov.add_actionheaders(target_object_name, sourcehdr, rgxp, actionheaders)
        elif action == 'modify':
          prov.modify_actionheaders(target_object_name, sourcehdr, rgxp, actionheaders)
        elif action == 'delete':
          sourcehdr = args[0]
          if sourcehdr == '--clear':
            prov.del_actionheaders(target_object_name, None, clear=True)
          else:
            prov.del_actionheaders(target_object_name, sourcehdr)
        else:
          usage()
        print response
      elif a == '--features':
        if action == 'get':
          response = prov.get_features(target_object_name)
        elif action == 'add':
          prov.config_features(target_object_name, config_file)
        elif action == 'modify':
          feature, value = args
          prov.edit_features(target_object_name, feature, value)
        elif action == 'delete':
          prov.del_features(target_object_name)
        print response
      elif a == '--metadata':
        if action == 'get':
          # TODO: it will use scan to bring all the keys
          response = prov.get_metadata(feat.global_namespace, target_object_name)
        elif action == 'add':
          prov.add_default_metadata(feat.global_namespace, target_object_name, config_file)
        elif action == 'modify':
          metadata_key, metadata_value = args
          prov.edit_metadata(feat.global_namespace, target_object_name, metadata_key, metadata_value)
        elif action == 'delete':
          # TODO: it will use scan to delete by wildcard
          prov.del_metadata(feat.global_namespace, target_object_name)
        print response
      else:
        usage()

  except getopt.GetoptError, e:
    usage(e)
  except TypeError, e:
    exErr = e
  except ValueError, e:
    exErr = e
  except Exception, e:
    exErr = e
  finally:
    if exErr:
      print exErr
      if debug:
        print format_exc()
      sys.exit(2)