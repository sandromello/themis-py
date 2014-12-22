from themis.group import Groups
import re, yaml
from themis.utils import is_valid_redis_key, BaseData, Features, ThemisMetaData
from themis.static import POLICY_CUSTOM_CALLBACK, FEATURES_CUSTOM_CALLBACK, \
METADATA_CUSTOM_CALLBACK, DEFAULT_FEATURES_VALUES, RESERVERD_KEYWORDS
from copy import deepcopy

class PolicyError(Exception): pass

class Policy(Groups):
  POLICY_TYPES = ['bypass', 'regular', 'bypass+']
  JAILBY_VALUES = [ 'SASLUsername', 'SenderIP', 'Sender', 'Sender+', 'SenderDomain', 'SenderDomain+' ]
  JAILACTION_VALUES = ['block', 'hold', 'monitor']
  # TODO: Add params policy_name and policy_namespace
  POLICY_PARAMS = ['Source', 'Destination', 'Enable', 'Type', 'Priority', 'JailBy', 'JailSpec', 'JailAction', 'ReplyData', 'OnlyHeaders', 
  'CountRCPT', 'StopHere', 'RequestsMon', 'SubjectProbation', 'CountSentProbation', 'IpProbation', 'BlockProbation', 'ActionHeaders', 'SPF']

  def __init__(self, redis):
    super(Policy, self).__init__(redis)

  def setpolicy(self, pdata):
    try:
      if self.getpolicy(pdata.policy_name):
        raise PolicyError('Policy "%s" already exists' % pdata.policy_name)
    except ValueError, e:
      # Policy does not exists
      pass
    except Exception, e:
      raise PolicyError('Error setting policy %s: %s' % (pdata.policy_name, e))

    pdata.validate_policy_args(self)
    
    # If it's a pool policy should be listed only in list:policies:pool_name
    if pdata.pool_policy:
      list_policy_name = ':'.join(('list', 'policies', pdata.pool_name))
    else:
      list_policy_name = ':'.join(('list', 'policies'))

    with self.redis.pipeline() as pipe:
      pipe.hmset(pdata.policy_namespace, pdata.as_dict, POLICY_CUSTOM_CALLBACK)
      pipe.zadd(list_policy_name, pdata.priority, pdata.policy_namespace)
      pipe.execute()

  def modifypolicy(self, json_data):
    pdata = self.getpolicy(json_data['policy_name'])
    pdata.validate_policy_args(self)
    try:
      for key in json_data:
        pdata.__dict__[key.lower()] = json_data[key]
    except KeyError, k:
      raise PolicyError('Could not find key for record: %s' % k)

    # VALIDATE NEW DATA
    pdata.do_init()
    pdata.validate_policy_args(self)
    self.redis.hmset(pdata.policy_namespace, pdata.as_dict, POLICY_CUSTOM_CALLBACK)

  # TODO: Fix
  def get_requests(self, target, messagesBySecStoreDays, sleep_time=None):
    from datetime import datetime
    from time import sleep

    namespace = 'requestsbysec:%s' % target
    messagesBySecStoreDays = self.redis.hget('config:themis:features:global', 'messagesBySecStoreDays')
    now = datetime.now()
    now_in_seconds = now.hour * 60 * (int(messagesBySecStoreDays) * 60) + now.second

    if not sleep_time:
      response = self.redis.hget(namespace, 'second:%s' % now_in_seconds)
      if not response:
        raise ValueError('Could not find any request: second:%s' % now_in_seconds)
      return response
    else:
      while True:
        now = datetime.now()
        now_in_seconds = now.hour * 60 * (int(messagesBySecStoreDays) * 60) + now.second
        print self.redis.hget(namespace, 'second:%s' % now_in_seconds)
        sleep(sleep_time)

  def config_features(self, namespace, config_file):
    if namespace in RESERVERD_KEYWORDS:
      raise ValueError('Reserved word found: %s. Use another name' % ', '.join(RESERVERD_KEYWORDS))

    if not config_file:
      global_config = DEFAULT_FEATURES_VALUES
    else:
      with open(config_file) as f:
        _, global_config, _ = yaml.load_all(f)
    feats = Features(**global_config)
    # sanity check for key items in config file
    feats.strict_check()
    self.redis.hmset('config:themis:features:%s' % namespace, feats.as_dict, FEATURES_CUSTOM_CALLBACK)

  def edit_features(self, namespace, feature, value):
    try:
      feat = Features(**self.redis.hgetall('config:themis:features:%s' % namespace))
      feat.strict_check()
    except Exception, e:
      raise ValueError('Strict check error, inconsistent features. ERROR: %s' % e)
    self.redis.hset('config:themis:features:%s' % namespace, feature, value, feat_mapping=True)

  def del_features(self, namespace):
    self.redis.delete('config:themis:features:%s' % namespace)

  def get_features(self, namespace):
    if namespace == 'list':
      callback = {}
      [callback.update({key : str(value)}) for key, value in FEATURES_CUSTOM_CALLBACK.items()]
      return callback
    return self.redis.hgetall('config:themis:features:%s' % namespace)

  def get_metadata(self, target):
    if target == 'list':
      callback = {}
      [callback.update({key : str(value)}) for key, value in METADATA_CUSTOM_CALLBACK.items()]
      return callback
    return self.redis.hgetall(target)

  def edit_metadata(self, target, key, value):
    try:
      tmetadata = ThemisMetaData(**self.redis.hgetall(target))
      tmetadata.strict_check()
    except Exception, e:
      raise ValueError('Strict check error, inconsistent metadata key. ERROR: %s' % e)
    # If get here it is safe to edit
    self.redis.hset(target, key, value, feat_mapping=True)

  def search_keys(self, target_lookup):
    return self.scan(target_lookup) or []

  def lookup_delete(self, target_lookup, debug=False):
    if re.match(r'^policy.*|^list.*|^group.*|^config.*|^pool.*', target_lookup):
      raise ValueError('Cannot delete keys with the starting names: list, group, config and pool.')
    scan_result = self.scan(target_lookup)
    if not scan_result:
      raise ValueError('Could not find any keys to delete')
    total = len(scan_result)
    for key in scan_result:
      if debug:
        print 'Deleting key:', key
      self.redis.delete(key)
    return 'SUCCESS - Deleted %s key(s)' % total

  def add_default_metadata(self, target, config_file):
    if target in RESERVERD_KEYWORDS:
      raise ValueError('Reserved word found: %s. Use another name' % ', '.join(RESERVERD_KEYWORDS))

    tmetadata = ThemisMetaData(**ThemisMetaData.METADATA_DEFAULT_VALUES)
    if not config_file:
      global_config = DEFAULT_FEATURES_VALUES
    else:
      with open(config_file) as f:
        _, global_config, _ = yaml.load_all(f)
    tmetadata.update_features(**global_config)
    self.redis.hmset(target, tmetadata.as_dict, dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items()))

  def add_actionheaders(self, policy_name, sourcehdr, regexp, actionheaders):
    """
    :param sourcehdr: A string with the lookup header
    :param regexp: A string with the regexp that will be applied to the sourcehdr if exists
    :param action: A tuple of new headers to add in case of a match
    """
    pdata = self.getpolicy(policy_name)
    try:
      # Check if this header is already set
      pdata.actionheaders[sourcehdr]
      raise ValueError('Source header already exists: %s' % sourcehdr)
    except KeyError:
      pdata.actionheaders[sourcehdr] = [regexp] + actionheaders
      pdata._check_action_headers()
      self.redis.hmset(pdata.policy_namespace, pdata.as_dict, POLICY_CUSTOM_CALLBACK)

  def modify_actionheaders(self, policy_name, sourcehdr, regexp, actionheaders):
    """
    :param sourcehdr: A string with the lookup header
    :param regexp: A string with the regexp that will be applied to the sourcehdr if exists
    :param action: A tuple of new headers to add in case of a match
    """
    pdata = self.getpolicy(policy_name)
    try:
      # Check if this header is already set
      pdata.actionheaders[sourcehdr]

      pdata.actionheaders[sourcehdr] = [regexp] + actionheaders
      pdata._check_action_headers()
      self.redis.hmset(pdata.policy_namespace, pdata.as_dict, POLICY_CUSTOM_CALLBACK)
    except KeyError:
      raise ValueError('Source Header %s does not exists. Cannot modify a header that does not exists' % sourcehdr)

  def del_actionheaders(self, policy_name, sourcehdr, clear=False):
    pdata = self.getpolicy(policy_name)
    if clear:
      pdata.actionheaders = {}
    else:
      if sourcehdr not in pdata.actionheaders:
        raise ValueError('Could not find source header %s' % sourcehdr)
      del pdata.actionheaders[sourcehdr]
    self.redis.hmset(pdata.policy_namespace, pdata.as_dict, POLICY_CUSTOM_CALLBACK)
      
  def addpool(self, pool_name, servers):
    is_valid_redis_key(pool_name)
    if pool_name in RESERVERD_KEYWORDS:
      raise ValueError('Reserved word found: %s. Use another name' % ', '.join(RESERVERD_KEYWORDS))
    try:
      self.getpool(pool_name)
      raise ValueError('Pool "%s" already exists' % pool_name)
    except Exception:
      pass

    for server in servers:
      # http://stackoverflow.com/questions/11809631/fully-qualified-domain-name-validation?answertab=votes#tab-top
      if not re.match(r'(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', server):
        raise ValueError('Is not a qualified server: %s' % server)
    pool_namespace = ':'.join(('pool', pool_name))
    with self.redis.pipeline() as pipe:
      pipe.sadd(pool_namespace, *servers)
      pipe.sadd('list:pools', pool_namespace)
      pipe.execute()

  def getpool(self, pool_name):
    pool_namespace = ':'.join(('pool', pool_name))
    pool = list(self.redis.smembers(pool_namespace))
    if not pool:
      raise ValueError('Pool "%s" does not exists' % pool_name)
    return { pool_name :  pool }

  def editpool(self, pool_name, servers):
    is_valid_redis_key(pool_name)
    self.getpool(pool_name)
    for server in servers:
      # http://stackoverflow.com/questions/11809631/fully-qualified-domain-name-validation?answertab=votes#tab-top
      if not re.match(r'(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', server):
        raise ValueError('Is not a qualified server: %s' % server)

    pool_namespace = ':'.join(('pool', pool_name))
    with self.redis.pipeline() as pipe:
      pipe.sadd(pool_namespace, *servers)
      pipe.sadd('list:pools', pool_namespace)
      pipe.execute()

  def list_pools(self):
    pools = {}
    for pool_name in self.scan('pool:*'):
      pools[pool_name] = list(self.redis.smembers(pool_name))
    if not pools:
      raise ValueError('Could not find any pools')
    return pools

  def remove_pool(self, pool_name):
    is_valid_redis_key(pool_name)
    pool_namespace = ':'.join(('pool', pool_name))
    with self.redis.pipeline() as pipe:
      pipe.delete(pool_namespace)
      pipe.srem('list:pools', pool_namespace)
      del_result, _ = pipe.execute()
    if not del_result:
      raise ValueError('Could not find pool name %s' % pool_name)

  def remove_server_from_pool(self, pool_name, servers):
    is_valid_redis_key(pool_name)
    pool_namespace = ':'.join(('pool', pool_name))
    if type(servers) is not list:
      raise TypeError('Wrong type of parameters, expect list, found: %s' % type(servers))
    if len(servers) >= len(self.redis.smembers(pool_namespace)):
      raise IndexError('You MUST NOT remove all the servers, remove the pool instead')
    result = self.redis.srem(pool_namespace, *servers)
    if not result:
      raise ValueError('Could not find any servers to delete: %s' % servers)
    return result

  def get_all_policies(self):
    """ 
    Get all policies searching by string that starts with 'policy:'
    return a list of policies
    """
    policies = {}
    for policy_name in self.scan('policy:*'):
      pdata = PolicyData(**self.redis.hgetall(policy_name, POLICY_CUSTOM_CALLBACK))
      policies[pdata.policy_name] = pdata
    if not policies:
      raise ValueError('Could not find any policy, using base search "policy:*"')
    return policies
    #return self.redis.zrange('list:policies', 0, -1)

  def delete(self, policy_name):
    """ Delete a single policy 
    :param policy_name: The name of the policy
    """
    pdata = self.getpolicy(policy_name)
    with self.redis.pipeline() as pipe:
      pipe.delete(pdata.policy_namespace)
      if pdata.pool_policy:
        pipe.zrem('list:policies:%s' % pdata.pool_name, pdata.policy_namespace)
      else:
        pipe.zrem('list:policies', pdata.policy_namespace)
      del_result, _ = pipe.execute()
    if not del_result:
      raise ValueError('Could not find policy by the name: ' + policy_name)

  def get_all_data_policies(self, mta_hostname=None):
    """ Get all enabled policies
    Returns a list of PolicyData objects
    """
    search_pattern = 'list:policies'
    if mta_hostname:
      # ['pool:pool_name01', 'pool:pool_name02', ...]
      pools = list(self.redis.smembers('list:pools'))
      ismember = []
      with self.redis.pipeline() as pipe:
        for pool in pools:
          pipe.sismember(pool, mta_hostname)
        # [True, False, ...]
        ismember = pipe.execute()

      pool = [pool for m, pool in zip(ismember, pools) if m]
      if pool:
        # Expect pool:pool_name from 'pool'
        pool = pool[0].split(':')[1]
        search_pattern = 'list:policies:%s' % pool

    policies = []
    try:
      for policy_name in self.redis.zrange(search_pattern, 0, -1):
        #policy_data = self.redis.hgetall(policy_name)
        pdata = PolicyData(**self.redis.hgetall(policy_name, POLICY_CUSTOM_CALLBACK))
        if not pdata.enable:
          continue

        policies.append(pdata)
        # validate if group exists
        self.getgroup(pdata.source)
        self.getgroup(pdata.destination)
    except Exception, e:
      raise PolicyError('Error parsing policies, check database consistency: %s' % e)

    return policies

  def getpolicy(self, policy_name):
    policy_namespace = ':'.join(('policy', policy_name))
    data = self.redis.hgetall(policy_namespace, POLICY_CUSTOM_CALLBACK)
    if not data:
      raise ValueError('Cant find any policy for name: %s' % policy_name)
    try:
      pdata = PolicyData(**data)
    except Exception, e:
      raise PolicyError('Inconsistency policy data, check stored data. %s' % e)
    return pdata

class PolicyData(BaseData):
  def __init__(self, **entries):
    # convert keys to lower
    entries = dict((k.lower(), v) for k,v in entries.iteritems())
    self.__dict__.update(entries)
    self.do_init()

  # Override
  @property
  def as_dict(self):
    if 'inverted_source' in self.__dict__ and self.inverted_source:
      self.source = '!' + self.source
    if 'inverted_destination' in self.__dict__ and self.inverted_destination:
      self.destination = '!' + self.destination

    return super(PolicyData, self).as_dict

  def do_init(self):
    is_valid_redis_key(self.policy_name)
    if self.policy_name in RESERVERD_KEYWORDS:
      raise ValueError('Reserved word found: %s. Use another name' % ', '.join(RESERVERD_KEYWORDS))
    self.policy_namespace = ':'.join(('policy', self.policy_name))
    self.pool_policy = False
    if ':' in self.policy_name:
      self.pool_policy = True
      split_policy = self.policy_name.split(':')
      if len(split_policy) > 2:
        raise ValueError('Accept only one colon for policy name')
      self.pool_name, _ = split_policy

    self._validate()
    self._check_jailspec()
    self._check_inverted()
    self._check_action_headers()

    self.is_destination_any = 'any' in self.destination
    self.is_source_any = 'any' in self.source

  def _validate(self):
    for entry in self.as_dict.keys():
      if not entry in [param.lower() for param in Policy.POLICY_PARAMS + ['policy_name']]:
        raise NameError('Wrong key found: %s' % entry)

  def _check_jailspec(self):
    for spec in self.jailspec:
      if type(spec) is not tuple:
        raise ValueError('JailSpec in wrong format. Should be requests:time. E.g.: 1:1000')

  def _check_inverted(self):
    self.inverted_source = '!' in self.source
    self.inverted_destination = '!' in self.destination
    try:
      # Extract only numbers, characters and underscore.
      self.source = re.search(r'[\w]+', self.source).group()
      self.destination = re.search(r'[\w]+', self.destination).group()
    except Exception, e:
      raise ValueError('Error extracting data from source or destination: %s' % e)

  def _check_action_headers(self):
    if self.actionheaders:
      # Expected: {'X-HDR01' : ['REGEX', ('X-NEW-HDR', 'X-VAL'), ('X-NEW-HDR', 'X-VAL'), ...], 'X-HDR02' : [...]}
      actionheaders = deepcopy(self.actionheaders)
      try:
        for hdr, hdrlist in actionheaders.items():
          # regexp value
          hdrlist.pop(0)
          for hdrtuple in hdrlist:
            if type(hdrtuple) is not tuple:
              raise ValueError('Expected tuple')
      except Exception, e:
        raise ValueError('ActionHeaders in wrong format. Should be ... %s' % e)

  def validate_policy_args(self, grp):
    for key, value in self.__dict__.items():
      if key in ['source', 'destination']:
        # Ignore any start symbols !#@...
        value = re.search(r'[\w.]+$', value)
        if not value:
          raise ValueError('Could not find pattern: %s' % value)
        if not 'any' == value.group():
          grp.getgroup(value.group())
      elif key in ['countrcpt', 'stophere', 'requestsmon', 'enable', 'spf']:
        if value not in ['TRUE', 'FALSE', True, False]:
          raise ValueError('Enable, StopHere, RequestsMon and CountRCPT only accepts TRUE or FALSE')
      elif key == 'type':
        if value not in Policy.POLICY_TYPES:
          raise TypeError('Invalid argument, Type must be: ' + ' '.join(Policy.POLICY_TYPES))
      elif key == 'jailby':
        if value not in [param for param in Policy.JAILBY_VALUES]:
          raise TypeError('Invalid argument, JailBy must be: ' + ' '.join(Policy.JAILBY_VALUES))
      elif key == 'jailaction':
        if value not in Policy.JAILACTION_VALUES:
          raise TypeError('Invalid argument, JailAction must be: ' + ' '.join(Policy.JAILACTION_VALUES))
      elif key == 'replydata':
        if len(value) > 60 or type(value) is not str:
          raise ValueError('ReplyData accepts string type with 60 characters only.')
        elif len(re.findall('%s', value)) > 1:
          raise ValueError('Too many format strings detected, accepts only one')