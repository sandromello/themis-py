import hashlib, os, re, time
from netaddr import IPNetwork
from datetime import datetime, timedelta
from themis.static import FEATURES_CUSTOM_CALLBACK, METADATA_CUSTOM_CALLBACK
from copy import deepcopy

class BaseData(object):
  IGNORE_POLICY_KEYS = ['inverted_source', 'inverted_destination', 'is_source_any', 'is_destination_any', 
  'pool_policy', 'pool_name', 'policy_namespace', 'jailspec_data']
  IGNORE_FEATURES_KEYS = [ 'ipReputationFeatureNamespace', 'ipReputationFeatureGroupByNamespace', 
  'countSentMessagesFeatureGroupByNamespace', 'subjectReputationFeatureGroupByNamespace', 'tmetadata' ]
  IGNORE_METADATA_KEYS = [ 'namespace' ]

  @property
  def as_dict(self):
    local_dict = deepcopy(self.__dict__)
    [local_dict.pop(key, None) for key in self.IGNORE_FEATURES_KEYS + self.IGNORE_POLICY_KEYS + self.IGNORE_METADATA_KEYS]
    return local_dict

class Features(BaseData):
  def __init__(self, **entries):
    self.__dict__.update(entries)
    #self.global_config = self.__dict__
    self._validate()
    self.tmetadata = None

  def _validate(self):
    features_keys = FEATURES_CUSTOM_CALLBACK.keys()
    for entry in self.as_dict.keys():
      if not entry in features_keys:
        raise NameError('Wrong key found: %s' % entry)
    self.strict_check()

  def strict_check(self):
    [self.__dict__.update({key : type_info(self.__dict__[key])}) for key, type_info in FEATURES_CUSTOM_CALLBACK.items()]

  def build_namespaces(self, milter_object):
    self.ipReputationFeatureNamespace = ':'.join((self.global_namespace, 'ipReputationFeature', milter_object))
    self.ipReputationFeatureGroupByNamespace = ':'.join((self.global_namespace, 'ipReputationFeature:groupby'))
    self.countSentMessagesFeatureGroupByNamespace = ':'.join((self.global_namespace, 'countSentMessagesFeature:groupby'))
    self.subjectReputationFeatureGroupByNamespace = ':'.join((self.global_namespace, 'subjectReputationFeature:groupby'))

  def get_time(self):
    now_in_timestamp = time.time()
    now_date_obj = datetime.fromtimestamp(float(now_in_timestamp))
    return now_in_timestamp, now_date_obj

  def call_feeders(self, redis, pdata, milter_object, milter_from_ipaddress, milter_subject):
    if not self.feederFeaturesEnabled:
      return
    
    if not self.tmetadata:
      raise ValueError('tmetadata attribute is empty, expected ThemisMetaData object')

    self.tmetadata.build_namespace(milter_object)
    self.build_namespaces(milter_object)

    now_in_timestamp, now_date_obj = self.get_time()
    
    count_sent_feature_reset, ip_reputation_feature_reset, subject_feature_match = [False, False, False]
    ### ipReputationFeature feeder
    if self.tmetadata.ip_reputation_lastupdate:
      past_salt = datetime.fromtimestamp(self.tmetadata.ip_reputation_lastupdate) + timedelta(hours=pdata.ipprobation)
      if not past_salt > now_date_obj:
        ip_reputation_feature_reset = True

    # subjectReputationFeature feeder
    if self.tmetadata.last_subject == milter_subject and self.tmetadata.subject_lastupdate:
      subject_feature_match = True
      past_salt = datetime.fromtimestamp(float(self.tmetadata.subject_lastupdate)) + timedelta(hours=pdata.subjectprobation)
      if not past_salt > now_date_obj:
        subject_feature_match = 'first_subject_count'

    # countSentMessagesFeature
    if self.tmetadata.sentmessages_lastupdate:
      past_salt = datetime.fromtimestamp(self.tmetadata.sentmessages_lastupdate) + timedelta(hours=pdata.countsentprobation)
      if not past_salt > now_date_obj:
        count_sent_feature_reset = True
    
    # Update all keys with current timestamp
    self.tmetadata.__dict__.update(dict.fromkeys(['ip_reputation_lastupdate', 'subject_lastupdate', 'sentmessages_lastupdate'], now_in_timestamp))
    self.tmetadata.last_subject = milter_subject
    
    # update features
    with redis.pipeline() as pipe:
      # Ip Reputation Feature
      if ip_reputation_feature_reset:
        pipe.delete(self.ipReputationFeatureNamespace)
        pipe.zrem(self.ipReputationFeatureGroupByNamespace, milter_object)
      # Count Sent Feature
      elif count_sent_feature_reset:
        pipe.zrem(self.countSentMessagesFeatureGroupByNamespace, milter_object)
      # Subect Feature
      elif subject_feature_match == 'first_subject_count':
        pipe.zrem(self.subjectReputationFeatureGroupByNamespace, milter_object)
        self.tmetadata.subject_repeated_count = 1
      elif subject_feature_match:
        self.tmetadata.subject_repeated_count += 1
      else:
        pipe.zrem(self.subjectReputationFeatureGroupByNamespace, milter_object)
      pipe.hmset(self.tmetadata.namespace, self.tmetadata.as_dict, 
        dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items()))
      pipe.expire(self.tmetadata.namespace, self.tmetadata.global_ttl)
      pipe.sadd(self.ipReputationFeatureNamespace, milter_from_ipaddress)
      pipe.expire(self.ipReputationFeatureNamespace, self.tmetadata.global_ttl)
      # Execute commands and get the penultimate element of the list, it is pipe.sadd(...)
      ip_reputation_incr = pipe.execute()[-2]

    # Increase for grouping objects by score
    with redis.pipeline() as pipe:
      # We increase if it is true because a new ip is added in the set
      if ip_reputation_incr:
        pipe.zincrby(self.ipReputationFeatureGroupByNamespace, milter_object, 1)
      # We increase because the subject matched, the last one is equal to the current
      if subject_feature_match:
        pipe.zincrby(self.subjectReputationFeatureGroupByNamespace, milter_object, 1)
      # A simple count of objects, increase every time this method is executed
      pipe.zincrby(self.countSentMessagesFeatureGroupByNamespace, milter_object, 1)
      pipe.execute()

  def feederRateReputationFeature(self, ai_obj, block_probation):
    first_block_count, now_in_timestamp = True, time.time()
    if ai_obj.tmetadata.block_lastupdate:
      now_date_obj = datetime.fromtimestamp(float(now_in_timestamp))
      past_salt = datetime.fromtimestamp(float(ai_obj.tmetadata.block_lastupdate)) + timedelta(hours=block_probation)
      if past_salt > now_date_obj:
        first_block_count = False
    
    ai_obj.tmetadata.block_lastupdate = now_in_timestamp
    if first_block_count:
      ai_obj.tmetadata.block_count = 1
    else:
      ai_obj.tmetadata.block_count += 1
    ai_obj.set_metadata()


class ThemisMetaData(BaseData):
  METADATA_DEFAULT_VALUES = {
    'learningBlueMode' : True,
    'learningRedMode' : False,
    'predictBy' : 'BLUE',
    'manual_block' : False,
    'bypass' : False,
    'blue_creation_date' : 0,
    'red_creation_date' : 0,
    'last_update' : 0,
    'ip_reputation_lastupdate' : 0,
    'subject_lastupdate' : 0,
    'last_subject' : '',
    'sentmessages_lastupdate' : 0,
    'subject_repeated_count' : 0,
    'block_count' : 0
  }
  def __init__(self, **entries):
    self.__dict__.update(entries)
    self.namespace = None

  # Strict check is necessary to prevent AttributeError exceptions
  def strict_check(self):
    [self.__dict__.update({key : type_info(self.__dict__[key])}) for key, type_info in METADATA_CUSTOM_CALLBACK.items()]

  def update_features(self, **entries):
    """ Custom keys must prevail over global features keys (config.yaml). 
    """
    for key, value in entries.items():
      if key in self.__dict__:
        continue
      self.__dict__[key] = value 
    self.strict_check()

  def build_namespace(self, milter_object):
    self.namespace = ':'.join((self.global_namespace, 'metadata', milter_object))

########################
########################
########################

class TMSException(Exception):
  #def __init__(self, message, status_code=None, headers=None):
  def __init__(self, **entries):
    Exception.__init__(self)
    entries['status_code'] = entries.get('status_code') or 400
    entries['headers'] = entries.get('headers') or {}
    self.__dict__.update(entries)

# TODO: Not yet implemented
class Credentials(object):
  """ Represents the credentials to access the IDNS53.
  :param redis: Redis connection
  """
  def __init__(self, redis):
    self.redis = redis
    self.namespace = ':'.join(('themis', 'config', 'auth', 'secretkeys'))
    self.servername = None

  @property
  def token_namespace(self):
    if self.servername:
      return ':'.join(('themis', 'config', 'tokens', self.servername))
    raise AttributeError("'servername' attribute not found")

  def is_valid_secretkey(self, secretkey, servername):
    self.servername = servername
    if secretkey == self.redis.hget(self.namespace, servername):
      return True

  def is_valid_publickey(self, publickey, servername):
    self.servername = servername
    if publickey == self.redis.hget(self.namespace, servername):
      return True

  def is_valid_token(self, token, servername):
    self.servername = servername
    if self.redis.sismember(self.token_namespace, token):
      return True

  def gen_token(self, expire_token):
    """ Return a random token
    :param expire_token: Time in seconds to expire token
    """
    token = hashlib.sha1(os.urandom(128)).hexdigest()
    with self.redis.pipeline() as pipe:
      pipe.delete(self.token_namespace)
      pipe.sadd(self.token_namespace, token)
      pipe.expire(self.token_namespace, expire_token)
      pipe.execute()
    return token

def isvalidtype(data):
  # Match @anything. Domains
  if re.match(r'^@[\w\.]+$', data):
    return 'domain'
  # Match account@domain. Full mailnames
  elif re.match(r'[\w\.]+@[\w\.]+$', data):
    return 'fullmailname'
  elif data == 'any':
    return 'any'
  else:
    try:
      return IPNetwork(data)
    except Exception:
      raise ValueError('Cannot match any type for: %s' % data)

def is_valid_redis_key(key):
  try:
    # Only accepts numbers and characters
    if not re.match(r'[\w]+:[\w]+|[\w]+$', key):
      raise ValueError('Wrong value identified. Only accept numbers and characters. Found: ' + key)
  except TypeError, e:
    e.message = e.message + ' Found: %s' % type(key)
    raise