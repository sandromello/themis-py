import sys, unittest, redis, yaml, time
from itertools import izip

sys.path.append('../lib/')
from policy import PolicyData, Policy
from utils import ThemisMetaData, Features

class FeaturesTestCase(unittest.TestCase):
  """ Tests for Policy class """    

  FEATURES_CUSTOM_CALLBACK = {
    'statisticsFeature' : bool, 
    'evaluateByRecipientFeature' : bool,
    'policiesByServerPoolFeature' : bool,
    'messagesBySecFeature' : bool,
    'messagesBySecStoreDays' : int,
    'feederFeaturesEnabled' : bool,
    'featuresByServerPool' : bool,
    'learnFeature' : bool,
    'learnPredictSafeValue' : float,
    'learnOnlyOnce' : bool,
    'learnEscalationValue' : float,
    'learnBlockMinutes' : float,
    'rateReputationFeature' : bool,
    'rateReputationBlockHitValue' : int,
    'rateReputationDecreaseValue' : float,
    'rateReputationIncreaseMinutes' : float,
    'ipReputationFeature' : bool,
    'ipReputationHitValue' : int,
    'ipReputationDecreaseValue' : float,
    'ipReputationIncreaseMinutes' : float,
    'subjectReputationFeature' : bool,
    'subjectReputationHitValue' : int,
    'subjectReputationDecreaseValue' : float,
    'subjectReputationIncreaseMinutes' : float,
    'global_custom_block' : float,
  }

  DEFAULT_POLICY_PARAMS = {
    'enable' : 'TRUE',
    'type' : 'regular',
    'priority' : 5,
    'jailby' : 'Sender:user@domain+',
    'jailheader' : 'X-Themis-Quarantine',
    'jailaction' : 'monitor',
    'replydata' : 'Limit reached. Blocking for %s second(s)',
    'countsentprobation' : 1,
    'countrcpt' : 'FALSE',
    'stophere' : 'FALSE',
    'requestsmon' : 'FALSE',
    'subjectprobation' : 0.5,
    'ipprobation' : 0.5,
    'blockprobation' : 0.5,
    'countsentprobation' : 1
  }

  METADATA_ITENS = {
    'learnFeature' : True,
    'learnPredictSafeValue' : 10,
    'learnEscalationValue' : 1.0,
    'learningBlueMode' : True,
    'learningRedMode' : False,
    'blue_creation_date' : time.time(),
    'last_update' : 0,
    'predictBy' : 'BLUE',
    'ip_reputation_lastupdate' : 0,
    'subject_lastupdate' : 0,
    'last_subject' : 0,
    'sentmessages_lastupdate' : 0,
    'manual_block' : False,
    'bypass' : True,
    'subject_repeated_count' : 0,
    'block_count' : 0
  }

  def pairs_to_dict_typed(self, response, type_info):
    it = iter(response)
    result = {}
    for key, value in izip(it, it):
      if key in type_info:
        try:
          value = type_info[key](value)
        except:
          # if for some reason the value can't be coerced, just use
          # the string value
          pass
      result[key] = value
    return result

  def hgetall_custom_callback(self, response):
    data = dict(ThemisMetaData.METADATA_CUSTOM_CALLBACK.items() + self.FEATURES_CUSTOM_CALLBACK.items())
    return response and self.pairs_to_dict_typed(response, data) or {}

  def init(self):
    with open('../config/config.yaml') as f:
      _, config_features, _ = yaml.load_all(f)

    self.features = config_features
    self.redis = redis.StrictRedis('localhost')
    #self.redis.flushdb()
    self.redis.set_response_callback('HGETALL', self.hgetall_custom_callback)
    self.policy = Policy(self.redis)
    self.add_default_policy()

  def add_default_policy(self):
    default_policy = { 'Source' : 'any', 'Destination' : 'any', 'JailSpec' : '1:1000' }
    for default_key, value in self.DEFAULT_POLICY_PARAMS.items():
      if default_key not in default_policy.keys():
        default_policy[default_key] = value
    default_policy['policy_name'] = 'default'
    pdata = PolicyData(**default_policy)
    try:
      self.policy.delete('default')
    except ValueError:
      pass
    self.policy.setpolicy(pdata)

  def test_store_global_features(self):
    """ This method tests a config file with several key features. It must be inserted to redis,
    then fetched back with the proper type. 
    """
    self.init()
    # convert global config features to Features object
    global_features = Features(**self.features)

    # store global config features in redis
    self.redis.hmset('config:themis:features', global_features.as_redis)
    # fetch from redis the global features
    global_features = Features(**self.redis.hgetall('config:themis:features'))
    # if got to here then it MUST be TRUE, the validation are made in the Features object
    self.assertTrue(True)

  def test_themis_metadata_override(self):
    self.init()
    """ This method checks if the metadata overrides the global features. """
    tmetadata = ThemisMetaData(**self.METADATA_ITENS)

    # Custom features for ThemisMetaData
    tmetadata.messagesBySecStoreDays = 500
    tmetadata.learnTimeFrameValue = '104:1000'
    tmetadata.ipReputationFeature = True
    tmetadata.learnOnlyOnce = False

    # Include all the global features in the ThemisMetaData, this will not override what is already set
    tmetadata.update_features(**Features(**self.features).as_dict)

    assertResult = False
    # Custom features MUST NOT be overrided
    for key, value in tmetadata.__dict__.items():
      if key == 'messagesBySecStoreDays' and value == 500:
        assertResult = True
      elif key == 'learnTimeFrameValue' and value == '104:1000':
        assertResult = True
      elif key == 'ipReputationFeature' and value is True:
        assertResult = True
      elif key == 'learnOnlyOnce' and value is False:
        assertResult = True
    self.assertTrue(assertResult)

  def test_subject_feature_count(self):
    """ This method validates if the subject feature is counted properly, generating 3 requests with the same subject,
    then changing it to validate if the count is correct """
    self.init()
    self.redis.delete('AI:metadata:unittest@domain.tld')
    for index in range(0, 5):
      metadata = self.redis.hgetall('AI:metadata:unittest@domain.tld')

      feat = Features(**self.features)
      if not metadata:
        # Here we feed redis for the first time with metadata. Will be executed only one once
        tmetadata = ThemisMetaData(**self.METADATA_ITENS)
        self.redis.hmset('AI:metadata:unittest@domain.tld', tmetadata.as_redis)
        # We update 
        tmetadata.update_features(**feat.as_dict)
      else:
        tmetadata = ThemisMetaData(**metadata)
      policy = Policy(self.redis)
      pdata = policy.getpolicy('default')

      milter_object = 'unittest@domain.tld'
      from_ipaddress = '189.10.21.1'
      if index == 4:
        milter_subject = 'Must NOT Update Subject Count, because subject title is different at last loop'
      else:
        milter_subject = 'Repeated Subject until index is 3'

      # Enable feeder feature
      feat.feederFeaturesEnabled = True

      feat.tmetadata = tmetadata
      feat.call_feeders(self.redis, pdata, milter_object, from_ipaddress, milter_subject)
      tmetadata = ThemisMetaData(**self.redis.hgetall('AI:metadata:unittest@domain.tld'))
    # Must be null because at the index 4 the subject is changed, so the namespace is deleted by this object
    score_milter_object = self.redis.zrange('AI:subjectReputationFeature:groupby', 0, -1, withscores=True)
    # Should assert True with 3 because at the index 4 I change the subject name
    self.assertTrue(tmetadata.subject_repeated_count == 3 and not score_milter_object)

  # NOTE: It is not necessary test the behavior of all the other features because has the same implementation
  def test_subject_feature_reset_time(self):
    """ This method validates if the subject feature is reseted properly. """
    self.init()
    self.redis.delete('AI:metadata:unittest@domain.tld')
    for index in range(0, 3):
      metadata = self.redis.hgetall('AI:metadata:unittest@domain.tld')

      feat = Features(**self.features)
      if not metadata:
        # Here we feed redis for the first time with metadata. Will be executed only one once
        tmetadata = ThemisMetaData(**self.METADATA_ITENS)
        self.redis.hmset('AI:metadata:unittest@domain.tld', tmetadata.as_redis)
        # We update 
        tmetadata.update_features(**feat.as_dict)
      else:
        tmetadata = ThemisMetaData(**metadata)
      policy = Policy(self.redis)
      pdata = policy.getpolicy('default')

      milter_object = 'unittest@domain.tld'
      from_ipaddress = '189.10.21.1'
      milter_subject = 'Repeated Subject'

      # Enable feeder feature
      feat.feederFeaturesEnabled = True

      # 0.5 second in hour 
      pdata.subjectprobation = 0.000138888889
      feat.tmetadata = tmetadata
      feat.call_feeders(self.redis, pdata, milter_object, from_ipaddress, milter_subject)
      tmetadata = ThemisMetaData(**self.redis.hgetall('AI:metadata:unittest@domain.tld'))
      #print tmetadata.subject_repeated_count
      # If time sleep is 0.1 the subject_repeated_count will be two (2)
      time.sleep(0.5)
    # Must return 1 because the subject is repeated and always reseted to 1
    score_milter_object = self.redis.zrange('AI:subjectReputationFeature:groupby', 0, -1, withscores=True)[0][1]
    self.assertTrue(tmetadata.subject_repeated_count == 1 and score_milter_object == 1)

  def test_ip_reputation_feature(self):
    """ This method validates if the ips are updated correctly, and also if the scores are with proper values """
    self.init()
    self.redis.delete('AI:metadata:unittest@domain.tld')
    for from_ipaddress in ['189.20.3.1', '200.20.3.100', '200.20.3.100', '201.20.230.10']:
      metadata = self.redis.hgetall('AI:metadata:unittest@domain.tld')

      feat = Features(**self.features)
      if not metadata:
        # Here we feed redis for the first time with metadata. Will be executed only one once
        tmetadata = ThemisMetaData(**self.METADATA_ITENS)
        self.redis.hmset('AI:metadata:unittest@domain.tld', tmetadata.as_redis)
        # We update 
        tmetadata.update_features(**feat.as_dict)
      else:
        tmetadata = ThemisMetaData(**metadata)
      policy = Policy(self.redis)
      pdata = policy.getpolicy('default')

      milter_object = 'unittest@domain.tld'
      milter_subject = 'Subject does matter'

      # Enable feeder feature
      feat.feederFeaturesEnabled = True

      feat.tmetadata = tmetadata
      feat.call_feeders(self.redis, pdata, milter_object, from_ipaddress, milter_subject)

    score_object = self.redis.zrange(feat.ipReputationFeatureGroupByNamespace, 0, -1, withscores=True)[0][1]
    self.assertTrue(len(self.redis.smembers(feat.ipReputationFeatureNamespace)) == 3 and score_object == 3)




if __name__ == '__main__':
  unittest.main()