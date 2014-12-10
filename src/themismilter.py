#!/usr/bin/env python
from themis.utils import isvalidtype
from themis import (
  FEATURES_CUSTOM_CALLBACK, 
  METADATA_CUSTOM_CALLBACK,
  Features, 
  ThemisMetaData,
  AI,
  Policy,
  RateLimiter
)
from traceback import format_exc
from netaddr import IPNetwork, IPAddress
from datetime import datetime, timedelta
from math import ceil
from email.utils import parseaddr
from multiprocessing import Process as Thread, Queue
from themis.marshalredis import MarshalRedis

import Milter, time, logging.config
import re, sys, yaml, os

# TODO: Count receive messages by header
# TODO: Implement greylist functionality
# TODO: Rest interface for configuring
# TODO: Send UDP requests containing statistics
# TODO: Test performance: Anex, list, alias, severeal rcpts

class ThemisMilter(Milter.Base):
  REDIS, LOGGER, FEATS = [None, None, None]
  def __init__(self):
    self.id = Milter.uniqueID()  # Integer incremented with each call.
    self.resync_config()
    self.redis = ThemisMilter.REDIS
    self.log = ThemisMilter.LOGGER
    self.gconf = ThemisMilter.FEATS

    self.policy = Policy(self.redis)
    self.log = logging.getLogger(__name__)
    self.policies = None

  def resync_config(self):
    config_file = ThemisMilter.REDIS.hget('config:themis:resync', 'config_file')
    if config_file:
      with open(config_file) as f:
        main_config, global_config, logger_config = yaml.load_all(f)

      ThemisMilter.REDIS = MarshalRedis(main_config['redis_server'])
      global_config = ThemisMilter.REDIS.hgetall('config:themis:features:global', FEATURES_CUSTOM_CALLBACK) or global_config
      ThemisMilter.FEATS = Features(**global_config)

      logging.config.dictConfig(logger_config['logger'])
      ThemisMilter.LOGGER = logging.getLogger(__name__)
      if ThemisMilter.REDIS.exists('config:themis:features:global'):
        ThemisMilter.LOGGER.warning('RESYNC - Config file "%s" will be ignored. Using redis server config.' % config_file)
      ThemisMilter.REDIS.delete('config:themis:resync')

  @Milter.noreply
  def connect(self, IPname, family, hostaddr):
    # (self, 'ip068.subnet71.example.com', AF_INET, ('215.183.71.68', 4720) )
    # (self, 'ip6.mxout.example.com', AF_INET6,
    #   ('3ffe:80e8:d8::1', 4720, 1, 0) )
    self.log.debug('CONNECT - From %s at %s in ID %s' % (IPname, hostaddr[0], self.id))
    #self.log("connect from %s at %s in ID: %s" % (IPname, hostaddr, self.milter.id) )
    self.from_ipaddress = hostaddr[0]
    return Milter.CONTINUE

  @Milter.nocallback
  def hello(self, heloname):
    self.log.debug('HELO - heloname: %s' % heloname)
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    try:
      mta_hostname = None
      if self.gconf.policiesByServerPoolFeature:
        mta_hostname = self.getsymval('{j}')
        self.log.debug('CONNECT - policiesByServerPoolFeature enabled, mta_hostname: %s' % mta_hostname)

      if self.gconf.messagesBySecFeature:
        now = datetime.now()
        now_in_seconds = now.hour * 60 * (self.gconf.messagesBySecStoreDays * 60) + now.second
        self.redis.hincrby('requestsbysec:global', 'second:%s' % now_in_seconds)
      
      self.policies = self.policy.get_all_data_policies(mta_hostname)

      self.milter_headers, self.recipients, self.subject = [dict(), list(), None]
      self.saslauth = self.getsymval('{auth_authen}') # authenticated user
      self.saslauth_domain = None
      if self.saslauth:
        if not '@' in self.saslauth:
          self.log.info('ENVFROM - Got a broken SASLUsername: %s' % self.saslauth)
          
          # TODO: Try to fix the broken sasl accounts
          self.saslauth_domain = '@broken_sasl.tld'
          self.saslauth = self.saslauth + self.saslauth_domain
          
        else:
          self.saslauth_domain = '@' + self.saslauth.split('@')[1]
      # ('From Name', 'user@domain.tld')
      _, self.mailfrom = parseaddr(mailfrom)

      if not self.mailfrom:
        # Blank mailfrom
        self.mailfrom = 'blank@mailfrom.tld'
      elif '@' not in self.mailfrom:
        self.mailfrom = self.mailfrom + '@mailfrom.tld'
      self.mailfrom_domain = '@' + self.mailfrom.split('@')[1]
    except Exception, e:
      self.log.error('ENVRCPT - BYPASS - Error processing envfrom')
      self.log.exception(e)
      return Milter.ACCEPT

    return Milter.CONTINUE

  @Milter.noreply
  def envrcpt(self, to, *str):
    try:
      # This state happens a "loop" for each recipient
      rcptinfo = to, Milter.dictfromlist(str)
      # ('To Name', 'user@domain.tld')
      _, rcpt = parseaddr(rcptinfo[0])
      self.recipients.append(rcpt)
    except Exception, e:
      self.log.error('ENVRCPT - BYPASS - Error processing recipients')
      self.log.exception(e)
      return Milter.ACCEPT

    return Milter.CONTINUE

  @Milter.noreply
  def header(self, name, hval):
    # If has key headers repeated the last one will prevail
    try:
      self.milter_headers[name] = hval
      if name == 'Subject':
        self.subject = hval or ':::blank_subject:::'
    except Exception, e:
      self.log.warning('HEADER - Error processing headers')
      self.log.exception(e)
    return Milter.CONTINUE

  @Milter.noreply
  def eoh(self):
    self.queue_id = self.getsymval('{i}')
    self.log.debug('ENVFROM - %s - Mail from: %s SASLUsername: %s' % (self.queue_id, self.mailfrom, self.saslauth or 'NULL'))

    try:
      for hdr, hdr_value in self.milter_headers.items():
        self.log.debug('HEADER - %s - %s | %s' % (self.queue_id, hdr, hdr_value))
    except Exception, e:
      self.log.warning('EOH - Could not debug headers. %s' % e)
      self.log.exception(e)

    rcptlog = ', '.join(self.recipients)
    self.log.debug('ENVRCPT - %s - RCPT(s): %s' % (self.queue_id, rcptlog))

    return Milter.CONTINUE

  @Milter.nocallback
  def body(self, chunk):
    # TODO: dont need body
    return Milter.CONTINUE

  def eom(self):
    # TODO: add custom header - http://stackoverflow.com/questions/17558552/how-do-i-add-custom-field-to-python-log-format-string
    eom_log_header = 'EOM - %s - ' % self.queue_id 
    try:   
      if not self.policies:
        self.log.warning(eom_log_header + 'BYPASS - Could not find any policies')
        return Milter.ACCEPT

      for pdata in self.policies:
        self.namespace = self.gconf.global_namespace

        # Custom Headers are included if a header is found and the value has been matched with a regular expression
        if pdata.actionheaders:
          for hdr_key, hdr_value in self.milter_headers.items():
            try:
              if not hdr_key in pdata.actionheaders:
                continue

              rgxp = pdata.actionheaders[hdr_key].pop(0)
              
              if re.match(r'%s' % rgxp, hdr_value):
                self.log.debug(eom_log_header + 'MATCH, regexp %s value %s' % (rgxp, hdr_value))
                for actionheader in pdata.actionheaders[hdr_key]:
                  new_hdr, new_hdr_value = actionheader
                  self.log.debug(eom_log_header + 'Adding header %s with value %s' % (new_hdr, new_hdr_value))
                  self.addheader(new_hdr, new_hdr_value)
              else:
                self.log.debug(eom_log_header + 'NOT MATCH, regexp %s value %s' % (rgxp, hdr_value))
            except Exception, e:
              self.log.error(eom_log_header + 'Error processing action headers: %s' % e)
              self.log.exception(e)
              break
          
          if pdata.onlyheaders:
            self.log.debug(eom_log_header + 'BYPASS - Accepting connection, policy validate only headers')
            return Milter.ACCEPT

        jailby_namespace = pdata.jailby
        # Features and config by pool servers
        if self.gconf.featuresByServerPool and self.gconf.policiesByServerPoolFeature:
          global_config = self.redis.hgetall(':'.join(('config:themis:features', pdata.policy_name)), FEATURES_CUSTOM_CALLBACK)
          if global_config:
            self.gconf = Features(**global_config)
          if pdata.pool_policy:
            self.namespace = ':'.join((self.namespace, pdata.pool_name))
            
            self.gconf.ai_namespace = self.namespace
            jailby_namespace = ':'.join((pdata.pool_name, jailby_namespace))
            self.log.debug(eom_log_header + 'Pool policy Name: %s namespace: %s jailby_namespace: %s' % (pdata.pool_name, self.namespace, jailby_namespace) )

        self.log.info(eom_log_header + 'Executing policy: %s Pool Policy: %s' % (pdata.policy_name, pdata.pool_policy))

        if pdata.requestsmon:
          # Monitoring requests by sec of a policy
          now = datetime.now()
          now_in_seconds = now.hour * 60 * (self.gconf.messagesBySecStoreDays * 60) + now.second
          self.redis.hincrby('requestsbysec:%s' % pdata.policy_name, 'second:%s' % now_in_seconds)

        if '+' in pdata.jailby:
          # Jail by sasl @domain or user@domain
          if self.saslauth:
            self.mailfrom_domain = self.saslauth_domain
            self.mailfrom = self.saslauth

        self.milter_from_object = None
        if re.match(r'^SenderDomain\+$|^SenderDomain$', pdata.jailby):
          # Dont jail plus because sasl_auth may be None
          self.milter_from_object = self.mailfrom_domain
        elif re.match(r'^Sender\+$|^Sender$', pdata.jailby):
          self.milter_from_object = self.mailfrom
        elif re.match(r'^SenderIP$', pdata.jailby):
          self.milter_from_object = self.from_ipaddress
        elif 'SASLUsername' == pdata.jailby:
          if not self.saslauth:
            self.log.warning(eom_log_header + 'NEXT - Empty saslusername skipping policy: %s' % pdata.policy_name)
            continue
          self.milter_from_object = self.saslauth

        else:
          self.log.warning(eom_log_header + 'NEXT - Could NOT match jailby key: %s for policy: %s' % (pdata.jailby, pdata.policy_name))
          continue

        # Evaluate to True if only one recipient match
        # If the destination match for domain destination, ACCEPT! Here it is a simple match of destination, only by @domain
        is_dest_match, recipient_bypass_match = False, False
        if pdata.is_destination_any:
          is_dest_match = True
          self.log.debug(eom_log_header + "DEST_MATCH - 'any' found")
        else:
          for rcpt in self.recipients:
            rcpt_domain = '@' + rcpt.split('@')[1]
            if self.policy.hasmember(pdata.destination, [rcpt_domain], pdata.inverted_destination):
              self.log.info(eom_log_header + 'DEST_MATCH - Recipient: %s Policy: %s' % (rcpt_domain, pdata.policy_name))
              # Bypass complex, only bypass if source and destination match
              if pdata.type == 'bypass+':
                recipient_bypass_match = True
                break
              # We break because we need only one match to start rate limiting
              is_dest_match = True
              break
            else:
              self.log.debug(eom_log_header + 'DEST_NOT_MATCH - RCPT: %s Policy: %s' % (rcpt, pdata.policy_name))

        # Check if the objects are in a specific redis SET. This prevents unnecessary looping
        is_source_match = pdata.is_source_any
        if not is_source_match:
          objects = [self.mailfrom_domain, self.mailfrom, self.from_ipaddress]
          is_source_match = self.policy.hasmember(pdata.source, objects, invert=pdata.inverted_source)

        if not is_source_match:
          # This is only necessary to validate if an ipaddress belongs to a CIDR
          for group_src_member in self.policy.getgroup(pdata.source):
            self.log.debug(eom_log_header + 'Looping through groups. group: %s member(s): %s' % (pdata.source, group_src_member))
            try:
              if IPNetwork is type(isvalidtype(group_src_member)):
                is_source_match = self.match(group_src_member, invert=pdata.inverted_source)
            except Exception, e:
              self.log.warning(eom_log_header + 'Source check error. Policy: %s Error: %s' % (pdata.policy_name, e))
              continue

        if is_source_match:
          local_milter_from_object = self.milter_from_object
          self.log.info(eom_log_header + 'SOURCE_MATCH - group_source_name: %s milter_from_object: %s from_ipaddress: %s mailfrom_domain: %s mailfrom: %s invert: %s' 
            % (pdata.source, local_milter_from_object, self.from_ipaddress, self.mailfrom_domain, self.mailfrom, pdata.inverted_source))

          # Bypass by the source (simple bypass) or by recipient (complex)
          if pdata.type == 'bypass' or recipient_bypass_match == True:
            self.log.info(eom_log_header + 'BYPASS - Source, Destination or both matched. Policy: %s' % pdata.policy_name)
            return Milter.ACCEPT
        else:
          self.log.info(eom_log_header + 'SOURCE_NOT_MATCH - milter_from_object: %s group_src_member: %s invert_source: %s jailby: %s'
          % (self.milter_from_object, group_src_member, pdata.inverted_source, pdata.jailby))  

        if is_dest_match and is_source_match:
          self.log.info(eom_log_header + 'SOURCE_AND_DEST_MATCH')

          metadata_namespace = ':'.join((self.namespace, 'metadata', local_milter_from_object))
          metadata = self.redis.hgetall(metadata_namespace) or ThemisMetaData.METADATA_DEFAULT_VALUES
          tmetadata = ThemisMetaData(**metadata)
          tmetadata.namespace = metadata_namespace

          # Bypass object
          if tmetadata.bypass:
            self.log.info(eom_log_header + 'BYPASS - object %s' % local_milter_from_object)
            return Milter.ACCEPT
          
          # Block object manually
          if tmetadata.manual_block:
            self.log.warning(eom_log_header + 'MANUAL_BLOCK - Blocking, found a block key %s' % metadata_namespace)
            self.setreply('550', '5.7.1', 'Account manually blocked, contact your administrator')
            return Milter.REJECT

          rcpt_count = 1
          # Count by recipient, E.G.: If there's two recipients, two sended messages, otherwise count only one
          if pdata.countrcpt:
            # TODO: Every policy should contain a list of bypass domains
            rcpt_count = len(self.recipients)
            #rcpt_count = len( [rcpt for rcpt in self.recipients if '@' + rcpt.split('@')[1] not in bypass_domains] )

          # FEEDER FEATURES
          self.gconf.tmetadata = tmetadata
          self.gconf.call_feeders(self.redis, pdata, local_milter_from_object, self.from_ipaddress, self.subject)

          # HERE WE START GLOBAL RATELIMITING
          conditions = pdata.jailspec
          if pdata.jailspec == [('0', '0')]:
            conditions = map(tuple, self.gconf.global_conditions)
          self.log.debug(eom_log_header + 'Block Conditions: %s' % conditions)

          rate = RateLimiter(self.redis, jailby_namespace, conditions)
          free, wait = rate.acquire(local_milter_from_object, block_size=rcpt_count, block=False)

          self.log.info(eom_log_header + 'Rate limiting object: %s. Namespace: %s Block Size: %s' 
            % (local_milter_from_object, jailby_namespace, rcpt_count))

          if not free:
            if self.gconf.global_custom_block:
              # Custom blocking time. More than one condition will use only custom_block
              wait = int(rate.is_manual_block(local_milter_from_object))
              if not wait >= 0:
                wait = rate.block(local_milter_from_object, minutes=self.gconf.global_custom_block)

            self.set_block_stats(metadata_namespace, pdata.blockprobation)
            self.log.info(eom_log_header + 'BLOCK:%s - %s seconds left.' % (local_milter_from_object, wait))
            # Proccess milter action: reject, quarantine, addheader...
            return self.milter_action(pdata, wait, eom_log_header)

          tmetadata.update_features(**self.gconf.as_dict)

          # TODO: Not ready yet. learnFeature should stay off
          if not tmetadata.learnFeature:
            with self.redis.pipeline() as pipe:
              pipe.hmset(tmetadata.namespace, tmetadata.as_dict, 
                dict(FEATURES_CUSTOM_CALLBACK.items() + METADATA_CUSTOM_CALLBACK.items()))
              pipe.expire(tmetadata.namespace, tmetadata.global_ttl)
              pipe.execute()
          else:
            # Here we start learning
            ai_obj = AI(self.redis, local_milter_from_object, self.gconf.__dict__)
            if ai_obj.ai_metadata.learnFeature:
              # Is on for learning - specific account config
              ai_obj.learnBlue(rcpt_count)
              ai_obj.learnRed(rcpt_count)

              predicted = ai_obj.predict()
              if not predicted:
                # Learning mode active
                # TODO: Check this
                continue

              if rcpt_count > predicted:
                self.log.info(eom_log_header + 'BLOCK:%s - Destination rcpts are greater than the predicted.' % local_milter_from_object)
                # Proccess milter action: reject, quarantine, addheader...
                return self.milter_action(pdata, log_header=eom_log_header)

              # subjectReputationFeature
              if tmetadata.subjectReputationFeature:
                if tmetadata.subject_repeated_count and tmetadata.subject_repeated_count > tmetadata.subjectReputationHitValue:
                  # Decrease by percentage
                  predicted = ceil(predicted - (tmetadata.subjectReputationDecreaseValue * predicted))
                  tmetadata.learnBlockMinutes += tmetadata.subjectReputationIncreaseMinutes
                  self.log.info(eom_log_header + 'SubjectFeature - Bad reputation, decreasing predicted value to: %s. Increasing minutes to: %s' 
                    % (predicted, tmetadata.subjectReputationIncreaseMinutes))

              # rateReputationFeature
              if tmetadata.rateReputationFeature:
                if tmetadata.block_count and tmetadata.block_count > tmetadata.rateReputationBlockHitValue:
                  # Decrease by percentage
                  predicted = ceil(predicted - (tmetadata.rateReputationDecreaseValue * predicted))
                  tmetadata.learnBlockMinutes += tmetadata.rateReputationIncreaseMinutes
                  self.log.info(eom_log_header + 'RateFeature - Bad reputation, decreasing predicted value to: %s. Increasing minutes to: %s' 
                    % (predicted, tmetadata.rateReputationIncreaseMinutes))

              if tmetadata.ipReputationFeature:
                if len(self.redis.smembers(tmetadata.ipReputationFeatureNamespace)) > tmetadata.ipReputationHitValue:
                  # Decrease by percentage
                  predicted = ceil(predicted - (tmetadata.ipReputationDecreaseValue * predicted))
                  tmetadata.learnBlockMinutes += tmetadata.ipReputationIncreaseMinutes
                  self.log.info(eom_log_header + 'IpFeature - Bad reputation, decreasing predicted value to: %s. Increasing minutes to: %s' 
                    % (predicted, tmetadata.ipReputationIncreaseMinutes))

              conditions = { 'requests': predicted, 'minutes' : tmetadata.learnBlockMinutes }
              
              rate = RateLimiter(self.redis, 'AI:' + jailby_namespace, conditions)
              free, wait = rate.acquire(local_milter_from_object, block_size=rcpt_count, block=False)
              if not free:
                if self.gconf.global_custom_block:
                  # Custom blocking time. More than one condition will use only custom_block
                  wait = int(rate.is_manual_block(local_milter_from_object))
                  if not wait >= 0:
                    wait = rate.block(local_milter_from_object, minutes=self.gconf.global_custom_block)

                # rateReputationFeature
                self.gconf.feederRateReputationFeature(ai_obj, pdata.blockprobation)
                # Proccess milter action: reject, quarantine, addheader...
                return self.milter_action(pdata, wait, eom_log_header)

        else:
          self.log.info(eom_log_header + 'SOURCE_AND_DEST_NOTMATCH')
        if pdata.stophere and is_dest_match and is_source_match:
          # Stop processing additional policies
          self.log.info(eom_log_header + 'STOPHERE - Stopping additional policies, stopped on: %s' % pdata.policy_name)
          break

    except Exception, e:
      self.log.error(eom_log_header + 'BYPASS - Error processing connection %s.' % self.id)
      self.log.exception(e)
      return Milter.ACCEPT

    return Milter.CONTINUE

  def close(self):
    return Milter.CONTINUE

  def abort(self):
    return Milter.CONTINUE

  def milter_action(self, pdata, wait=0, log_header=''):
    if pdata.jailaction == 'block':
      self.setreply('550', '5.7.1', pdata.replydata % wait)
      return Milter.REJECT  
    elif pdata.jailaction == 'quarantine':
      self.addheader(pdata.jailheader, 'YES')
    elif pdata.jailaction == 'hold':
      self.quarantine('Themis policy milter')
    elif pdata.jailaction == 'monitor':
      self.log.info(log_header + 'BYPASS - MONITORING')
    return Milter.ACCEPT

  def set_block_stats(self, metadata_namespace, block_probation):
    now_in_timestamp = time.time()
    now_date_obj = datetime.fromtimestamp(float(now_in_timestamp))
    block_lastupdate = self.redis.hget(metadata_namespace, 'block_lastupdate')
    if block_lastupdate:
      past_salt = datetime.fromtimestamp(float(block_lastupdate)) + timedelta(hours=block_probation)
      if past_salt > now_date_obj:
        return self.redis.hincrby(metadata_namespace, 'block_count', 1)
      return self.redis.hset(metadata_namespace, 'block_count', 1)

  def match(self, group_src_member, invert=False):
    # It's a domain
    if re.match(r'@[\w\.]+$', group_src_member):
      result = group_src_member == self.mailfrom_domain
    # It's an account
    elif re.match(r'[\w\.]+@[\w\.]+$', group_src_member):
      result = group_src_member == self.mailfrom
    else:
      result = IPAddress(self.from_ipaddress) in IPNetwork(group_src_member)

    if invert:
      return not result
    return result

def background():
  while True:
    try:
      if not logq.get(): break
    except KeyboardInterrupt:
      pass

if __name__ == '__main__':
  # TODO: Try catch errors. This will not start at boot
  config_file = os.getenv('THEMIS_CFG')
  if not config_file:
    # TODO: Change this path to package
    config_file = '/etc/themis/config.yaml'
  
  try:
    with open(config_file) as f:
      main_config, global_config, logger_config = yaml.load_all(f)

    ThemisMilter.REDIS = MarshalRedis(main_config['redis_server'])
    global_config = ThemisMilter.REDIS.hgetall('config:themis:features:global') or global_config
    ThemisMilter.FEATS = Features(**global_config)
    # sanity check for key items in config file
    ThemisMilter.FEATS.strict_check()

    logq = Queue(maxsize=main_config['queue_maxsize'])

    logging.config.dictConfig(logger_config['logger'])
    ThemisMilter.LOGGER = logging.getLogger(__name__)

    if ThemisMilter.REDIS.exists('config:themis:features:global'):
      ThemisMilter.LOGGER.info('Config file "%s" will be ignored. Using redis server config.' % config_file)

    bt = Thread(target=background)
    bt.start()
    socketname = main_config['milter_socket']
  except KeyError, e:
    print 'Could not find config by name.', e
    print format_exc()
    sys.exit(1)
  except yaml.YAMLError, e:
    print 'Error parsing yaml file:', config_file, e
    print format_exc()
    sys.exit(1)
  except Exception, e:
    print 'Unknown error', e
    print format_exc()
    sys.exit(1)

  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = ThemisMilter
  # tell Sendmail which features we use
  Milter.set_flags(Milter.ADDHDRS)
  ThemisMilter.LOGGER.info("Starting ThemisMilter...")
  sys.stdout.flush()
  Milter.runmilter('themis', socketname, timeout)
  logq.put(None)
  bt.join()
  ThemisMilter.LOGGER.info("ThemisMilter shutdown")